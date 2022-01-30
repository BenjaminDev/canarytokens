from twisted.internet import defer, reactor
from twisted.internet.task import deferLater
from twisted.logger import Logger
from twisted.names import dns, error, server

log = Logger()

import base64
import math
import re

# from exception import UnicodeDecodeError

# import settings

# from canarytokens.canarydrop import Canarydrop
from canarytokens.channel import InputChannel
from canarytokens.constants import INPUT_CHANNEL_DNS
# from exception import NoCanarytokenFound, NoCanarytokenPresent
from canarytokens.queries import get_all_canary_domains, get_canarydrop
from canarytokens.tokens import handle_query_name



class DNSServerFactory(server.DNSServerFactory, object):
    def handleQuery(self, message, protocol, address):
        if message.answer:
            return

        query = message.queries[0]
        if address:
            src_ip = address[0]
            if address[1] == 0:
                log.debug(
                    ('Dropping request from {src} because source port is 0').format(
                        src=src_ip,
                    ),
                )
                return None
        else:
            src_ip = protocol.transport.socket.getpeername()[0]

        try:
            log.info('Query: {} sent {}'.format(src_ip, query))
        except UnicodeDecodeError:
            # Invalid query
            return None

        return (
            self.resolver.query(query, src_ip)
            .addCallback(self.gotResolverResponse, protocol, message, address)
            .addErrback(self.gotResolverError, protocol, message, address)
        )

    def gotResolverError(self, failure, protocol, message, address):
        if failure.check(error.DNSQueryRefusedError):
            response = self._responseFromMessage(message=message, rCode=dns.EREFUSED)

            self.sendReply(protocol, response, address)
            self._verboseLog('Lookup failed')
        else:
            super(DNSServerFactory, self).gotResolverError(
                failure, protocol, message, address,
            )


class ChannelDNS(InputChannel):
    CHANNEL = INPUT_CHANNEL_DNS

    def __init__(self, listen_domain='canary.thinknest.com', switchboard=None, **kwargs):
        super(ChannelDNS, self).__init__(switchboard=switchboard, name=self.CHANNEL, **kwargs)
        self.listen_domain = listen_domain
        self.canary_domains = get_all_canary_domains()

    def _do_ns_response(self, name=None):
        """
        Calculate the response to a query.
        """
        answer = dns.RRHeader(
            name=name,
            payload=dns.Record_NS(ttl=10, name='ns1.' + name),
            type=dns.NS,
            auth=True,
        )
        additional = dns.RRHeader(
            name='ns1.' + name,
            payload=dns.Record_A(ttl=10, address=settings.PUBLIC_IP),
            type=dns.A,
            auth=True,
        )
        answers = [answer]
        authority = []
        additional = [additional]
        return answers, authority, additional

    def _do_soa_response(self, name=None):
        """
        Ensure a standard response to a SOA query.
        """
        answer = dns.RRHeader(
            name=name,
            payload=dns.Record_SOA(
                mname=name.lower(),
                rname='info.' + name.lower(),
                serial=0,
                refresh=300,
                retry=300,
                expire=300,
                minimum=300,
                ttl=300,
            ),
            type=dns.SOA,
            auth=True,
        )
        answers = [answer]
        authority = []
        additional = []

        return answers, authority, additional

    def _do_dynamic_response(self, name=None):
        """
        Calculate the response to a query.
        """
        payload = dns.Record_A(ttl=10, address=settings.PUBLIC_IP)
        answer = dns.RRHeader(name=name, payload=payload, type=dns.A, auth=True)
        answers = [answer]
        authority = []
        additional = []
        return answers, authority, additional

    def _do_no_response(self, query=None):
        """
        Calculate the response to a query.
        """
        answers = []
        authority = []
        additional = []
        return answers, authority, additional






    def query(self, query, src_ip):
        """
        Check if the query should be answered dynamically, otherwise dispatch to
        the fallback resolver.
        """

        IS_NX_DOMAIN = True in [
            query.name.name.lower().endswith(d) for d in settings.NXDOMAINS
        ]

        if (
            not True
            in [query.name.name.lower().endswith(d) for d in self.canary_domains]
            and not IS_NX_DOMAIN
        ):
            return defer.fail(error.DNSQueryRefusedError())

        if query.type == dns.NS:
            return defer.succeed(self._do_ns_response(name=query.name.name))

        if query.type == dns.SOA:
            return defer.succeed(self._do_soa_response(name=query.name.name))

        if query.type != dns.A:
            return defer.succeed(self._do_no_response(query=query))

        try:
            canarydrop, src_data = handle_query_name()
            # TODO: What was the deal with this my_sql special case!
            # Ignoring for now but needs a look see.
            # if canarydrop._drop['type'] == 'my_sql':
            #     d = deferLater(...)

            self.dispatch(canarydrop=canarydrop, src_ip=src_ip, src_data=src_data)

        except (NoCanarytokenPresent, NoCanarytokenFound):
            # If we dont find a canarytoken, lets just continue. No need to log.
            pass
        except Exception as e:
            log.error(e)

        if IS_NX_DOMAIN:
            return defer.fail(error.DomainError())

        return defer.succeed(self._do_dynamic_response(name=query.name.name))
        # return defer.fail(error.DomainError())

    def lookupCAA(self, name, timeout):
        """Respond with NXdomain to a -t CAA lookup."""
        return defer.fail(error.DomainError())

    def lookupAllRecords(self, name, timeout):
        """Respond with error to a -t ANY lookup."""
        return defer.fail(error.DomainError())

    def format_additional_data(self, **kwargs):
        log.info(kwargs)
        additional_report = 'Source IP : {ip}'.format(ip=kwargs['src_ip'])

        if 'src_data' in kwargs:

            if 'sql_username' in kwargs['src_data']:
                additional_report += '\nSQL Server User: {username}'.format(
                    username=kwargs['src_data']['sql_username'],
                )

            if 'mysql_username' in kwargs['src_data']:
                additional_report += '\nMySQL User: {username}'.format(
                    username=kwargs['src_data']['mysql_username'],
                )

            if 'linux_inotify_filename_access' in kwargs['src_data']:
                additional_report += '\nLinux File Access: {filename}'.format(
                    filename=kwargs['src_data']['linux_inotify_filename_access'],
                )

            if 'generic_data' in kwargs['src_data']:
                additional_report += '\nGeneric data: {generic_data}'.format(
                    generic_data=kwargs['src_data']['generic_data'],
                )

            if 'dtrace_uid' in kwargs['src_data']:
                additional_report += '\nDTrace UID: {uid}'.format(
                    uid=kwargs['src_data']['dtrace_uid'],
                )

            if 'dtrace_hostname' in kwargs['src_data']:
                additional_report += '\nDTrace hostname: {hostname}'.format(
                    hostname=kwargs['src_data']['dtrace_hostname'],
                )

            if 'dtrace_command' in kwargs['src_data']:
                additional_report += '\nDTrace command: {command}'.format(
                    command=kwargs['src_data']['dtrace_command'],
                )

            if 'dtrace_filename' in kwargs['src_data']:
                additional_report += '\nDTrace filename: {filename}'.format(
                    filename=kwargs['src_data']['dtrace_filename'],
                )

            if (
                'windows_desktopini_access_username' in kwargs['src_data']
                and 'windows_desktopini_access_domain' in kwargs['src_data']
            ):
                if 'windows_desktopini_access_hostname' in kwargs['src_data']:
                    additional_report += '\nWindows Directory Browsing By: {domain}\{username} from {hostname}'.format(
                        username=kwargs['src_data'][
                            'windows_desktopini_access_username'
                        ],
                        domain=kwargs['src_data']['windows_desktopini_access_domain'],
                        hostname=kwargs['src_data'][
                            'windows_desktopini_access_hostname'
                        ],
                    )
                else:
                    additional_report += (
                        '\nWindows Directory Browsing By: {domain}\{username}'.format(
                            username=kwargs['src_data'][
                                'windows_desktopini_access_username'
                            ],
                            domain=kwargs['src_data'][
                                'windows_desktopini_access_domain'
                            ],
                        )
                    )

            if 'aws_keys_event_source_ip' in kwargs['src_data']:
                additional_report += '\nAWS Keys used by: {ip}'.format(
                    ip=kwargs['src_data']['aws_keys_event_source_ip'],
                )

            if 'log4_shell_computer_name' in kwargs['src_data']:
                additional_report += (
                    '\nComputer name from Log4J shell: {computer_name}'.format(
                        computer_name=kwargs['src_data']['log4_shell_computer_name'],
                    )
                )

        return additional_report

    def _handleMySqlErr(self, result):
        log.error('Error dispatching MySQL alert: {}'.format(result))
