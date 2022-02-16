from email.message import Message
import socket
from typing import List
from unicodedata import name
from unittest import result

from twisted.internet import defer, error, reactor
from twisted.names import authority, client, common, dns, server
from twisted.trial import unittest
from twisted.python import failure
from canarytokens.channel_dns import DNSServerFactory, ChannelDNS
from canarytokens.redismanager import DB
from distutils.util import strtobool
import pytest
import os

# @pytest.fixture(scope="session", autouse=True)
# def clear_db():
#     redis_hostname = 'localhost' if strtobool(os.getenv('CI', 'False')) else 'redis'
#     DB.set_db_details(hostname=redis_hostname, port=6379)
#     redis = DB.get_db()
#     for key in redis.scan_iter():
#         redis.delete(key)
#     yield redis

#     for key in redis.scan_iter():
#         redis.delete(key)
# def justPayload(results):
#     return [r.payload for r in results[0]]

# class NoFileAuthority(authority.FileAuthority):
#     def __init__(self, soa, records):
#         # Yes, skip FileAuthority
#         common.ResolverBase.__init__(self)
#         self.soa, self.records = soa, records


# soa_record = dns.Record_SOA(
#                     mname = 'test-domain.com',
#                     rname = 'root.test-domain.com',
#                     serial = 100,
#                     refresh = 1234,
#                     minimum = 7654,
#                     expire = 19283784,
#                     retry = 15,
#                     ttl=1
#                 )

# reverse_soa = dns.Record_SOA(
#                      mname = '93.84.28.in-addr.arpa',
#                      rname = '93.84.28.in-addr.arpa',
#                      serial = 120,
#                      refresh = 54321,
#                      minimum = 382,
#                      expire = 11193983,
#                      retry = 30,
#                      ttl=3
#                 )

# my_soa = dns.Record_SOA(
#     mname = 'my-domain.com',
#     rname = 'postmaster.test-domain.com',
#     serial = 130,
#     refresh = 12345,
#     minimum = 1,
#     expire = 999999,
#     retry = 100,
#     )

# test_domain_com = NoFileAuthority(
#     soa = ('test-domain.com', soa_record),
#     records = {
#         'test-domain.com': [
#             soa_record,
#             dns.Record_A('127.0.0.1'),
#             dns.Record_NS('39.28.189.39'),
#             dns.Record_SPF('v=spf1 mx/30 mx:example.org/30 -all'),
#             dns.Record_SPF('v=spf1 +mx a:\0colo', '.example.com/28 -all not valid'),
#             dns.Record_MX(10, 'host.test-domain.com'),
#             dns.Record_HINFO(os='Linux', cpu='A Fast One, Dontcha know'),
#             dns.Record_CNAME('canonical.name.com'),
#             dns.Record_MB('mailbox.test-domain.com'),
#             dns.Record_MG('mail.group.someplace'),
#             dns.Record_TXT('A First piece of Text', 'a SecoNd piece'),
#             dns.Record_A6(0, 'ABCD::4321', ''),
#             dns.Record_A6(12, '0:0069::0', 'some.network.tld'),
#             dns.Record_A6(8, '0:5634:1294:AFCB:56AC:48EF:34C3:01FF', 'tra.la.la.net'),
#             dns.Record_TXT('Some more text, haha!  Yes.  \0  Still here?'),
#             dns.Record_MR('mail.redirect.or.whatever'),
#             dns.Record_MINFO(rmailbx='r mail box', emailbx='e mail box'),
#             dns.Record_AFSDB(subtype=1, hostname='afsdb.test-domain.com'),
#             dns.Record_RP(mbox='whatever.i.dunno', txt='some.more.text'),
#             # dns.Record_WKS('12.54.78.12', socket.IPPROTO_TCP,
#             #                '\x12\x01\x16\xfe\xc1\x00\x01'),
#             # dns.Record_NAPTR(100, 10, "u", "sip+E2U",
#             #                  "!^.*$!sip:information@domain.tld!"),
#             dns.Record_AAAA('AF43:5634:1294:AFCB:56AC:48EF:34C3:01FF')],
#         'http.tcp.test-domain.com': [
#             dns.Record_SRV(257, 16383, 43690, 'some.other.place.fool')
#         ],
#         'host.test-domain.com': [
#             dns.Record_A('123.242.1.5'),
#             dns.Record_A('0.255.0.255'),
#         ],
#         'host-two.test-domain.com': [
# #
# #  Python bug
# #           dns.Record_A('255.255.255.255'),
# #
#             dns.Record_A('255.255.255.254'),
#             dns.Record_A('0.0.0.0')
#         ],
#         'cname.test-domain.com': [
#             dns.Record_CNAME('test-domain.com')
#         ],
#         'anothertest-domain.com': [
#             dns.Record_A('1.2.3.4')],
#     }
# )

# reverse_domain = NoFileAuthority(
#     soa = ('93.84.28.in-addr.arpa', reverse_soa),
#     records = {
#         '123.93.84.28.in-addr.arpa': [
#              dns.Record_PTR('test.host-reverse.lookup.com'),
#              reverse_soa
#         ]
#     }
# )


# my_domain_com = NoFileAuthority(
#     soa = ('my-domain.com', my_soa),
#     records = {
#         'my-domain.com': [
#             my_soa,
#             dns.Record_A('1.2.3.4', ttl='1S'),
#             dns.Record_NS('ns1.domain', ttl='2M'),
#             dns.Record_NS('ns2.domain', ttl='3H'),
#             dns.Record_SRV(257, 16383, 43690, 'some.other.place.fool', ttl='4D')
#             ]
#         }
#     )
from canarytokens import queries
from canarytokens import canarydrop
from canarytokens.tokens import Canarytoken, TokenTypes
from canarytokens.switchboard import Switchboard
from pydantic import BaseSettings, conint
class Settings(BaseSettings):
    CHANNEL_DNS_PORT: conint(gt=0, lt=65535) = 5354
    CHANNEL_HTTP_PORT: conint(gt=0, lt=65535) = 8083
    CHANNEL_SMTP_PORT: conint(gt=0, lt=65535) = 2500
    CHANNEL_MYSQL_PORT: conint(gt=0, lt=65535) = 6033

    PUBLIC_IP:str = '10.0.1.3'

    REDIS_HOST: str = 'redis'
    REDIS_PORT: conint(gt=0, lt=65535) = 6379
    REDIS_DB: str = '0'

    LISTEN_DOMAIN: str = 'example.com'
    NXDOMAINS:List[bytes] = [b'noexample.com']
    class Config:
        env_file = 'switchboard.env'
        env_file_encoding = 'utf-8'
        env_prefix = 'CANARY_'
settings = Settings()

switchboard = Switchboard()

class ServerDNSTestCase(unittest.TestCase):
    """
    Test cases for DNS server and client.
    """
    def setUp(self) -> None:
        # clear_db()
        queries.add_canary_domain('one.example.com')
        #FIXME: Add a fixture to load expected values from a settings obj
        queries.add_canary_domain('demo.com')
        queries.add_canary_page('post.jsp')
        queries.add_canary_path_element('tags')
        return super().setUp()
    def test_channel_dns_query(self):
        """
        Test ChannelDNS.
        """
        resolver = ChannelDNS(
            listen_domain=settings.LISTEN_DOMAIN,
            switchboard=switchboard,
            settings = settings,

        )
        canarytoken = Canarytoken()
        cd = canarydrop.Canarydrop(
            type=TokenTypes.DNS,
            generate=True,
            alert_email_enabled=False,
            alert_email_recipient='email@test.com',
            alert_webhook_enabled=False,
            alert_webhook_url=None,
            canarytoken=canarytoken,
            memo='memo',
            browser_scanner_enabled=False,
        )
        queries.save_canarydrop(cd)


        m = dns.Message()
        m.addQuery(cd.get_hostname().encode(), type=dns.A)
        query = m.queries[0]
        query_result = resolver.query(query=query, src_ip='1.2.1.1').result
        response_header = query_result[0][0]

        assert response_header.type == dns.A
        assert response_header.name.name == query.name.name
        assert socket.inet_ntoa(response_header.payload.address) == settings.PUBLIC_IP

        recovered_drop = queries.get_canarydrop(canarytoken.value())

@pytest.mark.asyncio(asyncio_mode='strict')
def test_DNS_server_factory():
    dns_factory = DNSServerFactory()
    m = dns.Message()
    m.addQuery(name='example.com', type=dns.MX)
    m.addQuery(name='example.com', type=dns.AAAA)
    dns_factory.handleQuery(message=m, protocol=None, address=('2.2.2.4', '53'))
