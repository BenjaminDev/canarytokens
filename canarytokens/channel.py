""""
Base class for all canarydrop channels.
"""

from typing import Union
import datetime

from typing import Dict, List

import simplejson
from pydantic import BaseSettings
from twisted.logger import Logger
from canarytokens.canarydrop import Canarydrop
from twisted.internet import defer
from canarytokens.exceptions import DuplicateChannel
from canarytokens.models import (
    SlackField,
    TokenAlertDetailGeneric,
    TokenAlertDetails,
    TokenAlertDetailsSlack,
    SlackAttachment,
)
from canarytokens.switchboard import Switchboard

log = Logger()


def format_as_slack_canaryalert(details: TokenAlertDetails) -> TokenAlertDetailsSlack:
    fields: List[SlackField] = [
        SlackField(title='Channel', value=details.channel),
        SlackField(title='Memo', value=details.memo),
        SlackField(
            title='time', value=details.time.strftime('%Y-%m-%d %H:%M:%S (UTC)'),
        ),
        SlackField(title='Manage', value=details.manage_url),
    ]

    attchments = [SlackAttachment(title_link=details.manage_url, fields=fields)]
    return TokenAlertDetailsSlack(
        # channel="#general",
        attachments=attchments,
    )


#     attachment = {
#             'title': 'Canarytoken Triggered\n',
#             'title_link': manage_link,
#             'mrkdwn_in': ['title'],
#             'fallback': 'Canarytoken Triggered: {link}'.format(link=manage_link),
#         }
#         fields.append({'title': 'Channel', 'value': self.name})
#         fields.append({'title': 'Memo', 'value': canarydrop.memo})
#         fields.append(
#             {
#                 'title': 'Time',
#                 'value': datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S (UTC)'),
#             },
#         )
#         fields.append({'title': 'Manage', 'value': manage_link})
#         attachment['fields'] = fields
#         payload['attachments'] = [attachment]
#         breakpoint()
#         return payload


class Channel(object):
    CHANNEL = 'Base'

    def __init__(self, switchboard=None, name=None):
        self.switchboard: Switchboard = switchboard
        self.name = name or self.CHANNEL
        log.info('Started channel {name}'.format(name=self.name))


class InputChannel(Channel):
    CHANNEL = 'InputChannel'

    def __init__(
        self,
        switchboard,
        name: str,
        settings: BaseSettings,
        unique_channel=False,
    ):
        super(InputChannel, self).__init__(switchboard=switchboard, name=name)
        self.settings = settings
        try:
            self.register_input_channel()
        except DuplicateChannel as e:
            if unique_channel:
                raise e

    def register_input_channel(
        self,
    ):
        self.switchboard.add_input_channel(name=self.name, channel=self)

    @classmethod
    def gather_alert_details(
        cls,
        canarydrop,
        protocol='https',
        host='localhost.com',  # DESIGN: Shift this to settings. Do we need to have this logic here?
    ) -> TokenAlertDetails:
        return TokenAlertDetails(
            channel=cls.CHANNEL,
            time=datetime.datetime.utcnow(),
            memo=canarydrop.memo,
            # TODO: this manage url should come from the backend / settings object.
            manage_url='{protocol}://{host}/manage?token={token}&auth={auth}'.format(
                protocol=protocol,
                host=host,
                token=canarydrop.canarytoken.value(),
                auth=canarydrop.auth,
            ),
            additional_data={},
        )

    @classmethod
    def format_webhook_canaryalert(
        cls,
        canarydrop,
        protocol='https',
        host='localhost.com',  # DESIGN: Shift this to settings. Do we need to have this logic here?
        **kwargs,
    ) -> Union[TokenAlertDetailsSlack, TokenAlertDetailGeneric]:
        # TODO: This can be done better! Not sure
        details = cls.gather_alert_details(
            canarydrop, protocol='https', host='localhost.com',
        )
        if 'https://hooks.slack.com' in canarydrop['alert_webhook_url']:
            return format_as_slack_canaryalert(details=details)
        else:
            return details

    #     payload = {}

    #     if not host or host == '':
    #         host = self.settings.PUBLIC_IP

    #     payload['channel'] = self.name
    #     payload['time'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S (UTC)')
    #     payload['memo'] = canarydrop.memo
    #     payload[
    #         'manage_url'
    #     ] = '{protocol}://{host}/manage?token={token}&auth={auth}'.format(
    #         protocol=protocol,
    #         host=host,
    #         token=canarydrop['canarytoken'],
    #         auth=canarydrop['auth'],
    #     )
    #     payload['additional_data'] = kwargs

    #     return payload

    # def format_slack_canaryalert(
    #     self,
    #     canarydrop,
    #     src_ip:str,
    #     src_data:Dict[str, str],
    #     host='localhost.com', #DESIGN:
    #     protocol='https', # DESIGN: move this decision to settings
    # ):
    #     details = TokenAlertDetails(
    #         channel=self.name,
    #         time=datetime.datetime.utcnow(),
    #         memo=canarydrop.memo,
    #         manage_url='{protocol}://{host}/manage?token={token}&auth={auth}'.format(protocol=protocol, host=host, token=canarydrop.canarytoken.value(), auth=canarydrop.auth,               ),
    #         additional_data={}
    #     )
    #     slack_details = format_as_slack_canaryalert(details=details)

    #     return slack_details.dict()
    # TODO: move to channel output email or make it a pure standalone function
    # Seems to be used in twilio as well.
    def format_canaryalert(
        self,
        canarydrop,
        protocol,
        host,
        params=None,
        **kwargs,
    ):
        msg = {}
        if not host or host == '':
            host = self.settings.PUBLIC_IP

        if 'useragent' in kwargs:
            msg['useragent'] = kwargs['useragent']

        if 'referer' in kwargs:
            msg['referer'] = kwargs['referer']

        if 'location' in kwargs:
            msg['location'] = kwargs['location']

        if 'src_ip' in kwargs:
            msg['src_ip'] = kwargs['src_ip']

        msg['time'] = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S (UTC)')
        msg['channel'] = self.name

        if 'src_data' in kwargs and 'aws_keys_event_source_ip' in kwargs['src_data']:
            msg['src_ip'] = kwargs['src_data']['aws_keys_event_source_ip']
            msg['channel'] = 'AWS API Key Token'

        if 'src_data' in kwargs and 'aws_keys_event_user_agent' in kwargs['src_data']:
            msg['useragent'] = kwargs['src_data']['aws_keys_event_user_agent']

        if 'src_data' in kwargs and 'log4_shell_computer_name' in kwargs['src_data']:
            msg['log4_shell_computer_name'] = kwargs['src_data'][
                'log4_shell_computer_name'
            ]

        if params.get('body_length', 999999999) <= 140:
            msg['body'] = """Canarydrop@{time} via {channel_name}: """.format(
                channel_name=self.name,
                time=msg['time'],
            )
            capacity = 140 - len(msg['body'])
            msg['body'] += canarydrop.memo[:capacity]
        else:
            msg[
                'body'
            ] = """
One of your canarydrops was triggered.
Channel: {channel_name}
Time   : {time}
Memo   : {memo}
{additional_data}
Manage your settings for this Canarydrop:
{protocol}://{host}/manage?token={token}&auth={auth}""".format(
                channel_name=self.name,
                time=msg['time'],
                memo=canarydrop.memo,
                additional_data=self.format_additional_data(**kwargs),
                protocol=protocol,
                host=host,
                token=canarydrop['canarytoken'],
                auth=canarydrop['auth'],
            )
            msg[
                'manage'
            ] = '{protocol}://{host}/manage?token={token}&auth={auth}'.format(
                protocol=protocol,
                host=host,
                token=canarydrop['canarytoken'],
                auth=canarydrop['auth'],
            )
            msg[
                'history'
            ] = '{protocol}://{host}/history?token={token}&auth={auth}'.format(
                protocol=protocol,
                host=host,
                token=canarydrop['canarytoken'],
                auth=canarydrop['auth'],
            )

        if params.get('subject_required', False):
            msg['subject'] = self.settings.ALERT_EMAIL_SUBJECT
        if params.get('from_display_required', False):
            msg['from_display'] = self.settings.ALERT_EMAIL_FROM_DISPLAY
        if params.get('from_address_required', False):
            msg['from_address'] = self.settings.ALERT_EMAIL_FROM_ADDRESS
        return msg

    def dispatch(self, *, canarydrop, src_ip, src_data):
        defer.ensureDeferred(
            self.switchboard.dispatch(
                input_channel=self.name,
                canarydrop=canarydrop,
                src_ip=src_ip,
                src_data=src_data,
            ),
        )


class OutputChannel(Channel):
    CHANNEL = 'OutputChannel'

    def __init__(self, switchboard=None, name=None):
        super(OutputChannel, self).__init__(switchboard=switchboard, name=name)
        self.register_output_channel()

    def register_output_channel(
        self,
    ):
        self.switchboard.add_output_channel(name=self.name, channel=self)

    async def send_alert(
        self,
        input_channel,
        canarydrop: Canarydrop,
        src_ip: str,
        src_data: Dict[str, str],
    ):
        # TODO: get rid of that kwargs
        await self.do_send_alert(
            input_channel=input_channel,
            canarydrop=canarydrop,
            src_ip=src_ip,
            src_data=src_data,
        )

    def do_send_alert(self, **kwargs):
        #  Design: Make this a protocol and drop this.
        raise NotImplementedError('Generic Output channel cannot `do_send_alert`')
