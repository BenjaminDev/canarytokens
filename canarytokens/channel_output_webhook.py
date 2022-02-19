"""
Output channel that sends to webhooks.
"""
from typing import Dict
from twisted.internet.defer import succeed
from twisted.logger import Logger
from twisted.web.iweb import IBodyProducer
from zope.interface import implementer
import httpx

log = Logger()
import simplejson
from twisted.internet import reactor
from twisted.web.client import Agent
from twisted.web.http_headers import Headers

from canarytokens.channel import InputChannel, OutputChannel
from canarytokens.constants import OUTPUT_CHANNEL_WEBHOOK
from canarytokens import canarydrop


class WebhookOutputChannel(OutputChannel):
    CHANNEL = OUTPUT_CHANNEL_WEBHOOK

    async def do_send_alert(
        self,
        input_channel: InputChannel,
        canarydrop: canarydrop.Canarydrop,
        src_ip: str,
        src_data: Dict[str, str],
    ):
        payload = input_channel.format_webhook_canaryalert(
            canarydrop=canarydrop,
            src_ip=src_ip,
            src_data=src_data,
        )
        # slack = 'https://hooks.slack.com'
        # if slack in canarydrop['alert_webhook_url']:
        #     payload = input_channel.format_slack_canaryalert(
        #         canarydrop=canarydrop,
        #         src_ip=src_ip,
        #         src_data=src_data,
        #     )
        # else:
        #     payload = input_channel.format_webhook_canaryalert(
        #         canarydrop=canarydrop,
        #         src_ip=src_ip,
        #         src_data=src_data,
        #     )

        await self.generic_webhook_send(
            payload=payload.dict(), alert_webhook_url=canarydrop.alert_webhook_url,
        )

    async def generic_webhook_send(self, payload: Dict, alert_webhook_url: str):
        def handle_response(response):
            if response.status_code != 200:
                log.error(
                    'Failed sending request to webhook {url} with code {error}'.format(
                        url=alert_webhook_url,
                        error=response.status_code,
                    ),
                )
            else:
                log.info(
                    f'Webhook sent to {alert_webhook_url}',
                )

        async with httpx.AsyncClient() as client:
            # DESIGN: If we going to offload here we might as well do it in more places
            # Benchmarks still TODO.
            response = await client.post(
                url=alert_webhook_url,
                headers=httpx.Headers({'content-type': 'application/json'}),
                json=payload,
                timeout=httpx.Timeout(
                    5.0,
                ),  # Time out on all operations after 5 seconds
            )
        handle_response(response)
        # agent = Agent(reactor)
        # body = BytesProducer(payload)
        # defr = agent.request(
        #     'POST'.encode(),
        #     str(canarydrop.alert_webhook_url).encode(),
        #     Headers({'content-type': ['application/json']}),
        #     body,
        # )
        # defr.addCallback(handle_response)
        # defr.addErrback(handle_error)
        # return await defr
