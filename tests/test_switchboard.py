import pytest
from canarytokens.channel import InputChannel
from canarytokens.channel_dns import ChannelDNS
from canarytokens.channel_output_webhook import WebhookOutputChannel
from canarytokens.exceptions import InvalidChannel
from canarytokens import queries
from canarytokens import canarydrop
from canarytokens.tokens import Canarytoken, TokenTypes
from canarytokens.switchboard import Switchboard


@pytest.mark.asyncio(asyncio_mode='strict')
async def test_switchboard_no_channels():
    switchboard = Switchboard()
    with pytest.raises(InvalidChannel):
        await switchboard.dispatch(
            input_channel='not_valid',
            canarydrop=None,
            src_ip='10.2.1.1',
            src_data={'some': 'data'},
        )


def test_switchboard_register_input_channel(settings):
    switchboard = Switchboard()
    dns_input_channel = ChannelDNS(switchboard=switchboard, settings=settings)
    # switchboard.add_input_channel(name="http")
    assert dns_input_channel.name in switchboard.input_channels
    assert dns_input_channel.CHANNEL in switchboard.input_channels


@pytest.mark.asyncio(asyncio_mode='strict')
@pytest.mark.parametrize(
    'alert_webhook_url',
    [
        'https://hooks.slack.com/services/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',
        'https://example.com/test',
    ],
)
async def test_switchboard_register_input_channel(settings, alert_webhook_url):
    switchboard = Switchboard()

    webhook_output_channel = WebhookOutputChannel(switchboard=switchboard)
    switchboard.add_input_channel(
        name='tester',
        channel=InputChannel(
            switchboard=switchboard,
            name='tester',
            settings=settings,
        ),
    )
    canarytoken = Canarytoken()
    cd = canarydrop.Canarydrop(
        type=TokenTypes.DNS,
        generate=True,
        alert_email_enabled=False,
        alert_email_recipient='email@test.com',
        alert_webhook_enabled=True,
        alert_webhook_url=alert_webhook_url,
        canarytoken=canarytoken,
        memo='memo',
        browser_scanner_enabled=False,
    )
    # queries.save_canarydrop(cd)
    await switchboard.dispatch(
        input_channel='tester',
        canarydrop=cd,
        src_ip='10.2.1.1',
        src_data={'some': 'data'},
    )
    await switchboard.dispatch(
        input_channel='tester',
        canarydrop=cd,
        src_ip='10.0.1.1',
        src_data={'more': 'data'},
    )

    # await webhook_output_channel.generic_webhook_send(payload={"stuff": "ddd"}, canarydrop=cd)
    # switchboard.add_input_channel(name="http")
    triggered_stuff = queries.get_canarydrop_triggered_list(canarytoken)
    assert len(triggered_stuff) == 2

    assert webhook_output_channel.name in switchboard.output_channels
    assert webhook_output_channel.CHANNEL in switchboard.output_channels
