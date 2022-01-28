from twisted.application import internet

import queries
import wireguard as wg
from canarydrop import Canarydrop
from channel import InputChannel
from constants import INPUT_CHANNEL_WIREGUARD


class ChannelWireGuard(InputChannel):
    CHANNEL = INPUT_CHANNEL_WIREGUARD

    def __init__(self, switchboard, port=wg.DEFAULT_PORT):
        InputChannel.__init__(self, switchboard, name=self.CHANNEL, unique_channel=True)
        self.service = internet.UDPServer(port, wg.WireGuardProtocol(channel=self))

    def dispatch(self, **kwargs):
        canarytoken = kwargs.pop('canarytoken')
        # TODO: If canarydrop no longer exists, delete key -> canarytoken mapping in WireGuard keymap
        kwargs['canarydrop'] = Canarydrop(**queries.get_canarydrop(canarytoken))
        InputChannel.dispatch(self, **kwargs)
