"""
Class that receives alerts, and dispatches them to the registered endpoint.
"""

from twisted.logger import Logger

log = Logger()

from canarytokens.exceptions import DuplicateChannel, InvalidChannel


class Switchboard(object):
    def __init__(
        self,
    ):
        """Return a new Switchboard instance."""
        self.input_channels = {}
        self.output_channels = {}
        log.info('Canarytokens switchboard started')

    def add_input_channel(self, name=None, channel=None):
        """Register a new input channel with the switchboard.

        Arguments:
        name -- unique name for the input channel
        formatters -- a dict in the form { TYPE: METHOD,...} used to lookup
                      the channel's format method depending on the alert type
        """
        if name in self.input_channels:
            raise DuplicateChannel()

        self.input_channels[name] = channel

    def add_output_channel(self, name=None, channel=None):
        """Register a new output channel with the switchboard.

        Arguments:
        name -- unique name for the input channel
        formatters -- a dict in the form { TYPE: METHOD,...} used to lookup
                      the channel's format method depending on the alert type
        """
        if name in self.output_channels:
            raise DuplicateChannel()

        self.output_channels[name] = channel

    def dispatch(self, input_channel=None, canarydrop=None, **kwargs):
        """Calls the correct alerting method for the trigger and channel combination.

        For now it prints to stdout.

        TODO: this spawns threads to actually do the alerting

        Arguments:
        input_channel -- name of the channel on which the alert originated
        canarydrop -- a Canarydrop instance
        **kwargs -- passed to the channel instance's formatter methods
        """
        try:
            if input_channel not in self.input_channels:
                raise InvalidChannel()

            canarydrop.add_canarydrop_hit(input_channel=input_channel, **kwargs)

            if not canarydrop.alertable():
                log.warn(
                    'Token {token} is not alertable at this stage.'.format(
                        token=canarydrop.canarytoken.value(),
                    ),
                )
                return

            # update accounting info
            canarydrop.alerting(input_channel=input_channel, **kwargs)

            for requested_output_channel in canarydrop.get_requested_output_channels():
                try:
                    output_channel = self.output_channels[requested_output_channel]
                    output_channel.send_alert(
                        canarydrop=canarydrop,
                        input_channel=self.input_channels[input_channel],
                        **kwargs,
                    )
                except KeyError as e:
                    raise Exception('Error sending alert: {err}'.format(err=e.message))
        except Exception as e:
            log.error('Exception occurred in switchboard dispatch: {err}'.format(err=e))
