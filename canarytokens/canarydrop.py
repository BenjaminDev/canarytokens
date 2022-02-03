"""
A Canarydrop ties a canarytoken to an alerting mechanisms,
and records accounting information about the Canarytoken.

Maps to the object stored in Redis.
"""
from __future__ import annotations

import base64
import json
from typing import List, Union

import os
import random
from hashlib import md5
from typing import Any, Dict, Optional
from datetime import datetime
import pyqrcode
import simplejson
from pydantic import BaseModel, EmailStr, HttpUrl, constr

# import wireguard as wg
from canarytokens.constants import (OUTPUT_CHANNEL_EMAIL,
                                    OUTPUT_CHANNEL_TWILIO_SMS,
                                    OUTPUT_CHANNEL_WEBHOOK)
from canarytokens.exceptions import (NoCanarytokenPresent, NoUser,
                                     UnknownAttribute)
from canarytokens.models import Anonymous, User
from canarytokens import queries
#  import (add_additional_info_to_hit,
#                                   add_canarydrop_hit, get_all_canary_domains,
#                                   get_all_canary_nxdomains,
#                                   get_all_canary_pages,
#                                   get_all_canary_path_elements,
#                                   get_all_canary_sites,
#                                   get_canarydrop_triggered_list, load_user)
# from canarytokens.tokens import Canarytoken
# from users import AnonymousUser, User
from canarytokens.tokens import Canarytoken, TokenTypes

# class CanaryDropData(BaseModel):
#     canarytoken: Canarytoken
#     alert_email_enabled: bool
#     alert_email_recipient: EmailStr
#     alert_sms_enabled: bool = False
#     alert_sms_recipient: constr(max_length=50, strip_whitespace=True) = None

# class



class Canarydrop(BaseModel):
    # TODO: model these bool, channel_detail pattern into a data class
    canarytoken: Canarytoken
    triggered_count: int = 0
    triggered_details: Dict[str, Any] = {}
    memo: str
    created_at: datetime = datetime.now()
    auth: str = md5(
                str(
                    random.SystemRandom().randrange(start=1, stop=2 ** 128, step=2)
                ).encode(),
            ).hexdigest()
    type: TokenTypes
    user: Union[User, Anonymous] = Anonymous()

    # Alerting details
    alert_email_enabled: bool  = False
    alert_email_recipient: EmailStr
    alert_sms_enabled: bool = False
    alert_sms_recipient: Optional[str] = None
    alert_webhook_enabled: bool = False
    alert_webhook_url: Optional[HttpUrl]

    # "generated_url",
    # "generated_email",
    # "generated_hostname",
    # "imgur_token",
    # "imgur",
    # "browser_scanner_enabled",
    # "web_image_path",
    # "web_image_enabled",
    # "clonedsite",
    # "aws_secret_access_key",
    # "aws_access_key_id",
    # "redirect_url",
    # "region",
    # "output",
    # "slack_api_key",
    # "wg_key",
    # "kubeconfig",
    # allowed_attrs = [
    # ]
    class Config:
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.strftime('%Y-%m-%dT%H:%M:%S'),
        }

    def add_additional_info_to_hit(self, hit_time=None, additional_info={}):
        try:
            hit_time = hit_time or self._drop["hit_time"]
        except:
            hit_time = self._drop["hit_time"] = datetime.datetime.utcnow().strftime(
                "%s.%f",
            )

        if hit_time not in queries.get_canarydrop_triggered_list(self.canarytoken):
            self.add_canarydrop_hit()

        queries.add_additional_info_to_hit(self.canarytoken, hit_time, additional_info)

    def add_canarydrop_hit(self, input_channel="http", **kwargs):
        # if "hit_time" in list(self._drop.keys()):
        #     hit_time = self._drop["hit_time"]
        # else:
        #     hit_time = None
        # TODO: Review the timeline of a canarydrop hit.
        queries.add_canarydrop_hit(
            self.canarytoken,
            input_channel=input_channel,
            hit_time=None,
            **kwargs,
        )

    def get_url_components(
        self,
    ):
        return (
            queries.get_all_canary_sites(),
            queries.get_all_canary_path_elements(),
            queries.get_all_canary_pages(),
        )

    def generate_random_url(
        self,
    ):
        """Return a URL generated at random with the saved Canarytoken.
        The random URL is also saved into the Canarydrop."""
        (sites, path_elements, pages) = self.get_url_components()

        generated_url = sites[random.randint(0, len(sites) - 1)] + "/"
        path = []
        for count in range(0, random.randint(1, 3)):
            if len(path_elements) == 0:
                break

            elem = path_elements[random.randint(0, len(path_elements) - 1)]
            path.append(elem)
            path_elements.remove(elem)
        path.append(self._drop["canarytoken"])

        path.append(pages[random.randint(0, len(pages) - 1)])
        generated_url += "/".join(path)

        self._drop["generated_url"] = generated_url

        return self._drop["generated_url"]

    def get_random_site(
        self,
    ):
        sites = queries.get_all_canary_sites()
        return sites[random.randint(0, len(sites) - 1)]

    def get_url(
        self,
    ):
        if "generated_url" in self._drop:
            return self._drop["generated_url"]
        return self.generate_random_url()

    def generate_random_hostname(self, with_random=False, nxdomain=False):
        """Return a hostname generated at random with the saved Canarytoken.
        The random hostname is also saved into the Canarydrop."""
        if nxdomain:
            domains = queries.get_all_canary_nxdomains()
        else:
            domains = queries.get_all_canary_domains()

        if with_random:
            generated_hostname = str(random.randint(1, 2 ** 24)) + "."
        else:
            generated_hostname = ""

        generated_hostname += (
            self.canarytoken.value()
            # self._drop["canarytoken"]
            + "."
            + domains[random.randint(0, len(domains) - 1)].decode()
        )

        return generated_hostname

    def get_hostname(self, with_random=False, as_url=False, nxdomain=False):

        random_hostname = self.generate_random_hostname(
            with_random=with_random,
            nxdomain=nxdomain,
        )
        return ("http://" if as_url else "") + random_hostname

    def get_requested_output_channels(
        self,
    ):
        """Return a list containing the output channels configured in this
        Canarydrop."""
        channels: List[str] = []
        if self.alert_email_enabled and self.alert_email_recipient:
            channels.append(OUTPUT_CHANNEL_EMAIL)
        if self.alert_webhook_enabled and self.alert_webhook_url:
            channels.append(OUTPUT_CHANNEL_WEBHOOK)
        if self.alert_sms_enabled and self.alert_sms_recipient:
            channels.append(OUTPUT_CHANNEL_TWILIO_SMS)
        return channels

    def _get_image_as_base64(self, path):
        if os.path.exists(path):
            with open(path, "r") as f:
                contents = f.read()
            return base64.b64encode(contents)

    def get_web_image_as_base64(
        self,
    ):
        return self._get_image_as_base64(self["web_image_path"])

    def get_secretkeeper_photo_as_base64(self, item):
        return self._get_image_as_base64(
            self["triggered_list"][item]["additional_info"]["secretkeeper_photo"],
        )

    def get_cloned_site_javascript(
        self,
    ):
        CLONED_SITE_JS = """
if (document.domain != "CLONED_SITE_DOMAIN" && document.domain != "www.CLONED_SITE_DOMAIN") {
    var l = location.href;
    var r = document.referrer;
    var m = new Image();
    m.src = "CANARYTOKEN_SITE/"+
            "CANARYTOKEN.jpg?l="+
            encodeURI(l) + "&amp;r=" + encodeURI(r);
}
                """
        return (
            CLONED_SITE_JS.replace("CLONED_SITE_DOMAIN", self["clonedsite"])
            .replace("CANARYTOKEN_SITE", self.get_random_site())
            .replace("CANARYTOKEN", self["canarytoken"])
        )

    def get_qrcode_data_uri_png(
        self,
    ):
        qrcode = pyqrcode.create(self.get_url()).png_as_base64_str(scale=5)
        return "data:image/png;base64,{qrcode}".format(qrcode=qrcode)

    def get_wg_conf(self):
        return wg.clientConfig(self._drop["wg_key"])

    def get_wg_qrcode(self):
        wg_conf = self.get_wg_conf()
        qrcode = pyqrcode.create(wg_conf).png_as_base64_str(scale=2)
        return "data:image/png;base64,{}".format(qrcode)






    def serialize(
        self,
    ):
        """Return a representation of this Canarydrop suitable for saving
        into redis."""
        # TODO: rip out the _drop make this a dataclass or pydantic class
        # DESIGN: this needs a re-work. defering until tests passing and coverage is high.
        serialized = json.loads(self.json(exclude={"canarytoken"})) # TODO: check https://github.com/samuelcolvin/pydantic/issues/1409 and swap out when possible

        # serialized = self._drop.copy()
        serialized["type"] = str(serialized["type"])
        for k, v in serialized.copy().items():
            if isinstance(v, bool):
                serialized[k] = str(v)
            if v is None:  # HACK: will fix once _drop is gone.
                serialized.pop(k, None)
        if serialized["user"]:
            serialized["user"] = serialized["user"]["name"]

        if "triggered_details" in list(serialized.keys()):
            serialized["triggered_details"] = simplejson.dumps(
                serialized["triggered_details"],
            )
        for key in [
            # "type",
            # "alert_email_enabled",
            # "alert_email_recipient",
            # "alert_webhook_enabled",
            # "alert_webhook_url",
            # "canarytoken",
            # "memo",
            # "browser_scanner_enabled",
            # "timestamp",
            # "user",
            # "auth",
            # "alert_sms_enabled",
            # "web_image_enabled",
            # "generated_url",
        ]:
            serialized.pop(key, None)
        return serialized

    def alertable(
        self,
    ):
        if self.user.can_send_alert(canarydrop=self):
            return True
        else:
            return False

    def alerting(self, input_channel=None, **kwargs):
        self.user.do_accounting(canarydrop=self)

    def __getitem__(self, key):
        #TODO: remove __getitem__ but for now we hack it!
        return getattr(self, key)

    def __setitem__(self, key, value):
        self._drop[key] = value

    def get(self, *args):
        try:
            return self._drop[args[0]]
        except KeyError:
            if len(args) == 2:
                return args[1]
            raise KeyError(args[0])
