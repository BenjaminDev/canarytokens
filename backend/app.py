from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from canarytokens.canarydrop import Canarydrop, Canarytoken
from canarytokens.models import DNSTokenRequest, DNSTokenResponse
from canarytokens.queries import (
    add_canary_domain,
    remove_canary_domain,
    save_canarydrop,
)

# from canarytokens.settings import Settings
from canarytokens.redismanager import DB
from canarytokens.tokens import TokenTypes

# Settings.Config.env_file = "backend.env"
# settings = Settings()
app = FastAPI()


@app.on_event('startup')
def startup_event():
    DB.set_db_details(hostname='redis', port=6379)
    remove_canary_domain()
    add_canary_domain(domain='127.0.0.1')


@app.post('/generate')
def generate(details: DNSTokenRequest) -> DNSTokenResponse:
    canarytoken = Canarytoken()
    canarydrop = Canarydrop(
        generate=True,
        type=details.token_type,
        alert_email_enabled=True,
        alert_email_recipient=details.email,
        alert_webhook_enabled=True,
        alert_webhook_url=details.webhook_url,
        canarytoken=canarytoken,
        memo=details.memo,
        browser_scanner_enabled=False,
    )
    save_canarydrop(canarydrop)
    return DNSTokenResponse(
        email=canarydrop.get('alert_email_recipient'),
        token=canarydrop.canarytoken.value(),
        token_url=canarydrop.get_url(),
        auth_token=canarydrop['auth'],
        hostname=canarydrop.get_hostname(),
    )
