from datetime import datetime
import email
from re import L
from secrets import token_bytes
from typing import Any, Dict, List, NewType, Optional
from wsgiref.validate import validator

from attr import validate
from pydantic import BaseModel, EmailStr, HttpUrl, constr
import json

# from canarytokens.queries import is_webhook_valid
from canarytokens.tokens import TokenTypes

# DESIGN: We'll want a constraint on this but what is sensible as a user and what is practical for out system?
MEMO_MAX_CHARACTERS = 1000

memo_type = constr(max_length=MEMO_MAX_CHARACTERS)


def json_safe_dict(m: BaseModel) -> Dict[str, str]:
    return json.loads(m.json())


class Token(BaseModel):
    token_type: TokenTypes
    email: EmailStr
    webhook_url: HttpUrl
    memo: memo_type

    # @validator("memo")
    # def check_memo(cls, value:str)->str:
    #     max_memo_length = 2000
    #     if len(value) > max_memo_length:
    #         raise ValueError(f"Memo is limited to {max_memo_length}, length: {len(value)} was given")
    #     return value

    # @validator("name", "sector", "area")
    # def check_names(cls,v):
    # @validator("webhook")
    # def check_webhook(cls, value:HttpUrl):
    #     valid_webhook_resp_codes={200}
    #     if is_webhook_valid(value):
    #         raise ValueError(f"webhook: {value} does not respone with a valid status code. Only {valid_webhook_resp_codes} are valid")
    #     return value


class DNSTokenRequest(Token):
    token_type: TokenTypes = TokenTypes.DNS


class DNSTokenResponse(BaseModel):
    token_type: TokenTypes = TokenTypes.DNS
    token: str
    hostname: str
    token_url: HttpUrl
    auth_token: str
    # {"Token": "0nomj9kspdad3kpecqakf7ni8", "Hostname":
    # "0nomj9kspdad3kpecqakf7ni8.canarytokens.com",
    # "Url_components":
    # [["http://canarytokens.com"],
    # ["articles", "about", "terms", "feedback", "tags", "traffic", "images", "static"],
    # ["submit.aspx", "index.html", "post.jsp", "contact.php"]], "Error": null,
    # "Url": "http://canarytokens.com/static/images/traffic/0nomj9kspdad3kpecqakf7ni8/submit.aspx",
    # "Error_Message": null,
    # "Email": "test@test.com", "Auth": "cee1c1693bd2b3ab0db1c4b9db40c7cf"}


class User(BaseModel):
    name: constr(max_length=30, strip_whitespace=True, to_lower=True)
    email: Optional[EmailStr] = None
    # alert_expiry -> attach this to a user or a token?
    # alert_limit -> attach this to a user or a token?
    # alert_count -> attach this to a user or a token?
    def can_send_alert(self, canarydrop):
        return True  # TODO: user object may need some work.

    def do_accounting(self, canarydrop):
        # TODO: DESIGN: User object how should we manage them
        return


class Anonymous(User):
    name: constr(max_length=30, strip_whitespace=True, to_lower=True) = 'Anonymous'


class TokenAlertDetails(BaseModel):
    channel: str
    # Design: Is this a good name? Should it be time of trigger. Or time we recieved the event? Or time we sent this out?
    time: datetime
    memo: memo_type
    manage_url: HttpUrl
    # TODO: pin this dict down and make it a type. We know what this can be.
    additional_data: Dict[str, str]

    def dict(self) -> Dict[str, str]:
        return json_safe_dict(self)

    class Config:
        json_encoders = {
            datetime: lambda v: v.strftime('%Y-%m-%d %H:%M:%S (UTC)'),
        }


class SlackField(BaseModel):
    title: str
    value: str
    short: bool = True


class SlackAttachment(BaseModel):
    title: str = 'Canarytoken Triggered'
    title_link: HttpUrl
    mrkdwn_in: List[str] = ['title']
    fallback: str = ''
    fields: List[SlackField]

    def __init__(__pydantic_self__, **data: Any) -> None:
        # HACK: We can do better here.
        data['fallback'] = 'Canarytoken Triggered: {}'.format(data['title_link'])
        super().__init__(**data)


class TokenAlertDetailsSlack(BaseModel):
    # channel:str
    attachments: List[SlackAttachment]

    def dict(self) -> Dict[str, str]:
        return json_safe_dict(self)


TokenAlertDetailGeneric = NewType('TokenAlertDetailGeneric', TokenAlertDetails)
