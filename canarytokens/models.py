import email
from secrets import token_bytes
from typing import Optional
from wsgiref.validate import validator
from attr import validate
from pydantic import BaseModel, EmailStr, HttpUrl, constr
# from canarytokens.queries import is_webhook_valid
from canarytokens.tokens import TokenTypes

class Token(BaseModel):
    token_type: TokenTypes
    email:EmailStr
    webhook_url:HttpUrl
    memo:str

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
    token:str
    hostname:str
    token_url:HttpUrl
    auth_token:str
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

class Anonymous(User):
    name: constr(max_length=30, strip_whitespace=True, to_lower=True) = "Anonymous"