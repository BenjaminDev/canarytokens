from __future__ import annotations

import os

import pytest

from canarytokens import canarydrop
from canarytokens.exceptions import NoCanarytokenFound, UnknownAttribute
from canarytokens.queries import (add_canary_domain, add_canary_page,
                                  add_canary_path_element, get_canarydrop,
                                  save_canarydrop)
from canarytokens.redismanager import DB
from canarytokens.tokens import Canarytoken, TokenTypes
from distutils.util import strtobool

@pytest.fixture(scope="session", autouse=True)
def clear_db():
    redis_hostname = "localhost" if strtobool(os.getenv("CI", "False")) else "redis"
    DB.set_db_details(hostname=redis_hostname, port=6379)



def test_ping():

    db = DB.get_db()
    db2 = DB.get_db()
    assert db is db2
    assert db.ping()




@pytest.mark.parametrize("token_type", [o for o in TokenTypes])
def test_canarydrop(token_type):
    canarytoken = Canarytoken()
    #FIXME: Add a fixture to load expected values from a settings obj
    add_canary_domain("demo.com")
    add_canary_page("post.jsp")
    add_canary_path_element("tags")
    cd = canarydrop.Canarydrop(
        type=token_type,
        generate=True,
        alert_email_enabled=False,
        alert_email_recipient="email@test.com",
        alert_webhook_enabled=False,
        alert_webhook_url=None,
        canarytoken=canarytoken,
        memo="memo",
        browser_scanner_enabled=False,
    )
    save_canarydrop(cd)

    cd_retrieved = get_canarydrop(canarytoken.value())
    assert cd_retrieved.memo == cd.memo
    assert cd_retrieved.canarytoken.value() == cd.canarytoken.value()


def test_not_found_token():
    with pytest.raises(NoCanarytokenFound):
        Canarytoken.find_canarytoken("not_in_db")
