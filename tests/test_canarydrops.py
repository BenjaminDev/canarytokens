from __future__ import annotations

import pytest

from canarytokens import canarydrop
from canarytokens.exceptions import NoCanarytokenFound, UnknownAttribute
from canarytokens.queries import (add_canary_domain, get_canarydrop,
                                  save_canarydrop)
from canarytokens.redismanager import DB

# from exception import NoCanarytokenFound, UnknownAttribute


def test_ping():
    db = DB.get_db()
    db2 = DB.get_db()
    assert db is db2
    assert db.ping()


from canarytokens.tokens import Canarytoken, TokenTypes


@pytest.mark.parametrize("token_type", [o for o in TokenTypes])
def test_canarydrop(token_type):
    canarytoken = Canarytoken()
    add_canary_domain("demo.com")
    cd = canarydrop.Canarydrop(
        type=token_type,
        generate=True,
        alert_email_enabled=False,
        alert_email_recipient="email@test.com",
        alert_webhook_enabled=False,
        alert_webhook_url=None,
        canarytoken=canarytoken.value(),
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


def test_extra_attribute():
    with pytest.raises(UnknownAttribute):
        canarydrop.Canarydrop(
            type=TokenTypes.WEB,
            not_in=True,
            generate=True,
            alert_email_enabled=False,
            alert_email_recipient="email@test.com",
            alert_webhook_enabled=False,
            alert_webhook_url=None,
            canarytoken="ddd",
            memo="memo",
            browser_scanner_enabled=False,
        )
