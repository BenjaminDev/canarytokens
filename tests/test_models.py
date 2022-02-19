from canarytokens import models


def test_TokenAlertDetailsSlack():
    token_details = models.TokenAlertDetailsSlack(
        channel='https://hook.slack.com/test', attachments=[],
    )
    token_details.json()
