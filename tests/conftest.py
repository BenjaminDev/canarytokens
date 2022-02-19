from distutils.util import strtobool
import os
import pytest
from canarytokens.redismanager import DB
from canarytokens.settings import Settings

# class Settings(BaseSettings):
#     CHANNEL_DNS_PORT: conint(gt=0, lt=65535) = 5354
#     CHANNEL_HTTP_PORT: conint(gt=0, lt=65535) = 8083
#     CHANNEL_SMTP_PORT: conint(gt=0, lt=65535) = 2500
#     CHANNEL_MYSQL_PORT: conint(gt=0, lt=65535) = 6033

#     PUBLIC_IP:str = '10.0.1.3'

#     REDIS_HOST: str = 'redis'
#     REDIS_PORT: conint(gt=0, lt=65535) = 6379
#     REDIS_DB: str = '0'

#     LISTEN_DOMAIN: str = 'example.com'
#     NXDOMAINS:List[bytes] = [b'noexample.com']
#     class Config:
#         env_file = 'switchboard.env'
#         env_file_encoding = 'utf-8'
#         env_prefix = 'CANARY_'


@pytest.fixture
def settings():
    # Settings.LISTEN_DOMAIN = 'example.com'
    # Settings.NXDOMAINS = [b'noexample.com']
    # Settings.PUBLIC_IP = '10.0.1.3'
    return Settings(
        LISTEN_DOMAIN='example.com',
        NXDOMAINS=[b'noexample.com'],
        PUBLIC_IP='10.0.1.3',
    )


@pytest.fixture(scope='session', autouse=True)
def clear_db():
    redis_hostname = 'localhost' if strtobool(os.getenv('CI', 'False')) else 'redis'
    DB.set_db_details(hostname=redis_hostname, port=6379)
    db = DB.get_db()
    for key in db.scan_iter():
        db.delete(key)
    yield
    for key in db.scan_iter():
        db.delete(key)
