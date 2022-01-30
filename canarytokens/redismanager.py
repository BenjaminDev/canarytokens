import redis
from canarytokens.exceptions import RecreatingDBException
# import settings

import os

class DB:
    _db = None
    @classmethod
    def get_db(cls):
        if cls._db:
            return cls._db
        else:
            # TODO: Fix settings / config this needs a global re think.
            return cls.create_db(hostname="redis", port=6379)
    @classmethod
    def create_db(cls, *, hostname, port, logical_db=0):
        if cls._db:
            # TODO: rethink this. Should be fine but we may want to do better.
            raise RecreatingDBException("A db connection exists and we recreating it!")

        cls._db = redis.StrictRedis(
            host=hostname,
            port=port,
            db=logical_db,
            socket_timeout=10,
            encoding="utf-8",
            decode_responses=True,
        )
        return cls._db



# db.DEFAULT_EXPIRY = 120

KEY_CANARYDROP = 'canarydrop:'
KEY_CANARYDROPS_TIMELINE = 'canarydrops_timeline:'
KEY_CANARY_DOMAINS = 'canary_domains'
KEY_CANARY_NXDOMAINS = 'canary_nxdomains'
KEY_CANARY_GOOGLE_API_KEY = 'canary_google_api_key'
KEY_CANARY_PATH_ELEMENTS = 'canary_path_elements'
KEY_CANARY_PAGES = 'canary_pages'
KEY_USER_ACCOUNT = 'account:'
KEY_CANARYTOKEN_ALERT_COUNT = 'canarytoken_alert_count:'
KEY_IMGUR_TOKEN = 'imgur_token:'
KEY_IMGUR_TOKENS = 'imgur_tokens'
KEY_LINKEDIN_ACCOUNTS = 'linkedin_accounts'
KEY_LINKEDIN_ACCOUNT = 'linkedin_account:'
KEY_BITCOIN_ACCOUNTS = 'bitcoin_accounts'
KEY_BITCOIN_ACCOUNT = 'bitcoin_account:'
KEY_CLONEDSITE_TOKEN = 'cloned_site:'
KEY_CLONEDSITE_TOKENS = 'cloned_sites'
KEY_CANARY_IP_CACHE = 'geo_ip_cache:'
KEY_TOR_EXIT_NODES = 'tor_exit_nodes'
KEY_WEBHOOK_IDX = 'alertchannel_webhook:'
KEY_EMAIL_IDX = 'alertchannel_email:'
KEY_WIREGUARD_KEYMAP = 'wireguard-keymap'
KEY_KUBECONFIG_SERVEREP = 'kubeconfig_server_endpoint'
KEY_KUBECONFIG_CERTS = 'certificate:'
KEY_KUBECONFIG_HITS = 'kchit:'
