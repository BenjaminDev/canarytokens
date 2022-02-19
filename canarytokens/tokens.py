from __future__ import annotations

import enum
import math
import random
import re
from difflib import Match
from turtle import st
from typing import AnyStr, Dict, Tuple

from canarytokens.exceptions import NoCanarytokenFound

# from canarytokens.canarydrop import Canarydrop
# from exception import NoCanarytokenFound
from canarytokens import queries
from twisted.names.dns import Name


class TokenTypes(enum.Enum):
    WEB = 'web'
    DNS = 'dns'
    WEB_IMAGE = 'web_image'
    MS_WORD = 'ms_word'
    MS_EXCEL = 'ms_exel'
    ADOBE_PDF = 'adobe_pdf'
    WIREGUARD = 'wireguard'
    WINDOWS_DIR = 'windows_dir'
    CLONEDSITE = 'clonedsite'
    QR_CODE = 'qr_code'
    SVN = 'svn'
    SMTP = 'smtp'
    SQL_SERVER = 'sql_server'
    MY_SQL = 'my_sql'
    AWS_KEYS = 'aws_keys'
    SIGNED_EXE = 'signed_exe'
    FAST_REDIRECT = 'fast_redirect'
    SLOW_REDIRECT = 'slow_redirect'
    KUBE_CONFIG = 'kubeconfig'
    LOG_4_SHELL = 'log4shell'

    def __str__(self) -> str:
        return str(self.value)


canarytoken_ALPHABET = [
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
]
canarytoken_LENGTH = 25  # equivalent to 128-bit id

# TODO: put these in a nicer place. Ensure re.compile is called only once at startup
# add a naming convention for easy reading when seen in other files.
# Check that state is not stored in these eg: x=re.compile(...) x.match() === A and then x.match() === A still
sql_server_username = re.compile(
    r'([A-Za-z0-9.-]*)\.[0-9]{2}\.',
    re.IGNORECASE,
)
mysql_username = re.compile(r'([A-Za-z0-9.-]*)\.M[0-9]{3}\.', re.IGNORECASE)
linux_inotify = re.compile(r'([A-Za-z0-9.-]*)\.L[0-9]{2}\.', re.IGNORECASE)
generic = re.compile(r'([A-Za-z0-9.-]*)\.G[0-9]{2}\.', re.IGNORECASE)
dtrace_process = re.compile(
    r'([0-9]+)\.([A-Za-z0-9-=]+)\.h\.([A-Za-z0-9.-=]+)\.c\.([A-Za-z0-9.-=]+)\.D1\.',
    re.IGNORECASE,
)
dtrace_file_open = re.compile(
    r'([0-9]+)\.([A-Za-z0-9-=]+)\.h\.([A-Za-z0-9.-=]+)\.f\.([A-Za-z0-9.-=]+)\.D2\.',
    re.IGNORECASE,
)
desktop_ini_browsing = re.compile(
    r'([^\.]+)\.([^\.]+)\.?([^\.]*)\.ini\.',
    re.IGNORECASE,
)
log4_shell = re.compile(r'([A-Za-z0-9.-]*)\.L4J\.', re.IGNORECASE)

# TODO: we can do better than this.
# ??
source_data_extractors = {
    'sql_server_username': sql_server_username,
    'mysql_username': mysql_username,
    'linux_inotify': linux_inotify,
    'generic': generic,
    'dtrace_process': dtrace_process,
    'dtrace_file_open': dtrace_file_open,
    'desktop_ini_browsing': desktop_ini_browsing,
    'log4_shell': log4_shell,
}


def handle_query_name(query_name: Name) -> Tuple[Canarydrop, Dict[str, str]]:
    query_name = query_name.name.decode()
    token = Canarytoken(value=query_name)

    canarydrop = queries.get_canarydrop(canarytoken=token.value())

    src_data = Canarytoken.look_for_source_data(query_name=query_name)
    return canarydrop, src_data


class Canarytoken(object):
    CANARY_RE = re.compile(
        '.*(['
        + ''.join(canarytoken_ALPHABET)
        + ']{'
        + str(canarytoken_LENGTH)
        + '}).*',
        re.IGNORECASE,
    )

    def __init__(self, value=None):
        """Create a new Canarytoken instance. If no value was provided,
        generate a new canarytoken.

        Arguments:
        value -- A user-provided canarytoken. It's format will be validated.

        Exceptions:
        NoCanarytokenFound - Thrown if the supplied canarytoken is not in the
                           correct format.
        """

        if value:
            self._value = self.find_canarytoken(value).lower()
        else:
            self._value = Canarytoken.generate()

    @staticmethod
    def generate():
        """Return a new canarytoken."""
        return ''.join(
            [
                canarytoken_ALPHABET[random.randint(0, len(canarytoken_ALPHABET) - 1)]
                for x in range(0, canarytoken_LENGTH)
            ],
        )

    @staticmethod
    def find_canarytoken(haystack: str):
        """Return the canarytoken found in haystack.

        Arguments:
        haystack -- A string that might include a canarytoken.

        Exceptions:
        NoCanarytokenFound
        """
        m = Canarytoken.CANARY_RE.match(haystack)
        if not m:
            raise NoCanarytokenFound(haystack)

        return m.group(1)

    def value(
        self,
    ):
        return self._value

    @staticmethod
    def look_for_source_data(query_name: str) -> Dict[str, str]:
        for soure_name, source_extractor in source_data_extractors.items():
            if (m := source_extractor.match(query_name)) is not None:
                return getattr(Canarytoken, f'_{soure_name}')(m)
        else:
            return {}

    @staticmethod
    def _sql_server_data(matches: Match[AnyStr]):
        username = matches.group(1)
        data = {}
        # TODO: decoded base64 can contain all sorts of character
        # we need to sanitise this as it's user input!!!
        data['sql_username'] = base64.b64decode(
            username.replace('.', '').replace('-', '='),
        )
        return data

    @staticmethod
    def _mysql_data(matches: Match[AnyStr]):
        username = matches.group(1)
        data = {}
        # TODO: decoded base64 can contain all sorts of character
        # we need to sanitise this as it's user input!!!
        data['mysql_username'] = base64.b32decode(
            username.replace('.', '').replace('-', '=').upper(),
        )
        return data

    @staticmethod
    def _linux_inotify_data(matches: Match[AnyStr]) -> Dict[str, str]:
        data = {}
        filename = matches.group(1)
        filename = filename.replace('.', '').upper()
        # this channel doesn't have padding, add if needed
        filename += '=' * int((math.ceil(float(len(filename)) / 8) * 8 - len(filename)))
        data['linux_inotify_filename_access'] = base64.b32decode(filename)
        return data

    @staticmethod
    def _generic(matches: Match[AnyStr]) -> Dict[str, str]:
        data = {}
        generic_data = matches.group(1)
        generic_data = generic_data.replace('.', '').upper()
        # this channel doesn't have padding, add if needed
        # TODO: put this padding logic into utils somewhere.
        generic_data += '=' * int(
            (math.ceil(float(len(generic_data)) / 8) * 8 - len(generic_data)),
        )
        try:
            # TODO: this can smuggle in all sorts of data we need to sanitise
            #
            data['generic_data'] = base64.b32decode(generic_data)
        except TypeError:
            data['generic_data'] = 'Unrecoverable data: {}'.format(generic_data)
        return data

    @staticmethod
    def _dtrace_process_data(matches: Match[AnyStr]) -> Dict[str, str]:
        raise NotImplementedError('Please implement me! ')
        # data = {}
        # try:
        #     data['dtrace_uid'] = base64.b64decode(uid)
        # except:
        #     log.error(
        #         'Could not retrieve uid from dtrace '
        #         + 'process alert: {uid}'.format(uid=uid),
        #     )
        # try:
        #     data['dtrace_hostname'] = base64.b64decode(hostname.replace('.', ''))
        # except:
        #     log.error(
        #         'Could not retrieve hostname from dtrace '
        #         + 'process alert: {hostname}'.format(hostname=hostname),
        #     )
        # try:
        #     data['dtrace_command'] = base64.b64decode(command.replace('.', ''))
        # except:
        #     log.error(
        #         'Could not retrieve command from dtrace '
        #         + 'process alert: {command}'.format(command=command),
        #     )

        # return data

    @staticmethod
    def _dtrace_file_open(matches: Match[AnyStr]) -> Dict[str, str]:
        raise NotImplementedError('Please implement me')
        # data = {}
        # try:
        #     data['dtrace_uid'] = base64.b64decode(uid)
        # except:
        #     log.error(
        #         'Could not retrieve uid from dtrace '
        #         + 'file open alert: {uid}'.format(uid=uid),
        #     )

        # try:
        #     data['dtrace_hostname'] = base64.b64decode(hostname.replace('.', ''))
        # except:
        #     log.error(
        #         'Could not retrieve hostname from dtrace '
        #         + 'process alert: {hostname}'.format(hostname=hostname),
        #     )
        # try:
        #     data['dtrace_filename'] = base64.b64decode(filename.replace('.', ''))
        # except:
        #     log.error(
        #         'Could not retrieve filename from dtrace '
        #         + 'file open alert: {filename}'.format(filename=filename),
        #     )

        # return data

    @staticmethod
    def _desktop_ini_browsing(matches: Match[AnyStr]) -> Dict[str, str]:
        data = {}
        username = matches.group(1)
        hostname = matches.group(2)
        domain = (matches.group(3),)

        data['windows_desktopini_access_username'] = username
        data['windows_desktopini_access_hostname'] = hostname
        data['windows_desktopini_access_domain'] = domain
        return data

    @staticmethod
    def _log4_shell(matches: Match[AnyStr]) -> Dict[str, str]:
        data = {}
        computer_name = matches.group(1)
        if len(computer_name) <= 1:
            computer_name = 'Not Obtained'
        else:
            computer_name = computer_name[1:]
        data['log4_shell_computer_name'] = computer_name
        return data


# if __name__ == '__main__':
#     print((Canarytoken()))
#     token = Canarytoken().value()
#     print(token)
#     print((Canarytoken(value=token)))

#     bad_tokens = []
#     # short value
#     bad_tokens.append(token[:1])

#     # invalid char token
#     bad_tokens.append('!' + token[1:])

#     for t in bad_tokens:
#         try:
#             print((Canarytoken(value=t)))
#             assert False
#         except NoCanarytokenFound:
#             print(('Invalid token %s detected' % t))
