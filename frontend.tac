import sys, os
import logging
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from twisted.names import server
from twisted.application import service, internet

from httpd_site import CanarytokensHttpd, GeneratorPage
from switchboard import Switchboard

import setup_db
from twisted.web.server import GzipEncoderFactory

from twisted.logger import ILogObserver, textFileLogObserver
from twisted.python import logfile
import settings
from twisted.web.server import GzipEncoderFactory, Site
import twisted.web.resource
from twisted.web.util import Redirect
from twisted.web.resource import (
    EncodingResourceWrapper, ForbiddenResource,
    NoResource, Resource,
)
logging.basicConfig()
logger = logging.getLogger('generator_httpd')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger.debug('Canarydrops generator HTTPd')

# application = service.Application("Canarydrops Generator Web Server")
# f = logfile.LogFile.fromFullPath(settings.LOG_FILE, rotateLength=settings.FRONTEND_LOG_SIZE,
#                                  maxRotatedFiles=settings.FRONTEND_LOG_COUNT)
# application.setComponent(ILogObserver, textFileLogObserver(f))

root = Resource()
# root.putChild("", Redirect("generate"))
root.putChild(b'generate', GeneratorPage())
# root.putChild("manage", ManagePage())
# root.putChild("download", DownloadPage())
# root.putChild("settings", SettingsPage())
# root.putChild("history", HistoryPage())
# root.putChild("resources", LimitedFile("/workspace/templates/static"))
from twisted.application import service, strports
# with open("/workspace/templates/robots.txt", "r") as f:
#     root.putChild("robots.txt", Data(f.read(), "text/plain"))

wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
site = Site(wrapped)
# service = internet.TCPServer(8080, site)

application = service.Application('Twisted.web.wsgi Hello World Example')
server = strports.service('tcp:8080', site)
server.setServiceParent(application)

# canarytokens_httpd = CanarytokensHttpd(port=80)
# service.setServiceParent(application)
