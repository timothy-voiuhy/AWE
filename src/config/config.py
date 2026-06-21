import sys
import os

HOME_DIR  = os.path.expanduser("~")

# Project root: two levels up from this file (<root>/src/config/config.py)
RUNDIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) + os.sep

TELEGRAM_API_ID = ""
TELEGRAM_HASH = ""
TELEGRAM_PHONE_NUMBER = ""

if sys.platform == "linux":
    ROOT_CERT_FILE = HOME_DIR + "/AWE/proxycert/CA/rootCACert.pem"
    CERT_CACHE_DIR = HOME_DIR + "/AWE/proxycert/Certs/"
    CERT_KEYS_DIR = HOME_DIR + "/AWE/proxycert/Keys/"
    HOST_CERTS_DIR = HOME_DIR + "/AWE/proxycert/HOST_CERTS"
    PRIVATE_KEY_FILE = HOME_DIR + "/AWE/proxycert/CA/privatekey.pem"
    CERTIFICATE_FILE = HOME_DIR + "/AWE/proxycert/CA/awe_cert.crt"
    DEFAULT_WORKSPACE_DIR = HOME_DIR + "/AWE/AtomProjects/"
    WAPPALZER_RUN_DIR = HOME_DIR + "/AWE/Wappalzer/"
if sys.platform == "win32":
    CERT_CACHE_DIR = HOME_DIR + "\\AWE\\proxycert\\Certs\\"
    ROOT_CERT_FILE = HOME_DIR + "\\AWE\\proxycert\\CA\\rootCACert.pem"
    PRIVATE_KEY_FILE = HOME_DIR + "\\AWE\\proxycert\\CA\\privatekey.pem"
    DEFAULT_WORKSPACE_DIR = os.path.join(HOME_DIR, "AWE\\AtomProjects\\")
    WAPPALZER_RUN_DIR = HOME_DIR + "\\AWE\\Wappalzer\\"
    CERTIFICATE_FILE = HOME_DIR + "\\AWE\\proxycert\\CA\\awe_cert.crt"
    CERT_KEYS_DIR = HOME_DIR + "\\AWE\\proxycert\\Keys\\"
    HOST_CERTS_DIR = HOME_DIR + "\\AWE\\proxycert\\HOST_CERTS"

if sys.platform == "linux":
    PROXY_DUMP_DIR =  HOME_DIR + "/AWE/AtomProjects/Proxy/"
elif sys.platform == "win32":
    PROXY_DUMP_DIR = HOME_DIR+"\\AWE\\AtomProjects\\Proxy"
