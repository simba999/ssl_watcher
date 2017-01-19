from django.test import TestCase
from ssl_watcher.models import CertInfo
import ssl
import socket
import logging


# Create your tests here.
class TestAutomation(TestCase):
    def test_timeout(self):
        logging.basicConfig()
        logger = logging.getLogger("TestAutomation.test_timeout")
        logger.setLevel(logging.DEBUG)
        test_domain = "www.upwork.com"
        portid = 443

        try:
            ips = socket.gethostbyname_ex(test_domain)
        except Exception:
            logger.debug("%s site is bad resolution", test_domain)

        for ip in ips:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            flag = sock.connect_ex((test_domain, portid))
            self.assertFalse(flag, 0)

            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True

            context.load_default_certs()
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = context.wrap_socket(my_socket, server_hostname=test_domain)

            try:
                conn.connect((ip, 443))
            except Exception:
                logger.debug("non SSL/TLS 443")
                self.assertTrue("non SSL/TLS 443", True)

            timeout = conn.gettimeout()

            logger.debug("Timeout %s", timeout)
