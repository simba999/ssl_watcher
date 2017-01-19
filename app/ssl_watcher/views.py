# Create your views here.
from django.conf.urls import url
# from django.contrib import request
from urllib.parse import urlparse
from django.http import request
from django.shortcuts import render
import socket
import logging
import logging.config
from django.views.generic import View
from pprint import pformat
from django.http import HttpResponse
import ssl
import pprint
from django.http import HttpResponseRedirect
from django.shortcuts import render
from ssl_watcher.forms import UploadFileForm
from ssl_watcher.models import CertInfo
from django.utils import timezone
from datetime import datetime
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Count
from dateutil import parser
from datetime import date
from app import settings

# global variable for a list of domain
url_list = []

# logging configaration

logging.basicConfig()
logger = logging.getLogger(__name__)
hdlr = logging.FileHandler('myapp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,  # this fixes the problem
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default'],
            'level': 'INFO',
            'propagate': True
        }
    }
})


def get_ips(d):
    """
    This method returns the first IP address string
    that responds as the given domain name
    """
    try:
        data = socket.gethostbyname_ex(d)
        return data[2]
    except Exception:
        # fail gracefully!
        logger.info("The site %s is bad resolution", d)
        # raise Exception("The site " + d + " is bad resolution")


def get_certificate(url_list):
    """
    This function retrieve  certificates data
    :param url_list: domain
    :return: now null, but html mockup future
    """
    i = 0
    ctx_list = []
    cert_list = []

    while i < len(url_list):
        # log end
        parsed_uri = urlparse(url_list[i].decode('utf-8'))
        domain = '{uri.netloc}'.format(uri=parsed_uri)
        ips = get_ips(domain)
        portid = 443

        if ips is not None:
            for ip in ips:
                logger.info("The %s resolves %s ip", domain, ip)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                flag = sock.connect_ex((ip, portid))

                if flag == 0:
                    logger.info("connected")

                    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.check_hostname = True
                    context.load_default_certs()

                    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    conn = context.wrap_socket(my_socket, server_hostname=domain)
                    conn.connect((domain, 443))

                    logger.info("The Timeout is %s", conn.gettimeout())
                    cert = conn.getpeercert()

                    cert['domain'] = domain
                    cert['ip'] = ip

                    # match_hostname
                    try:
                        ssl.get_server_certificate((ip, 443), ssl_version=ssl.PROTOCOL_SSLv23)
                    except Exception:
                        logger.info("unmatched certificate")

                    ctx = dict(
                        domain=domain,
                        ip=ip
                    )
                    cert_list.append(cert)
                    ctx_list.append(ctx)

                else:
                    logger.error("The %s doesn't listen on port %s", domain, portid)

        i += 1

    save_cert(cert_list)

    return HttpResponse(pformat(ctx_list), content_type="text/plain")


def check_port(siteurl, portid):
    """
    This function checks if ip listens on specific port
    :param siteurl: IP of the domain
    :param portid: port number 443
    :return: null
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    flag = sock.connect_ex((siteurl, portid))

    if flag == 0:
        logger.info("Port 443 is open")

    else:
        logger.info("Port 443 is not open")


def upload_file(request):
    url_list.clear()

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_file(request.FILES['file'])
            get_certificate(url_list)
    else:
        form = UploadFileForm()
    return render(request, 'upload.html', {'form': form})


def handle_uploaded_file(f):
    """
    This function reads the data from text.file
    :param f: file
    :return:
    """
    with open('media/documents/urllist.txt', 'wb+') as destination:
        for chunk in f.readlines():
            url_list.append(chunk)
            destination.write(chunk)


def save_cert(cert_list):
    """
    This function save certificates information into model
    :param cert_list: a list of dict that includes the certificates infomation
    :return: null
    """
    for cert in cert_list:
        data = dict()

        data['OCSP'] = cert['OCSP'][0]
        data['caIssuers'] = cert['caIssuers'][0]
        data['crlDistributionPoints'] = cert['crlDistributionPoints'][0]

        for item in cert['issuer']:
            dic = dict(item)
            for key in dic:
                new_key = "issuer_" + key
                data[new_key] = dic[key]

        data['serialNumber'] = cert['serialNumber']
        data['notAfter'] = cert['notAfter']
        data['notBefore'] = cert['notBefore']

        for item in cert['subject']:
            dic = dict(item)
            for key in dic:
                new_key = "subject_" + key
                data[new_key] = dic[key]
                print("new_key: ", new_key)
                print("key: ", key)
                print("dict: ", dic[key])

        data['version'] = cert['version']
        data['domain'] = cert['domain']
        data['ip'] = cert['ip']

        alt_name_list = []

        for item in cert['subjectAltName']:
            alt_name_list.append(item[1])

        subjectAltName = ','.join(i for i in alt_name_list)

        certinfo = CertInfo()

        certinfo.OCSP = data.get('OCSP', '')
        certinfo.caIssuers = data.get('caIssuers', '')
        certinfo.crlDistributionPoints = data.get('crlDistributionPoints', '')
        certinfo.issuer_countryName = data.get('issuer_countryName', '')
        certinfo.issuer_organizationName = data.get('issuer_organizationName', '')
        certinfo.issuer_organizationalUnitName = data.get('issuer_organizationalUnitName', '')
        certinfo.issuer_commonName = data.get('issuer_commonName', '')

        notAfter = data.get('notAfter', '')

        if notAfter is not '':
            certinfo.notAfter = parser.parse(notAfter)

        notBefore = data.get('notBefore', '')

        if notBefore is not '':
            certinfo.notBefore = parser.parse(notBefore)

        expiry_date = parser.parse(notAfter).date()

        if expiry_date is not '':
            certinfo.expiry_date = expiry_date

        certinfo.serialNumber = data.get('serialNumber', '')
        certinfo.subject_businessCategory = data.get('subject_businessCategory', '')
        certinfo.subject_serialNumber = data.get('subject_serialNumber', '')
        certinfo.subject_streetAddress = data.get('subject_streetAddress', '')
        certinfo.subject_postalCode = data.get('subject_postalCode', '')
        certinfo.subject_countryName = data.get('subject_countryName', '')
        certinfo.subject_stateOrProvinceName = data.get('subject_stateOrProvinceName', '')
        certinfo.subject_localityName = data.get('subject_localityName', '')
        certinfo.subject_organizationName = data.get('subject_organizationName', '')
        certinfo.subject_commonName = data.get('subject_commonName', '')
        certinfo.version = data.get('version', '')
        certinfo.subjectAltName = subjectAltName if 'subjectAltName' in locals() else ''
        certinfo.domain = data.get('domain', '')
        certinfo.ip = data.get('ip', '')

        certinfo.save()


def show_info(request):
    """
    show the certificates information
    :param request:
    :return:
    """
    page = request.GET.get('page', 1)
    certinfos = CertInfo.objects.all().values()

    min_date = '1980-01-01'
    max_date = '2030-12-30'
    histogram_expiry_date = CertInfo.objects.values('expiry_date').filter(expiry_date__gte=min_date).order_by('expiry_date').annotate(count=Count('expiry_date'))

    return render(request, 'show_info.html', locals())
