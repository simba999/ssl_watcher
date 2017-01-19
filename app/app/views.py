# from django.conf.urls import url
# # from django.contrib import request
# from urllib.parse import urlparse
# from django.http import request
# from django.shortcuts import render
# import socket
# import logging
# import logging.config
# from django.views.generic import View
# from pprint import pformat
# from django.http import HttpResponse
# import ssl
# import pprint
# from django.http import HttpResponseRedirect
# from django.shortcuts import render
# from .forms import UploadFileForm

# url_list = []

# def getIP(d):
#     """
#     This method returns the first IP address string
#     that responds as the given domain name
#     """
#     try:
#         data = socket.gethostbyname(d)
#         ip = repr(data)
#         print ("dmon: ")
#         print (data)
#         return ip
#     except Exception:
#         # fail gracefully!
#         print ("EXCEption")
#         # logger.warn("gethostbyname is error")
#         return False

# def getDomain(View):
# 	"""
# 	This method returns the domain name of the url
# 	"""
# 	# log start
# 	logging.basicConfig()
# 	logger = logging.getLogger(__name__)
# 	logger.setLevel(logging.DEBUG)

# 	logging.config.dictConfig({
# 	    'version': 1,
# 	    'disable_existing_loggers': False,  # this fixes the problem
# 	    'formatters': {
# 	        'standard': {
# 	            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
# 	        },
# 	    },
# 	    'handlers': {
# 	        'default': {
# 	            'level':'INFO',
# 	            'class':'logging.StreamHandler',
# 	        },
# 	    },
# 	    'loggers': {
# 	        '': {
# 	            'handlers': ['default'],
# 	            'level': 'INFO',
# 	            'propagate': True
# 	        }
# 	    }
# 	})

# 	# log end
# 	parsed_uri = urlparse( 'http://spotify.com/questions/1234567/blah-blah-blah-blah' )
# 	# parsed_uri = urlparse( 'http://account.live.com/questions/1234567/blah-blah-blah-blah' )

# 	domain = '{uri.netloc}'.format(uri=parsed_uri)
# 	# ip = getIP(domain)
# 	logger.info(domain)
# 	data = socket.gethostbyname(domain)
# 	ip = repr(data)

# 	logger.info(ip)

# 	check_port(domain, 443)

# 	print ("IP is: ")
# 	print (ip)
# 	ctx = dict(
# 		domain=domain,
# 		ip=ip
# 		)
# 	return HttpResponse(pformat(ctx), content_type="text/plain")

# def check_port(siteurl, portid):
# 	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 	flag = sock.connect_ex((siteurl, portid))
# 	print ("PortId: ")
# 	print (portid)
# 	if flag == 0:
# 	   print ("Port is open")
# 	   context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
# 	   context.verify_mode = ssl.CERT_REQUIRED
# 	   context.check_hostname = True
# 	   context.load_default_certs()
# 	   # context.load_verify_locations("/etc/ssl/certs/ca-bundle.crt")
# 	   # context = ssl.create_default_context()
# 	   conn = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), 
# 	   	server_hostname=siteurl)
# 	   conn.connect((siteurl, portid))
# 	   cert = conn.getpeercert()
# 	   pprint.pprint(cert)
# 	else:
# 	   print ("Port is not open")

# def upload_file(request):
# 	pass

# # def index(request):
# # 	if request.method == 'POST':
# # 		if request.method == 'POST' and request.FILES['myfile']:
# # 			myfile = request.FILES['myfile']
# # 		    fs = FileSystemStorage()
# # 		    filename = fs.save(myfile.name, myfile)
# # 		    uploaded_file_url = fs.url(filename)
# # 		    return render(request, 'simple_upload.html', {
# # 		        'uploaded_file_url': uploaded_file_url
# # 		    })
# #     return render(request, 'simple_upload.html')

# def upload_file(request):
#     if request.method == 'POST':
#         form = UploadFileForm(request.POST, request.FILES)
#         if form.is_valid():
#             handle_uploaded_file(request.FILES['file'])
#             return HttpResponseRedirect('/success/')
#     else:
#         form = UploadFileForm()
#     return render(request, 'upload.html', {'form': form})

# def handle_uploaded_file(f):
#     with open('name.txt', 'wb+') as destination:
#         for chunk in f.read_line:
#         	url_lit = chunk
#         	print ("linne------")
#         	print (chunk)
#             destination.write(chunk)
	
