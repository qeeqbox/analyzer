from mics.certmaker import create_dummy_certificate
from os import path, mkdir

certsdir = path.abspath(path.join(path.dirname( __file__ ),'certs'))
if not certsdir.endswith(path.sep): certsdir = certsdir+path.sep
if not path.isdir(certsdir): mkdir(certsdir)
create_dummy_certificate('cert.pem', 'key.pem',certsdir,False)