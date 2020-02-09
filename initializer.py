from mics.certmaker import create_dummy_certificate
from os import path, mkdir, environ
from sys import argv

if __name__ == '__main__':
    if len(argv) == 2:
        if argv[1] == "--local" or argv[1] == "--docker":
            environ["analyzer_env"] = argv[1][1:]
            certsdir = path.abspath(path.join(path.dirname( __file__ ),'certs'))
            if not certsdir.endswith(path.sep): certsdir = certsdir+path.sep
            if not path.isdir(certsdir): mkdir(certsdir)
            create_dummy_certificate('cert.pem', 'key.pem',certsdir,False)
    else:
        exit()
else:
    exit()