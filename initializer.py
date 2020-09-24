from os import path, mkdir, environ, urandom
from sys import argv
from base64 import b64encode
from mics.certmaker import create_dummy_certificate

if __name__ == '__main__':
    if len(argv) == 2:
        if argv[1] == "--local" or argv[1] == "--docker":
            environ["analyzer_env"] = argv[1][1:]
            certsdir = path.abspath(path.join(path.dirname( __file__ ), 'certs'))
            if not certsdir.endswith(path.sep): certsdir = certsdir+path.sep
            if not path.isdir(certsdir): mkdir(certsdir)
            create_dummy_certificate('cert.pem', 'key.pem', certsdir, False)
        elif argv[1] == "--key":
            with open("key.hex", "w") as f:
                f.write(b64encode(urandom(128)).decode('utf-8'))
