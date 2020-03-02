__G__ = "(G)bd249ce4"

from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import PKey, TYPE_RSA, X509, X509Extension, dump_certificate, dump_privatekey
from uuid import uuid4
from os import path,remove

def create_dummy_certificate(certname,keyname,_dir, force=False) -> bool:
    if certname and keyname and _dir:
        if path.exists(_dir+keyname) and path.exists(_dir+certname) and not force:
            return True
        else:
            if path.exists(_dir+certname):
                remove(_dir+certname)
            if path.exists(_dir+keyname):
                remove(_dir+keyname)

        key = PKey()
        key.generate_key(TYPE_RSA, 4096)
        cert = X509()
        cert.set_serial_number(uuid4().int)
        cert.set_version(2)
        cert.get_subject().C = "US"
        cert.get_subject().ST = "WA"
        cert.get_subject().L = "127.0.0.1"
        cert.get_subject().O = "github.com/qeeqbox/analyzer"
        cert.get_subject().OU = "github.com/qeeqbox/analyzer"
        cert.get_subject().CN = "auto generated self signed certificate by qeeqbox/analyzer"
        cert.gmtime_adj_notBefore(-60 * 60 * 24 * 365 * 2)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 2)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
                             X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
                             X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),])
        cert.sign(key, 'sha256')
        with open(_dir+certname, 'wb') as f:
            f.write(dump_certificate(FILETYPE_PEM, cert))
        with open(_dir+keyname, 'wb') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
        return True
    return False