import PyKCS11
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

def extractCert():
    """
    Function that extracts the certificate from user as PEM.

    Returns
    -----
    cert_pem - User certificate as PEM.
    """
    
    lib = '/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    backend = default_backend()
    cert_pem = None

    for slot in slots:
        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]
        session = pkcs11.openSession(slot)
        cert_der = ''

        for obj in session.findObjects():

            attr = session.getAttributeValue(obj, all_attr)
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            if attr['CKA_CERTIFICATE_TYPE'] is not None:
                cert_der = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), backend)
                cert_pem = cert_der.public_bytes(Encoding.PEM)
                break
    
    return cert_pem