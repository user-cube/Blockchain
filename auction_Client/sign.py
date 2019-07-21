from PyKCS11 import *

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as padd


lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

def login():
    """
    Function that allows users to login

    Returns
    -----
    string - 
            "Unable to login" - If user cancel the operation or fails the pin.
            "Verification succeeded" - If it's an valid user otherwise returns "Verification failed".
            "Citizien Card Not Present" - If token isn't present.
    """
    lib = '/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
            data = bytes('userLogin', 'utf-8')

            session = pkcs11.openSession( slot )
            privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

            try:
                signature = bytes(session.sign( privKey, data, Mechanism(CKM_SHA1_RSA_PKCS) ))#Faz display do plugin de autenticação do gov.
            except:
                return "Unable to login"
            session.closeSession

            session = pkcs11.openSession(slot)
            pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            print(pubKeyHandle)
            pubKeyDer = session.getAttributeValue( pubKeyHandle, [CKA_VALUE], True )[0]
            pubKey = load_der_public_key( bytes(pubKeyDer), default_backend() )
            
            teste = pubKey.encrypt(data, padd.OAEP(
                mgf= padd.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            ))

            

            try:
                pubKey.verify( signature, data, padding.PKCS1v15(), hashes.SHA1() )
                return "Verification succeeded"
            except:
                return "Verification failed"

print(login())