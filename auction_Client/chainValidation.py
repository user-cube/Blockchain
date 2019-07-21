from PyKCS11 import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (padding, rsa, utils)

def verifyChain():
    verified = False
    lib = '/usr/local/lib/libpteidpkcs11.so'
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(lib)
    slots = pkcs11.getSlotList()
    classes = {
        CKO_PRIVATE_KEY : 'private key',
        CKO_PUBLIC_KEY : 'public key',
        CKO_CERTIFICATE : 'certificate'
    }
    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
            session = pkcs11.openSession( slot )
            objects = session.findObjects()
            for obj in objects:
                l = session.getAttributeValue( obj, [CKA_LABEL] )[0]
                c = session.getAttributeValue( obj, [CKA_CLASS] )[0]
                print( 'Object with label ' + l + ', of class ' + classes[c] )

    for slot in slots:
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo( slot ).label:
            data = bytes('data to be signed', 'utf-8')
            session = pkcs11.openSession( slot )
            privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            signature = bytes(session.sign( privKey, data, Mechanism(CKM_SHA1_RSA_PKCS) ))
            session.closeSession
            session = pkcs11.openSession(slot)
            pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
            pubKeyDer = session.getAttributeValue( pubKeyHandle, [CKA_VALUE], True )[0]
            session.closeSession
            pubKey = load_der_public_key( bytes(pubKeyDer), default_backend() )
            try :
                pubKey.verify( signature, data, padding.PKCS1v15(), hashes.SHA1() )
                verified = True
                print( 'Verification succeeded' )
            except:
                print( 'Verification failed' )
    
    return verified