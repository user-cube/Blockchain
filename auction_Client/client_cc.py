# encoding: utf-8
import os
import pkcs11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
import getpass
from OpenSSL import crypto
from pem import parse_file
import hashlib
from extract import extractCert
from assinar import sign_message
from chainValidation import verifyChain


class CitizenCard:
    """
    - Deciphering using the Private Key of the Portuguese Citizen Card is not currently supported, the code
    to be used: https://github.com/danni/python-pkcs11/blob/master/docs/opensc.rst

    """
    def __init__(self, pin=None):
        self.pin = pin

    def sign(self, data):
        return sign_message(data)

    def decrypt(self, data):
        with self.token.open(user_pin=self.pin) as session:
            priv = session.get_key(pkcs11.constants.ObjectClass.PRIVATE_KEY,
                                   pkcs11.KeyType.RSA, 'CITIZEN AUTHENTICATION KEY')

            return priv.decrypt(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

    def get_certificate_pem(self):
        return extractCert()

    def get_public_key(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
            return self.get_certificate(label).public_key()

    def get_public_key_pem(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
            return self.get_public_key(label).public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    def get_available_certs_labels(self):
        certs_labels = []

        with self.token.open(user_pin=self.pin) as session:
            # get public key certificates
            for cert in session.get_objects({pkcs11.constants.Attribute.CLASS:
                                             pkcs11.constants.ObjectClass.CERTIFICATE}):

                label = cert[pkcs11.constants.Attribute.LABEL]
                certs_labels.append(label)

        return certs_labels

    @staticmethod
    def verify(message, sign_bytes, x509_pem):
        cert = x509.load_pem_x509_certificate(x509_pem, default_backend())
        # Extract public key from certificate
        sign_cert_pk = cert.public_key()

        # Generate an verification context from the given public key and signature
        verifier = sign_cert_pk.verifier(
            sign_bytes,
            _aspaadding.PKCS1v15(),
            hashes.SHA256()
        )

        # Validates if the signature was performed using the given certificate and message
        verifier.update(message)
        return verifier.verify()

    def encrypt(self, message, x509_pem):
        cert = x509.load_pem_x509_certificate(x509_pem, default_backend())
        # Extract public key from certificate
        sign_cert_pk = cert.public_key()

        # encrypt message
        return sign_cert_pk.encrypt(message, _aspaadding.OAEP(
                                       mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None
                                    ))

    @staticmethod
    def validate_chain():
        return verifyChain()

    def generate_uuid(self):
        pem = self.get_certificate_pem()
        return hashlib.sha224(pem).hexdigest()

    def get_certificate_chain(self):
        return [self.get_certificate_pem(label=label).decode() for label in self.get_available_certs_labels()]

    def get_cc_name(self, label="CITIZEN AUTHENTICATION CERTIFICATE"):
        cert = None

        with self.token.open() as session:
            # get public key certificates
            for cert in session.get_objects({pkcs11.constants.Attribute.CLASS: pkcs11.constants.ObjectClass.CERTIFICATE,
                                             pkcs11.constants.Attribute.LABEL: label}):
                value = cert[pkcs11.constants.Attribute.VALUE]
                cert = x509.load_der_x509_certificate(value, default_backend())
                break

        if cert is None:
            return "Name could not be found!"

        certificate_pem = cert.public_bytes(Encoding.PEM)
        # load cert with x509
        cert = x509.load_pem_x509_certificate(certificate_pem, backend=default_backend())

        # get the subject attributes
        for attribute in cert.subject:
            if attribute._oid._name == "commonName":
                return attribute.value

        return "Name could not be found!"


if __name__ == '__main__':
    cc = CitizenCard()
    data = b'INPUT'
    signature = cc.sign(data)

    # x509 PEM CERTIFICATE
    x509_pem = cc.get_certificate_pem()
    cc.verify(data, signature, x509_pem)

    # encrypt data
    x509_pem = cc.get_certificate_pem()
    data_ciphered = cc.encrypt(data, x509_pem)

    # cc.decrypt(data_ciphered)
    cc.validate_chain(chain=cc.get_certificate_chain(), pem_certificate=x509_pem)

    print(cc.get_certificate_pem())
    print(cc.get_public_key_pem())
