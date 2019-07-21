# encoding: utf-8
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from OpenSSL import crypto
from pem import parse_file


class CitizenCard:
    """
    - Deciphering using the Private Key of the Portuguese Citizen Card is not currently supported, the code
    to be used: https://github.com/danni/python-pkcs11/blob/master/docs/opensc.rst

    """

    def __init__(self):
        pass

    def verify(self, message, sign_bytes, x509_pem):
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

    def validate_chain(self, chain, pem_certificate, ssl_ca_root_file="./utils/mozilla-ca-bundle.txt"):
        # parse CA roots certificate PEMs to an list
        trusted_certs_pems = parse_file(ssl_ca_root_file)

        # create a new store
        store = crypto.X509Store()

        # check middle CAs for revocation
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK)

        # check just the certificate CRL and not if all certificates up to the root are revoked
        # not recommended since requires all CAs root revogations
        store.set_flags(crypto.X509StoreFlags.CRL_CHECK_ALL)

        # add system trusted CA roots to store
        for pem_crt in trusted_certs_pems:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, pem_crt.as_bytes()))

        # load supplied chain
        for pem_crt in chain:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, pem_crt))

        # convert pem to OpenSSL certificate format
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_certificate)

        # validate full chain
        store_ctx = crypto.X509StoreContext(store, certificate)

        # load CRLs to the store
        for crl in [f for f in os.listdir("utils/crls") if os.path.isfile(os.path.join("utils/crls", f))]:
            store.add_crl(crypto.load_crl(crypto.FILETYPE_PEM, open(os.path.join("utils/crls", crl), "r").read()))

        store_ctx.verify_certificate()
