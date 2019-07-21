from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def keyGenerator():
    """
    Function that generates private and public keys to Auction Repository.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_file = 'auction_Repository_private_key.pem'
    f = open(private_file, 'wb')
    f.write(pem)
    f.close()

    public_key = private_key.public_key()

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_file = 'auction_Repository_public_key.pem'
    f = open(public_file, 'wb')
    f.write(pem)
    f.close()

keyGenerator()