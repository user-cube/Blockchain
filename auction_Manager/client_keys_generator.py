from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

class Keys:
    def keyGenerator(uuid):
        """
        Function that generates private and public keys to Auction Manager.
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

        private_file = '/utils/keys/'+str(uuid)+'private_key.pem'
        f = open(private_file, 'wb')
        f.write(pem)
        f.close()

        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_file = '/utils/keys/'+str(uuid)+'/public_key.pem'
        f = open(public_file, 'wb')
        f.write(pem)
        f.close()

    def encrypt(text,uuid):
        fd = open('/utils/keys/'+str(uuid)+'private_key.pem', "rb")
        private_key = fd.read()
        fd.close()
        encryptor = PKCS1_OAEP.new(private_key)
        encrypted_msg = encryptor.encrypt(text)
        encoded_encrypted_msg = base64.b64encode(encrypted_msg)
        return encoded_encrypted_msg

    def decrypt(text,uuid):
        fd = open('/utils/keys/'+str(uuid)+'public_key.pem', "rb")
        public_key = fd.read()
        fd.close()
        encryptor = PKCS1_OAEP.new(public_key)
        decoded_encrypted_msg = base64.b64decode(text)
        decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
        return decoded_decrypted_msg