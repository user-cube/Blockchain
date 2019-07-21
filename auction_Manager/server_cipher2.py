#server cipher for connection manager-repository

from diffiehellman.diffiehellman import DiffieHellman
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hashlib import sha256
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import modes
import os
import pickle
import base64
import json
import random

REPOSITORY_PUB_KEY = os.path.dirname(os.path.abspath(__file__)) + "/repository_public_key.pem"
RANDOM_ENTROPY_GENERATOR_SIZE = 32


class ServerCipher2:

    def __init__(self, mode, hmac_hash_type):
        self.mode = mode
        self.hmac_hash_type = hmac_hash_type

        # store client app keys
        self.manager_app_keys = self.generate_keys()

        # load server pub. key
        self.repository_pub_key = serialization.load_pem_public_key(open(REPOSITORY_PUB_KEY, "rb").read(),
                                                                backend=default_backend())

        # Diffie Hellman
        self.manager_dh = None

        # save session key
        self.session_key = None

        # warrant nounces
        self.warrant_nounces = {}

        # how many requests were made to the server
        self.request_to_server = 1

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        return private_key, public_key

    """
    ASYMMETRIC CIPHER
    """

    def asym_cipher(self, pub_key, raw_data):
        pickle_dumps = pickle.dumps(raw_data)
        return pub_key.encrypt(pickle_dumps, _aspaadding.OAEP(
                                       mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
                                       algorithm=hashes.SHA256(),
                                       label=None
                                    )
                               )

    def asym_decipher(self, private_key, ciphered_data):
        data = private_key.decrypt(ciphered_data, _aspaadding.OAEP(
            mgf=_aspaadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return pickle.loads(data)

    def asym_sign(self, private_key, data):
        return private_key.sign(data, _aspaadding.PSS(
                             mgf=_aspaadding.MGF1(hashes.SHA256()),
                             salt_length=_aspaadding.PSS.MAX_LENGTH),
                         hashes.SHA256())

    def asym_validate_sign(self, data, sign_data, public_key):
        verifier = public_key.verifier(sign_data, _aspaadding.PSS(
                mgf=_aspaadding.MGF1(hashes.SHA256()),
                salt_length=_aspaadding.PSS.MAX_LENGTH),
            hashes.SHA256())

        verifier.update(data)
        return verifier.verify()

    """
    SYMMETRIC KEY CIPHER
    """

    def sym_cipher(self, obj, ks, iv=os.urandom(16), mode=None):
        """

        :param iv: key to cipher the object
        :param obj: object to be ciphered
        :param ks: key to cipher the object
        :param mode:
        """
        if mode is None:
            mode = modes.CTR

        cipher = Cipher(algorithms.AES(ks), mode(iv), backend=default_backend())

        # pickle makes the serialization of the object
        pickle_dumps = pickle.dumps([obj, os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE)])

        # encrypt obj dumped data
        encryptor = cipher.encryptor()
        ciphered_obj = encryptor.update(pickle_dumps) + encryptor.finalize()

        return iv, ciphered_obj

    def sym_decipher(self, obj, ks, iv, mode=None):
        """

        :param obj:
        :param ks:
        :param iv:
        :param mode:
        :return:
        """
        if mode is None:
            mode = modes.CTR

        cipher = Cipher(algorithms.AES(ks), mode(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        deciphered_data = decryptor.update(obj) + decryptor.finalize()
        data, random = pickle.loads(deciphered_data)
        return data

    """
    HYBRID A-SYMMETRIC KEY CIPHER
    """
    def hybrid_decipher(self, obj, private_key, ks=None):
        obj, random_pickle = pickle.loads(base64.b64decode(obj))

        # decipher using rsa private key
        if ks is None:
            ks = self.asym_decipher(private_key, base64.b64decode(obj["key"]))

        # decipher using rsa private key
        iv = self.asym_decipher(private_key, base64.b64decode(obj["iv"]))

        # decipher using symmetric AES CTR
        return self.sym_decipher(base64.b64decode(obj["obj"]), ks, iv)

    def hybrid_cipher(self, obj, public_key, ks=os.urandom(32), cipher_key=True):
        # cipher using symmetric cipher AES CTR
        # returns the ciphered obj with the IV

        iv, ciphered_obj = self.sym_cipher(obj, ks)

        # iv ciphered with the public key
        iv_encrypted = self.asym_cipher(public_key, iv)

        # key ciphered with the public_key
        if cipher_key:
            # send ks to the server
            key_encrypted = self.asym_cipher(public_key, ks)

            pickle_dumps = pickle.dumps([{"obj": base64.b64encode(ciphered_obj).decode(),
                                          "iv": base64.b64encode(iv_encrypted).decode(),
                                          "key": base64.b64encode(key_encrypted).decode()},
                                         os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE)])
            return base64.b64encode(pickle_dumps)
        else:
            pickle_dumps = pickle.dumps([{"obj": base64.b64encode(ciphered_obj).decode(),
                                         "iv": base64.b64encode(iv_encrypted).decode()},
                                         os.urandom(RANDOM_ENTROPY_GENERATOR_SIZE)])
            return base64.b64encode(pickle_dumps)

    """
    KEY DERIVATION FUNCTION GIVEN THE MASTER KEY
    """

    def key_derivation(self, masterkey, salt=os.urandom(32), iterations=100000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )

        return kdf.derive(masterkey), salt

    """
    HMAC - create
    """
    def hmac_update_finalize(self, key, data):
        if not isinstance(key, bytes) and isinstance(key, str):
            key = key.encode()

        if not isinstance(data, bytes):
            data = pickle.dumps(data)

        h = hmac.HMAC(key, self.hmac_hash_type(), backend=default_backend())
        h.update(data)
        return h.finalize()

    """
    HMAC - verify
    """
    def hmac_verify(self, key, hmac_data, data):
        if not isinstance(key, bytes) and isinstance(key, str):
            key = key.encode()

        if not isinstance(data, bytes):
            data = pickle.dumps(data)

        h = hmac.HMAC(key, self.hmac_hash_type(), backend=default_backend())
        h.update(data)
        return h.verify(hmac_data)

    """
    SECURE LAYER ENCAPSULATION
    """
    def secure_layer_encrypt(self, msg: bytes):
        # generate a nounce that will be a warrant of the message
        # the nounce will be stored with the respective session key iteration
        # after retrieved it will be deleted and then the message exchanged between
        # the server and the client will be never deciphered again
        nounce = sha256(json.dumps(msg).encode() + os.urandom(32)).hexdigest().encode()
        key, salt = self.key_derivation(self.session_key, iterations=self.request_to_server)
        iv = os.urandom(16)

        # saving the iterations and salt used for the given nounce
        self.warrant_nounces[nounce] = {"iterations": self.request_to_server,
                                        "salt": salt, "seq": self.request_to_server}

        # salt (the salt used to the KDF), nounce (the genuineness warrant), iv (used in the cipher)
        sec_data = pickle.dumps({
            "salt": salt,
            "nounce": nounce,
            "iv": iv,
            "seq":  self.request_to_server
        })

        # sec_data ciphered
        sec_data_ciphered = self.hybrid_cipher(sec_data,  self.repository_pub_key)

        # HMAC
        hmac_key = sha256(key).hexdigest()
        hmac_data = self.hmac_update_finalize(hmac_key, msg)

        msg = [msg, hmac_data]
        pickle_dumps = pickle.dumps(msg)

        # cipher with symmetric cipher the message content
        iv, ciphered_obj = self.sym_cipher(pickle_dumps, key, iv=iv, mode=self.mode)

        # message to be signed and sent to the server
        return_message = {
            "data": base64.b64encode(ciphered_obj).decode(),
            "sec_data": base64.b64encode(sec_data_ciphered).decode()
        }

        self.request_to_server += 1

        # dump the return message
        pickle_dumps = pickle.dumps(return_message)

        return base64.b64encode(pickle_dumps)

    def secure_layer_decrypt(self, msg: bytes):
        msg = pickle.loads(base64.b64decode(msg))

        # get sec_data content
        sec_data = pickle.loads(self.hybrid_decipher(base64.b64decode(msg["sec_data"]), self.manager_app_keys[0]))

        nounce = sec_data["nounce"]

        if nounce not in self.warrant_nounces:
            print("Something went wrong with the nounce in the secure layer decrypt.")
            exit(1)

        if sec_data["seq"] != (self.warrant_nounces[nounce]["seq"]+1):
            print("Received wrong sequence number by the server")
            exit(1)

        # the nounce warrant allow us to retrieve the iterations and the salt used to derive the key
        iterations = self.warrant_nounces[nounce]["iterations"]
        salt = self.warrant_nounces[nounce]["salt"]

        # now it can be deleted
        del self.warrant_nounces[nounce]

        key, salt = self.key_derivation(self.session_key, iterations=iterations, salt=salt)

        raw_msg = pickle.loads(self.sym_decipher(base64.b64decode(msg["data"]), ks=key, iv=sec_data["iv"], mode=self.mode))

        # verify hmac
        hmac_key = sha256(key).hexdigest()
        self.hmac_verify(hmac_key, raw_msg[1], raw_msg[0])

        return raw_msg[0]

    """
    CLIENT SERVER SESSION KEY NEGOTIATION
    """

    def negotiate_session_key(self, phase, val=None):
        """
        First the Application loads the server public key that is distributed into the client application.
        It's ok to publicly distribute the Public Key but it must be verified if the public key
        of the server is still the same. If not, it must be updated. Another way is to request the public key
        of the server and ask for the user fingerprint verification. {verification missing}

        After that, the client app generate DH values (private and public) to exchange with the server in order to
        get the shared secret session key.

        Phase 1: [CLIENT]: send generated DH public key to the server (signed) and the app client rsa public key (signed too).
        The sent values will be ciphered with a random key and signed.

        Phase 2: [SERVER]: the server generates the private and public DH pair. Then using the server private key, the
        server decipher the DH public received encrypted value. Using again the server private key, the server deciphers
        the client public key and loads it into memory.
        Then, using the client public key, validates the signature made for the DH public value and public key received.
        Using the received client public key, the server will make a hybrid cipher (AES and RSA) of the DH server
        generated public key. After the cipher, the server will sign with the server private key the data ciphered.

        Phase 3: [CLIENT]: using the stored server public key the client will validate the signature received. After
        that using the client private key, the client will decipher the DH public value received from the server. Then
        using the DH public value, the client will generate the DH shared secret and using PBKDF2HMAC will use a key
        derivation function. The master key will be the secret DH shared value and will have 100 000 iterations. The
        salt is random and so, it will be ciphered and sent to the server.
        The session key has been generated.

        Phase 4: [SERVER]: Using the client public key it will be verified the signature of the received value. Using
        the server private key and a hybrid cipher the PBKDF2 salt will be deciphered. Using the key derivation
        function the session key will be obtained in the server.

        Then, there is a secure channel between the server and the client.

        :param val: value sent by the server
        :param phase: 1, 2, 3 or 4
        :return: value to send to the server
        """
        if phase == 1:
            # client generate DH private and public key
            self.manager_dh = DiffieHellman(key_length=256)
            self.manager_dh.generate_public_key()

            # cipher DH public key with server pub. key
            # cipher the client DH public key
            manager_dh_ciphered = self.hybrid_cipher(self.manager_dh.public_key, self.repository_pub_key)

            # cipher the client public key

            pem = self.manager_app_keys[1].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            manager_public_key_ciphered = self.hybrid_cipher(pem, self.repository_pub_key)

            return {
                "data": manager_dh_ciphered.decode(),
                "data_signature": base64.b64encode(self.asym_sign(self.manager_app_keys[0],
                                                                  manager_dh_ciphered)).decode(),
                "public_key": manager_public_key_ciphered.decode(),
                "public_key_signature": base64.b64encode(self.asym_sign(self.manager_app_keys[0],
                                                                        manager_public_key_ciphered)).decode(),
                "phase": 2,
                "cipher": "AES&RSA",
                "mode": self.mode.name,
                "hmac_hash": self.hmac_hash_type.name
            }
        elif phase == 3:
            # validate the DH received value
            self.asym_validate_sign(val["data"].encode(),
                                    base64.b64decode(val["data_signature"].encode()),
                                    self.repository_pub_key)

            # decipher the received DH value
            repository_dh_pub = self.hybrid_decipher(val["data"], self.manager_app_keys[0])

            # generate shared secret (client session key)
            self.manager_dh.generate_shared_secret(repository_dh_pub)

            # save the session key
            self.session_key, salt = self.key_derivation(str(self.manager_dh.shared_secret).encode())

            salt_ciphered = self.hybrid_cipher(salt, self.repository_pub_key)

            return {
                "phase": 4,
                "data": salt_ciphered.decode(),
                "data_signature": base64.b64encode(self.asym_sign(self.manager_app_keys[0],
                                                                  salt_ciphered)).decode()
            }
