#server cipher connection client-manager

from diffiehellman.diffiehellman import DiffieHellman
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pickle
import os
import base64
from server_cc import CitizenCard
from hashlib import sha256
import json


SERVER_PUB_KEY = os.path.dirname(os.path.abspath(__file__)) + "/utils/server_public_key.pem"
SERVER_PRIV_KEY = os.path.dirname(os.path.abspath(__file__)) + "/utils/server_private_key.pem"
RANDOM_ENTROPY_GENERATOR_SIZE = 32


class ServerCipher:

    def __init__(self):
        # load server pub. key
        self.server_pub_key = serialization.load_pem_public_key(open(SERVER_PUB_KEY, "rb").read(),
                                                                backend=default_backend())
        # load server priv. key
        self.server_priv_key = serialization.load_pem_private_key(open(SERVER_PRIV_KEY, "rb").read(),
                                                                  password=None,
                                                                  backend=default_backend())
        # Diffie Hellman
        self.server_dh = None
        
        # session key
        self.session_key = None

        # client public key
        self.client_public_key = None

        # number of requests received
        self.requests_received = 1

        # load cc libraries
        self.cc = CitizenCard()

        # mode CTR, CFB, OFB
        self.mode = None

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
        if not isinstance(key, bytes):
            key = key.encode()

        if not isinstance(data, bytes):
            data = pickle.dumps(data)

        h = hmac.HMAC(key, self.hmac_hash(), backend=default_backend())
        h.update(data)
        return h.finalize()

    """
    HMAC - verify
    """
    def hmac_verify(self, key, hmac_data, data):
        if not isinstance(key, bytes):
            key = key.encode()

        if not isinstance(data, bytes):
            data = pickle.dumps(data)

        h = hmac.HMAC(key, self.hmac_hash(), backend=default_backend())
        h.update(data)
        return h.verify(hmac_data)

    """
    SECURE LAYER ENCAPSULATION
    """
    def secure_layer_encrypt(self, msg: bytes, sec_data: dict):
        # the nounce has been already generated by the client
        # the iterations number will be the number of requests received by the server for that client
        # the number that counts is the decrypt number
        key, salt = self.key_derivation(masterkey=self.session_key, salt=sec_data["salt"],
                                        iterations=sec_data["iterations"])

        # HMAC
        hmac_key = sha256(key).hexdigest()
        hmac_data = self.hmac_update_finalize(hmac_key, msg)

        pickle_dumps = pickle.dumps([msg, hmac_data])

        iv, ciphered_msg = self.sym_cipher(pickle_dumps, ks=key, mode=self.mode)

        sec_data = pickle.dumps({
            "nounce": sec_data["nounce"],
            "seq": sec_data["seq"],
            "iv": iv
        })

        # sec_data ciphered
        sec_data_ciphered = self.hybrid_cipher(sec_data, self.client_public_key)

        return_message = {
            "data": base64.b64encode(ciphered_msg).decode(),
            "sec_data": base64.b64encode(sec_data_ciphered).decode()
        }

        # dump the return message
        pickle_dumps = pickle.dumps(return_message)

        return base64.b64encode(pickle_dumps)

    def secure_layer_decrypt(self, msg: bytes):
        msg = pickle.loads(base64.b64decode(msg))

        data = msg["data"].encode()
        sec_data = base64.b64decode(msg["sec_data"])

        iterations = self.requests_received
        self.requests_received += 1

        # decipher the sec_data
        sec_data = pickle.loads(self.hybrid_decipher(sec_data, self.server_priv_key))

        salt = sec_data["salt"]
        nounce = sec_data["nounce"]
        iv = sec_data["iv"]

        key, salt = self.key_derivation(self.session_key, iterations=iterations, salt=salt)

        raw_msg = pickle.loads(self.sym_decipher(base64.b64decode(data), key, iv, self.mode))

        # verify hmac
        hmac_key = sha256(key).hexdigest()
        self.hmac_verify(hmac_key, raw_msg[1], raw_msg[0])

        data = {"nounce": nounce,
                "salt": salt,
                "iterations": iterations,
                "seq": sec_data["seq"]+1}

        return raw_msg[0], data

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
        generated values. After the cipher, the server will sign with the server private key the data ciphered.

        Phase 3: [CLIENT]: using the stored server public key the client will validate the signature received. After
        that using the client private key, the client will decipher the DH public value received from the server. Then
        using the DH public value, the client will generate the DH shared secret and using PBKDF2HMAC will use a key
        derivation function. The master key will be the secret DH shared value and will have 100 000 iterations. The
        salt is random and so, it will be ciphered and sent to the server.
        The session key has been generated.

        Phase 4: [SERVER]: Using the client public key it will be verified the signature of the received value. Using
        the server private key and a hybrid cipher the PBKDF2 salt will be deciphered. Using the key derivation
        function the session key will be retrieved in the server.

        Then, there is a secure channel between the server and the client.


        :param phase: negotiation phase
        :param val: value sent by the client
        :return: value to send to the client
        """
        if phase == 2:
            # server generate DH private and public key, 1024 para cima ou curva elipticas
            self.server_dh = DiffieHellman(key_length=256)
            self.server_dh.generate_public_key()

            # get mode
            if val["mode"] == "CTR":
                self.mode = modes.CTR
            elif val["mode"] == "CFB":
                self.mode = modes.CFB
            elif val["mode"] == "OFB":
                self.mode = modes.OFB
            else:
                print("Wrong input!")
                exit(1)

            if val["hmac_hash"] == "sha256":
                self.hmac_hash = hashes.SHA256
            elif val["hmac_hash"] == "sha512":
                self.hmac_hash = hashes.SHA512
    
            # decipher the received DH value
            client_dh_pub = self.hybrid_decipher(val["data"], self.server_priv_key)

            # decipher client public key PEM format
            client_public_key_pem = self.hybrid_decipher(val["public_key"], self.server_priv_key)
    
            # load the client public key
            self.client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
    
            # validate signed data [data = dh value]
            self.asym_validate_sign(val["data"].encode(),
                                    base64.b64decode(val["data_signature"].encode()),
                                    self.client_public_key)
    
            # validate signature of client public key
            self.asym_validate_sign(val["public_key"].encode(),
                                    base64.b64decode(val["public_key_signature"].encode()),
                                    self.client_public_key)
    
            # cipher the server DH public key with the client public key
            server_dh_ciphered = self.hybrid_cipher(self.server_dh.public_key, self.client_public_key)

            # generate the DH shared secret (client session key)
            self.server_dh.generate_shared_secret(client_dh_pub)

            return {
                    "data": server_dh_ciphered.decode(),
                    "data_signature": base64.b64encode(self.asym_sign(self.server_priv_key,
                                                                      server_dh_ciphered)).decode(),
                    "phase": 3
                }
        elif phase == 4:
            # validate signature of the received salt
            self.asym_validate_sign(val["data"].encode(),
                                    base64.b64decode(val["data_signature"].encode()),
                                    self.client_public_key)

            # decipher the salt for PBKDF2
            pbkdf2_salt = self.hybrid_decipher(val["data"], self.server_priv_key)

            # save the session key
            self.session_key, salt = self.key_derivation(str(self.server_dh.shared_secret).encode(), pbkdf2_salt)
