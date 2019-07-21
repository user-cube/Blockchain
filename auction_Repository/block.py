from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

from Crypto.Cipher import AES
import string
import base64
import time

#import modules
PADDING = bytes('{', "utf-8")
BLOCK_SIZE = 32
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
#prepare crypto method
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

secret ="FODETEBARRACAAAA"
cipher = AES.new(secret)

text = '{"index": 0, "timestamp": 1548787808.0, "data": {"uuid": "6e2a4954bc92c3ba8221319ed04ee1c0a7b0c81c6cc719f0a2cda868", "name": "pqewfhlasm,z", "description": "kjbvws,", "tipo": "English", "amount": 1333131.0, "duration": 10, "serial_number": 8792630208881704824}, "proof": "100", "previous_hash": "1"}'
text = bytes(text, "utf-8")
encoded = EncodeAES(cipher, text)
print(encoded)



""" decoded = DecodeAES(cipher, encoded)
print(decoded) """


reader = open('auction_Repository_private_key.pem', 'rb')
privKey = RSA.importKey(reader.read())
pubKey = privKey.publickey()

enc_field = pubKey.encrypt(encoded, _aspaadding.OAEP(mgf=_aspaadding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA512(),label=None))
print(enc_field)