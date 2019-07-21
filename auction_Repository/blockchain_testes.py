from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
import time
from urllib.parse import urlparse
from uuid import uuid4
import os

from Crypto.Cipher import AES
import string
import base64

from cryptography.hazmat.primitives.asymmetric import padding as _aspaadding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

""" Block format

block = {
    'index': 1,
    'timestamp': 1506057125.900785,
    'information': [
        {
            'user': "8527147fe1f5426f9dd545de4b27ee00",
            'auction': "a77f5cdfa2934df3954a5c7c7da5df1f",
            'amount': 5,
        }
    ],
    'proof': 324984774000,
    'previous_hash': "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
}

"""
INITIAL_MINING_DIFFICULTY = 1

class Blockchain:

    def valid_chain(self, auction_id):
        """
        Determine if a given blockchain is valid
        
        Parameters
        -----
        chain - Blockchain

        Returns
        -----
        True if valid otherwise False.
        """

        last_block = self.last_block(auction_id)
        current_index = 1

        chain_size = len(os.listdir(auction_id))
        
        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    """ def blockCipher(self,content, privKey):
        print("Entrei")
        content = str(content)
        print(content)
        content = bytes(content, "utf-8")
        print(content)
        enc_content = privkey.encrypt(content,2048)
        return enc_content """
    def blockCipher(self, content):
        PADDING = bytes('{', "utf-8")
        BLOCK_SIZE = 32
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        #prepare crypto method
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

        secret ="FODETEBARRACAAAA"
        cipher = AES.new(secret)
        #text = '{"index": 0, "timestamp": 1548787808.0, "data": {"uuid": "6e2a4954bc92c3ba8221319ed04ee1c0a7b0c81c6cc719f0a2cda868", "name": "pqewfhlasm,z", "description": "kjbvws,", "tipo": "English", "amount": 1333131.0, "duration": 10, "serial_number": 8792630208881704824}, "proof": "100", "previous_hash": "1"}'
        text = bytes(content, "utf-8")
        encoded = EncodeAES(cipher, text)
        print(encoded)
        return encoded

    def new_genesis_block(self, data, proof="100", previous_hash="1"):
        """
        Create the first Block in the Blockchain

        Parameters
        -----
        proof - The proof given by the Proof of Work algorithm.
        data - Json with Auction Info.

        Returns
        -----
        block - New Block
        """

        print("Gene_Block")
        index = 0
        block = {
            'index': index,
            'timestamp': time.mktime(time.gmtime()),
            'data': data,
            'proof': proof,
            'previous_hash': previous_hash,
        }
        reader = open('auction_Repository/auction_Repository_private_key.pem', 'rb')
        privKey = RSA.importKey(reader.read())

        folder_name = "Blockchains/"+str(data.get("serial_number"))
        try:
            os.makedirs(folder_name)
        except:
            return False

        nome = str(index)+".txt"
        file_to_write = os.path.join(folder_name,nome)
        f= open(file_to_write,"wb")
        content = json.dumps(block)
        #f.write(content)
        encrypted = self.blockCipher(content, privKey)
        print("ola")
        f.write(encrypted)
        f.close
        
        return True

    def new_block(self, proof, data):
        """
        Create a new Block in the Blockchain

        Returns
        -----
        proof: The proof given by the Proof of Work algorithm.
        previous_hash: Hash of previous Block.

        Returns
        -----
        block - New Block
        """
        
        if os.path.exists("Blockchains/"+str(auction_id)):
            index = len(os.listdir("Blockchains/"+str(data["auction_id"])))
            f = open("Blockchains/"+str(index-1)+".txt", "r+")
            last_block = f.read()

            block = {
                'index': index,
                'timestamp': time.mktime(time.gmtime()),
                'data': data,
                'proof': proof,
                'previous_hash': self.hash(last_block)
            }
            folder_name = "Blockchains/"+str(data.get("auction_id"))
            nome = str(index)+".txt"
            file_to_write = os.path.join(folder_name,nome)
            f= open(file_to_write,"w+")
            f.write(json.dumps(block))
            f.close
            return True, block["timestamp"]
        else:
            return False

    def last_block(self, auction_id):
        """
        Returns the last block of blockchain.
        """
        try:
            index = len(os.listdir(auction_id))
            f = open(str(index-1)+".txt", "r+")
            last_block = f.read()
            return last_block
        except:
            return None

    def hash(self,block):
        """
        Creates a SHA-256 hash of a Block.

        Parameters
        -----
        block: Blockchain Block.

        Returns
        -----
        Hashed block.
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, auction_id):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading x zeroes
         - Where p is the previous proof, p' is the new proof and x is the number of bids
         
        Parameters
        -----
        auction_id: serial number of Blockchain
        
        Returns
        -----
        proof - The proof of work
        """
        last_block = self.last_block(auction_id)
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return bin(proof)

    def all_auctions(self):
        """
        Gets All Auctions.
        Returns name, serial number, description and status
        
        Returns
        -----
        All auctions
        """
        subfolders = [f.path for f in os.scandir('Blockchains') if f.is_dir() ]
        auction_info = []
        for subfolder in subfolders:
            f = open(str(subfolder)+"/0.txt", "r+")
            auction_info.append(f.read())
            print(f.read())
        print(auction_info)
        return auction_info

    def get_auction(self, auction_id):
        """
        Get Auction.
        Returns name, serial number, description and status
        
        Returns
        -----
        All auctions
        """
        if os.path.exists("Blockchains/"+str(auction_id)):
            print("Existe")
            chain_size = len(os.listdir("Blockchains/"+str(auction_id)))
            print(chain_size)
            index = 0
            blockchain_complete = []
            while index < chain_size:
                print("Abriu")
                f = open("Blockchains/"+str(auction_id)+"/"+str(index)+".txt", "r+")
                blockchain_complete.append(f.read())
                index += 1
            print(blockchain_complete)
            return blockchain_complete
        else:
            return False

    @staticmethod
    def valid_proof(last_proof, proof, last_hash, auction_id):
        """
        Validates the Proof

        Parameters
        -----
        last_proof: Previous Proof
        proof: Current Proof
        last_hash: The hash of the Previous Block
        
        Returns
        -----
        True if correct otherwise False.
        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        diff = INITIAL_MINING_DIFFICULTY + len(os.listdir(auction_id))
        n_zeros = ""
        for i in range(1,diff):
            n_zeros += "0"
        return guess_hash[:diff] == n_zeros