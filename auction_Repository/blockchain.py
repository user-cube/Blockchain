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
import ast

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
        chain = self.get_auction(auction_id)
        while current_index < len(chain):
            block = ast.literal_eval(chain[current_index])
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash, auction_id):
                return False

            last_block = block
            current_index += 1

        return True

    def blockCipher(self, content):
        PADDING = bytes('{', "utf-8")
        BLOCK_SIZE = 32
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
        #prepare crypto method
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

        secret ="LAGRIMADERRAMADA"
        cipher = AES.new(secret)
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
        index = 0
        block = {
            'index': index,
            'timestamp': time.mktime(time.gmtime()),
            'data': data,
            'proof': proof,
            'previous_hash': previous_hash,
        }

        folder_name = "Blockchains/"+str(data.get("serial_number"))
        try:
            os.makedirs(folder_name)
        except:
            return False

        nome = str(index)+".txt"
        file_to_write = os.path.join(folder_name,nome)
        f= open(file_to_write,"wb")
        content = json.dumps(block)
        encrypted = self.blockCipher(content)
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
        
        if os.path.exists("Blockchains/"+str(data["auction_id"])):
            index = len(os.listdir("Blockchains/"+str(data["auction_id"])))
            f = open("Blockchains/"+str(data["auction_id"])+"/"+str(index-1)+".txt", "rb")
            last_block = f.read()
            PADDING = bytes('{', "utf-8")
            DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
            secret ="LAGRIMADERRAMADA"
            cipher = AES.new(secret)
            decoded = DecodeAES(cipher, last_block)
            decoded = decoded.decode("utf-8")

            block = {
                'index': index,
                'timestamp': time.mktime(time.gmtime()),
                'data': data,
                'proof': proof,
                'previous_hash': self.hash(decoded)
            }
            folder_name = "Blockchains/"+str(data.get("auction_id"))
            nome = str(index)+".txt"
            file_to_write = os.path.join(folder_name,nome)
            f= open(file_to_write,"wb")
            content = json.dumps(block)
            encrypted = self.blockCipher(content)
            f.write(encrypted)
            f.close
            return True, block["timestamp"]
        else:
            return False

    def last_block(self, auction_id):
        """
        Returns the last block of blockchain.
        """

        print("Open file 1")
        print(auction_id)
        index = len(os.listdir("Blockchains/"+str(auction_id)))
        print("Open file 2")
        f = open("Blockchains/"+str(auction_id)+"/"+str(index-1)+".txt", "rb")
        last_block = f.read()
        PADDING = bytes('{', "utf-8")
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
        secret ="LAGRIMADERRAMADA"
        cipher = AES.new(secret)
        decoded = DecodeAES(cipher, last_block)
        decoded = decoded.decode("utf-8")
        print(decoded)
        return decoded

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
        last_block = ast.literal_eval(last_block)
        last_proof = last_block["proof"]
        last_hash = self.hash(last_block)
        proof = 0
        while self.valid_proof(last_proof, proof, last_hash, auction_id) is False:
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
            f = open(str(subfolder)+"/0.txt", "rb")
            PADDING = bytes('{', "utf-8")
            DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
            secret ="LAGRIMADERRAMADA"
            cipher = AES.new(secret)
            decoded = DecodeAES(cipher, f.read())
            decoded = decoded.decode("utf-8")
            print(decoded)
            auction_info.append(decoded)
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
            chain_size = len(os.listdir("Blockchains/"+str(auction_id)))
            index = 0
            blockchain_complete = []
            while index < chain_size:
                print("Abriu")
                f = open("Blockchains/"+str(auction_id)+"/"+str(index)+".txt", "rb")
                PADDING = bytes('{', "utf-8")
                DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
                secret ="LAGRIMADERRAMADA"
                cipher = AES.new(secret)
                decoded = DecodeAES(cipher, f.read())
                decoded = decoded.decode("utf-8")
                blockchain_complete.append(decoded)
                index += 1
            return blockchain_complete
        else:
            return False

    def getTime(self, auction_id):
        """
        Get Auction Time and Duration.
        Returns name, serial number, description and status
        
        Returns
        -----
        All auctions
        """
        if os.path.exists("Blockchains/"+str(auction_id)):
            f = open("Blockchains/"+str(auction_id)+"/0.txt", "rb")
            PADDING = bytes('{', "utf-8")
            DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
            secret ="LAGRIMADERRAMADA"
            cipher = AES.new(secret)
            decoded = DecodeAES(cipher, f.read())
            decoded = decoded.decode("utf-8")
            auction = ast.literal_eval(decoded)
            timestamp = auction["timestamp"]
            duration = auction["data"]["duration"]
            return timestamp, duration
        else:
            return None, None

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
        diff = INITIAL_MINING_DIFFICULTY + len(os.listdir("Blockchains/"+str(auction_id)))
        n_zeros = ""
        for i in range(0,diff):
            n_zeros += "0"
        return guess_hash[:diff] == n_zeros