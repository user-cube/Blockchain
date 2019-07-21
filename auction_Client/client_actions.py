from client_socket import ClientSocket
import json
import base64
from client_cc import CitizenCard
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from datetime import datetime
import uuid


class ClientActions(ClientSocket):
    def __init__(self, mode, hmac_hash_type, cc, host='127.0.0.1', port=8080):
        """
        Create a client to connect to server socket.

        Parameters
        -----
        cc - Citizen Card user
        host - Server IP
        port - Server port
        """
        self.cc = cc
        super().__init__(mode, hmac_hash_type, host, port)

    def newAuction(self, msg):
        """
        Sent by the client in order to create a Auction.

        Parameters
        -----
        msg - Dict with info

        Returns
        -----
        sck_receive - The response of the server
        """
        self.sck_send(msg)

        return self.sck_receive()

    def newBid(self, msg):
        """
        Sent by the client in order to create a Bid.

        Parameters
        -----
        id - Client uuid

        Returns
        -----
        sck_receive - The response of the server
        """
        self.sck_send(msg)

        return self.sck_receive()

    def bidpuzzle(self, msg):
        """
        Sent by the client in order to create a Bid.

        Parameters
        -----
        id - Client uuid

        Returns
        -----
        sck_receive - The response of the server
        """
        self.sck_send(msg)

        return self.sck_receive()

    def listAuctions(self):
        """
        Sent by the client in order to list all Auctions.
        
        Returns
        -----
        sck_receive - The response of the server
        """
        msg = {"type": "listAuctions"}
        self.sck_send(msg)

        return self.sck_receive()

    def getAuction(self, msg):
        """
        Sent by the client in order to list all Auctions.
        
        Returns
        -----
        sck_receive - The response of the server
        """
        self.sck_send(msg)

        return self.sck_receive()

    def allreceipts(self):
        """
        Sent by the client to show all receipts (as they are saved locally no need to call server).
        
        Returns
        -----
        None
        """

        # sign the message with the CC, but only the message
        msg["uuid"]=str(uuid.uuid4())
        msg["signature"] = base64.b64encode(self.cc.sign(msg.encode())).decode()
        msg = json.dumps(msg)
        
        self.sck_send(msg)

        return None