from server_registry import *
from server_cipher import ServerCipher
from blockchain import Blockchain
import shutil
import base64
import time

class ServerActions:
    def __init__(self):
        self.messageTypes = {
            'listAuctions': self.processListAuctions,
            'createAuction': self.processCreateAuction,
            'createBid': self.processCreateBid,
            'getAuctionLastBlock': self.processGetAuctionLastBlock,
            'getCryptoPuzzle': self.processGetCryptoPuzzle,
            'generateBid': self.processGenerateBid,
            'user_public_details': self.processUserPublicDetails,
            'session_key': self.processSessionKey,
            'getAuction': self.processGetAuction,
            'getAuctionTime': self.processGetAuctionTime
        }
        self.server_cipher = ServerCipher()
        self.registry = ServerRegistry()
        self.blockchain = Blockchain()

    def handleRequest(self, s, request, client):
        """
        Handle a request from a client socket.
        """
        try:
            sec_data = None
            try:
                json.loads(request)
                is_json = True
            except:
                is_json = False
            if client.server_cipher.session_key is not None and not is_json:
                request, sec_data = client.server_cipher.secure_layer_decrypt(request.encode())
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))
            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return
            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return
            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return
            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client, sec_data)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"}, sec_data)
        except Exception as e:
            logging.exception("Could not handle request")

    def processSessionKey(self, data, client, sec_data):

        if "phase" not in data["msg"] or not isinstance(data["msg"]["phase"], int):
            log(logging.ERROR, "The process session key must have a phase number.")
            client.sendResult({"error": "unknown request"}, sec_data)
            return
        if data["msg"]["phase"] == 2 or data["msg"]["phase"] == 4:
            result = client.server_cipher.negotiate_session_key(data["msg"]["phase"], data["msg"])
            # we have the shared secret but the client don't, so force no cipher response
            client.sendResult({"result": result}, sec_data)
            return
        else:
            log(logging.ERROR, "Invalid message phase: " + str(data["msg"]['phase']))
            client.sendResult({"error": "unknown request"}, sec_data)
            return

    def processUserPublicDetails(self, data, client, sec_data):
        for i in range(1, len(self.registry.users) + 1):
            if self.registry.users[i]["id"] == data["id"]:
                client.sendResult({"result": self.registry.users[i]["description"]}, sec_data)
                return
        client.sendResult({"result": None})

    def processGetAuctionLastBlock(self, data, client, sec_data):
        """
        Get Last Block of the Auction in the Blockchain.
        :param data: dic with type, uuid, ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        auction_info = self.blockchain.get_auction(data["auction_id"])[0]
        auction = self.blockchain.last_block(data["auction_id"])
        timestamp, duration = self.blockchain.getTime(data["auction_id"])
        proof_of_work = self.blockchain.proof_of_work(data["auction_id"])
        if len(auction) > 0:
            client.sendResult({"result": True, "auction_info": auction_info, "auction_lastblock": auction, "timestamp": timestamp, "duration": duration, "cryptopuzzle": proof_of_work}, sec_data)
        else:
            client.sendResult({"result": False}, sec_data)

    def processGetAuction(self, data, client, sec_data):
        """
        Get Auction Blockchain.
        :param data: dic with type, uuid, ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        auction = self.blockchain.get_auction(data["auction_id"])
        if auction == False:
            client.sendResult({"result":  False}, sec_data)
        else:
            client.sendResult({"result": True, "blockchain": auction}, sec_data)

    def processCreateAuction(self, data, client, sec_data):
        """
        Create Auction in the Blockchain.
        :param data: dic with type, uuid, ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        del data["type"]
        if self.blockchain.new_genesis_block(data=data):
            client.sendResult({"result": "Auction Criado"}, sec_data)
        else:
            client.sendResult({"result": "Erro na criação da auction"}, sec_data)

    def processCreateBid(self, data, client, sec_data):
        """
        Create Auction in the Blockchain.
        :param data: dic with type, uuid, ...
        :param client: client socket
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        if self.blockchain.new_block(data=data):
            client.sendResult({"result": "Auction Criado"}, sec_data)
        else:
            client.sendResult({"result": "Erro na criação da auction"}, sec_data)

    def processListAuctions(self, data, client, sec_data):
        """
        Sent by the Manager in order to list all Auctions.
        :param data: dic with type, id (optional uuid), ...
        :param client: manager socket
        :param sec_data: security related data needed to build the response
        :return: send result to manager socket
        """

        auctions = self.blockchain.all_auctions()
        client.sendResult({"result": auctions, "time": time.mktime(time.gmtime())}, sec_data)

    def processGetAuctionTime(self, data, client, sec_data):
        """
        Sent by the Manager in order to get an Auction Duration and Time of Creation.
        :param data: dic with type, id (optional uuid), ...
        :param client: manager socket
        :param sec_data: security related data needed to build the response
        :return: send result to manager socket
        """
        timestamp, duration = self.blockchain.getTime(data["auction_id"])
        client.sendResult({"result": True, "timestamp": timestamp, "duration": duration}, sec_data)

    def processGenerateBid(self, data, client, sec_data):
        """
        Sent by the Manager in order to list all Auctions.
        :param data: dic with type, id (optional uuid), ...
        :param client: manager socket
        :param sec_data: security related data needed to build the response
        :return: send result to manager socket
        """

        proof = data["cryptopuzzle"]
        del data["cryptopuzzle"]
        del data["type"]
        boo, time = self.blockchain.new_block(data=data, proof=proof)
        if boo:
            receipt = self.generateReceipt(data,time,proof)
            client.sendResult({"result": True, "receipt": receipt}, sec_data)
        else:
            client.sendResult({"result": False}, sec_data)

    def processGetCryptoPuzzle(self, data, client, sec_data):
        """
        Sent by the Manager in order to list all Auctions.
        :param data: dic with type, id (optional uuid), ...
        :param client: manager socket
        :param sec_data: security related data needed to build the response
        :return: send result to manager socket
        """

        proof_of_work = self.blockchain.proof_of_work(data["auction_id"])
        client.sendResult({"result": True, "cryptopuzzle": proof_of_work}, sec_data)

    def generateReceipt(self, data, time,proof):
        """
        Generate Receipt.
        :param data: dic with type, id (optional uuid), ...
        :param time: time of block creation
        :return: receipt
        """

        receipt = {"uuid": data["uuid"], "auction_id": data["auction_id"], "amount": data["amount"], "time": time, "proof": proof}
        return receipt
    