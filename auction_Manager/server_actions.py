from server_registry import *
from server_cipher import ServerCipher
import shutil
import base64
import hashlib
from server_socket import ServerSocket
from validation_message import Validation
from client_keys_generator import Keys
import time
import ast

class ServerActions(ServerSocket):
    def __init__(self, mode, hmac_hash_type, host='127.0.0.1', port=8081):
        self.messageTypes = {
            'listAuctions': self.processListAuctions,
            'user_public_details': self.processUserPublicDetails,
            'session_key': self.processSessionKey,
            'createAuction': self.processCreateAuction,
            'createBid': self.processCreateBid,
            'generateBid': self.processGenerateBid,
            'getAuction': self.processGetAuctionInfo
        }
        self.server_cipher = ServerCipher()
        self.registry = ServerRegistry()
        self.key = Keys()
        super().__init__(mode, hmac_hash_type, host, port)

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
            #Checks if data is a dict
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

    def processCreateAuction(self, data, client, sec_data):
        """
        Create a Auction.
        :param data: dic with the data name, amount ...
        :param sec_data: security related data needed to build the response
        :return: send result of Repo to Client
        """
        log(logging.DEBUG, "%s" % json.dumps(data))
        if not Validation.validateSchema(json_reader=data,tipo="auction"):
            log(logging.ERROR, "No valid schema: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return
        sn = abs(hash(json.dumps(data)))
        data["serial_number"] = sn
        self.sck_send(data)
        rsp = self.sck_receive()
        return client.sendResult(rsp["result"], sec_data) 

    def processCreateBid(self, data, client, sec_data):
        """
        Create a Bid by checking  first if it is all goog.
        :param data: dic with data
        :param sec_data: security related data needed to build the response
        :return: send result of Repo to Client
        """
        log(logging.DEBUG, "%s" % json.dumps(data))
        if not Validation.validateSchema(json_reader=data,tipo="bid"):
            log(logging.ERROR, "No valid schema: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return

        msg = {"type": "getAuctionLastBlock", "auction_id": data["auction_id"]}
        self.sck_send(msg)
        rsp = self.sck_receive()
        if rsp["result"]:
            dat = rsp["auction_info"]
            dat = ast.literal_eval(dat)
            dat = dat["data"]
            deti = rsp["auction_lastblock"]
            deti = ast.literal_eval(deti)
            index = deti["index"]
            deti = deti["data"]
            print(deti)
            if dat["tipo"]=="Blind" and index != 0:
                deti = self.decrypt(deti, deti["uuid"])
            print(deti)
            if dat["tipo"] == "English" and deti["amount"] < data["amount"]:
                timestamp = rsp["timestamp"]
                duration = rsp["duration"]
                if (float(timestamp)+(float(duration)*60)) > time.mktime(time.gmtime()):
                    msg_new = {"result": True, "cryptopuzzle": rsp["cryptopuzzle"], "tipo": dat["tipo"]}
                    return client.sendResult(msg_new, sec_data)
                else:
                    return client.sendResult({"result": False}, sec_data)
                
            elif dat["tipo"] == "Blind" and dat["amount"] < data["amount"]:
                timestamp = rsp["timestamp"]
                duration = rsp["duration"]
                if (float(timestamp)+(float(duration)*60)) > time.mktime(time.gmtime()):
                    msg_new = {"result": True, "cryptopuzzle": rsp["cryptopuzzle"], "tipo": dat["tipo"]}
                    return client.sendResult(msg_new, sec_data)
                else:
                    return client.sendResult({"result": False}, sec_data)
        return client.sendResult(rsp, sec_data)

    def processGenerateBid(self, data, client, sec_data):
        """
        Create a Bid in server.
        :param data: dic with data
        :param sec_data: security related data needed to build the response
        :return: send result of Repo to Client
        """
        log(logging.DEBUG, "%s" % json.dumps(data))
        if not Validation.validateSchema(json_reader=data,tipo="bid"):
            log(logging.ERROR, "No valid schema: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"}, sec_data)
            return
        if data["tipo"]=="Blind":
            del data["tipo"]
            self.encrypt(data, data[uuid])
        else:
            del data["tipo"]
        self.sck_send(data)
        rsp = self.sck_receive()
        if rsp["result"]:
            message = {"result": "Receipt Received!! Saving It!", "receipt": rsp["receipt"], "status": True}
            return client.sendResult(message, sec_data)
        else:
            message = {"result": "Some Error Happen!! Try Again", "status": False}
            return client.sendResult(message, sec_data) 

    def processListAuctions(self, data, client, sec_data):
        """
        Sent by the client in order to list all Auctions.
        :param data: dic with type, id (optional uuid), ...
        :param sec_data: security related data needed to build the response
        :return: send result to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))
        self.sck_send(data)
        rsp = self.sck_receive()
        return client.sendResult(rsp, sec_data) 

    def processGetAuctionInfo(self, data, client, sec_data):
        """
        Sent by the client in order to get a Auction Blockchain.
        :param data: dic with type, id (uuid), ...
        :param sec_data: security related data needed to build the response
        :return: send result (dic with a list with new messages) to client socket
        """
        log(logging.DEBUG, "%s" % json.dumps(data))
        self.sck_send(data)
        rsp = self.sck_receive()
        blockchain_info = ast.literal_eval(rsp["blockchain"][0])
        
        if (float(blockchain_info["timestamp"])+(float(blockchain_info["data"]["duration"])*60)) > time.mktime(time.gmtime()):
            print("Auction fechada")
            blockchains= []
            index = 0
            for blockchain in rsp["blockchain"]:
                blockchain = ast.literal_eval(blockchain)
                if index == 0:
                    blockchains.append(blockchain)
                else:
                    if blockchain_info["data"]["tipo"] == "Blind":
                        blockchain = self.decrypt(blockchain,blockchain["data"]["uuid"])
                    blockchains.append(blockchain)
                print(blockchain)
                index += 1
            print(blockchains)
            return client.sendResult({"result": True, "blockchain": blockchains}, sec_data)
        else:
            print("Auction Aberta")
            return client.sendResult(rsp, sec_data)

    @staticmethod
    def encrypt(blockchain_data, uuid):
        """
        Encrypt field with users key
        :param blockchain_data: data
        :param uuid: user uuid
        :return: fields required are encrypted
        """
        print("Encrypt")
        data == blockchain_data["amount"]
        if os.path.exists("./utils/keys/"+str(uuid)):
            blockchain_data["amount"] = self.key.encrypt(data,uuid)
        else:
            os.makedirs("utils/keys/"+str(uuid))
            self.key.keyGenerator(uuid)
            blockchain_data["amount"] = self.key.encrypt(data,uuid)
        return blockchain_data
        
    @staticmethod
    def decrypt(blockchain_data, uuid):
        """
        Decrypt Field
        :param blockchain_data: data
        :param uuid: user uuid
        :return: blockchain_data decrypted
        """
        print("decrypt")
        data == blockchain_data["amount"]
        print(data)
        blockchain_data["amount"] = self.key.decrypt(data,uuid)
        return blockchain_data