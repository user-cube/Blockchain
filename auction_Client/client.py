from client_actions import ClientActions
from client_cc import CitizenCard
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import ast
import os, errno
import json

class Client:
    def __init__(self):
        modes.CTR
        hmac_hash_type = SHA256

        print("Connecting to Server")

        self.cc = CitizenCard()
        self.client = ClientActions(modes.CTR, hmac_hash_type, self.cc)

        # generate the uuid of the user
        print("Generating UUID based in your Citizen Card (Authentication PIN may be asked more than once)")
        self.uuid = self.cc.generate_uuid()
        print("Client UUID is: %s " % self.uuid)
        # user keys
        self.private_key = None
        self.public_key = None
        self.private_key_pem = None
        self.public_key_pem = None
        self.user_asym_keys()

        while self.menu():
            pass
        
    def user_asym_keys(self):
        if not os.path.exists('utils/user_keys/%s/private_key.pem' % self.uuid):
            try:
                os.makedirs('utils/user_keys/%s' % self.uuid)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

            # create private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            """ cipher to stored private key """
            signature = self.cc.sign(self.uuid)

            ciphered_key_pem = self.client.client_cipher.sym_cipher(pem, signature[0:32], signature[32:48], modes.CTR)[1]  # return 0 -> iv, 1-> ciphered obj

            self.private_key_pem = pem
            private_file = 'utils/user_keys/%s/private_key.pem' % self.uuid
            f = open(private_file, 'wb')
            f.write(ciphered_key_pem)
            f.close()
        else:
            # load private key
            tmp = open('utils/user_keys/%s/private_key.pem' % self.uuid, "rb").read()

            signature = self.cc.sign(self.uuid)

            self.private_key_pem = self.client.client_cipher.sym_decipher(tmp, signature[0:32], signature[32:48], modes.CTR)

            self.private_key = serialization.load_pem_private_key(self.private_key_pem, password=None,
                                                                backend=default_backend())

        if not os.path.exists('utils/user_keys/%s/public_key.pem' % self.uuid):
            try:
                os.makedirs('utils/user_keys/%s' % self.uuid)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise

            # public key
            self.public_key = self.private_key.public_key()

            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            """ cipher the stored public key """
            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            # cipher the stored key
            ciphered_key_pem = self.client.client_cipher.sym_cipher(pem, signature[0:32], signature[32:48], modes.CTR)[1]  # return 0 -> iv, 1-> ciphered obj

            self.public_key_pem = pem
            public_file = 'utils/user_keys/%s/public_key.pem' % self.uuid
            f = open(public_file, 'wb')
            f.write(ciphered_key_pem)
            f.close()
        else:
            tmp = open('utils/user_keys/%s/public_key.pem' % self.uuid, "rb").read()

            # sign the uuid (known and unique value)
            signature = self.cc.sign(self.uuid)

            self.public_key_pem = self.client.client_cipher.sym_decipher(tmp, signature[0:32], signature[32:48], modes.CTR)

            # load public key
            self.public_key = serialization.load_pem_public_key(self.public_key_pem, backend=default_backend())

    def menu(self):
        """
        Menu function.
        """
        print("OPTIONS AVAILABLE:")
        print("1 - Create Auction")
        print("2 - Create Bid")
        print("3 - List Auctions")
        print("4 - List Bids")
        print("5 - Auction Information")
        print("0 - Exit")

        while True:
            try:
                option = int(input("Option: "))
                if (option <= 5 and option >= 0):
                    break
                else:
                    print("Invalid number")
            except:
                print("Invalid")

        print("-------------------------")
        
        if option == 1:
            while True:
                try:
                    name = str(input("Write the name of the auction:"))
                    if len(name) > 0:
                        break
                except:
                    print("Invalid")

            while True:
                try:
                    description = str(input("Write a short description for the auction:"))
                    if len(description) > 0:
                        break
                except:
                    print("Invalid")
            
            tipo = None
            
            while tipo == None:
                print("Type of Auction:")
                print("1 - English Auction")
                print("2 - Blind Auction")
                
                while True:
                    try:
                        ops = int(input("Option: "))
                        if (ops == 1 or ops == 2):
                            break
                        else:
                            print("Invalid number")
                    except:
                         print("Invalid")

                print("-------------------------")
                if ops == 1:
                    tipo = "English"
                elif ops == 2:
                    tipo = "Blind"
                else:
                    print("Not an Option. Choose Again!!!\n")
            while True:
                try:
                    amount = float(input("Inicial Amount:"))
                    if amount > 0:
                        break
                except:
                    print("Invalid")
            while True:
                try:
                    duration = int(input("Duration of the auction (in minutes): "))
                    if duration > 0:
                        break
                except:
                    print("Invalid")
            
            dinamic = None

            while dinamic == None:
                print("Insert dinamic code?:")
                print("WARNING: Make sure the code is written in python and RETURNS a Boolean!!")
                print("1 - YES")
                print("2 - NO")

                while True:
                    try:
                        opss = int(input("Option: "))
                        if (opss == 1 or opss == 2):
                            break
                        else:
                            print("Invalid number")
                    except:
                        print("Invalid")

                print("-------------------------")
                if opss == 1:
                    dinamic = True
                elif opss == 2:
                    dinamic = False
                else:
                    print("Not an Option. Choose Again!!!\n")

            message = None
            if dinamic:
                dinamic_code = getfile()
                message = {"uuid": self.uuid, "name": name, "description": description, "tipo": tipo, "amount": amount, "duration": duration, "dinamic_code": dinamic_code, "type": "createAuction"}
            else:
                message = {"uuid": self.uuid, "name": name, "description": description, "tipo": tipo, "amount": amount, "duration": duration, "type": "createAuction"}
            
            rsp = self.client.newAuction(message)
            print(rsp)

        elif option == 2:
            auction_serialnumber = int(input("Auction Serial Number: "))
            amount = int(input("Amount: "))
            print("Checking if Bid is good...")
            message = {"uuid": self.uuid, "auction_id": auction_serialnumber, "amount": amount, "type": "createBid"}
            rsp = self.client.newBid(message)
            if rsp["result"]:
                print("All Good. Preparing CriptoPuzzle!!")
                binary_number = rsp["cryptopuzzle"]
                answer = int(input("Please convert this binary number "+binary_number+" into a decimal number: "))
                message["cryptopuzzle"] = answer
                message["type"] = "generateBid"
                message["tipo"] = rsp["tipo"]
                resp = self.client.bidpuzzle(message)
                print(resp["result"])
                if resp["status"]:
                    if not os.path.exists("Receipts"):
                        try:
                            os.makedirs("Receipts")
                        except OSError as e:
                            if e.errno != errno.EEXIST:
                                raise
                    nome = str(hash(json.dumps(resp)))+".txt"
                    folder_name = "./Receipts"
                    file_to_write = os.path.join(folder_name,nome)
                    f= open(file_to_write,"w+")
                    f.write(json.dumps(resp["receipt"]))
                    f.close
            else:
                print("Erro na criação da Bid!!")
                
        elif option == 3:
            print("Listing all auctions and their status:\n")
            rsp = self.client.listAuctions()
            result = rsp["result"]
            time = rsp["time"]
            print(time)
            for auction in result:
                auction = ast.literal_eval(auction) 
                print("Auction Name: " + str((auction.get("data").get("name"))))
                print("Serial Number: " + str((auction["data"])["serial_number"]))
                print("Description: " + str((auction["data"])["description"]))
                if (float((auction["data"])["duration"])*60)+float(auction["timestamp"]) > float(time):
                    print("Status: Open")
                else:
                    print("Status: Closed")
            print("-------------------------")

        elif option == 4:
            print("Getting all your RECEIPTS")
            if os.path.exists("./Receipts"):
                n_receipts = len(os.listdir("./Receipts"))
                if n_receipts > 0:
                    files = [f.path for f in os.scandir('./Receipts')]
                    for fil in files:
                        f = open(str(fil), "r+")
                        print(f.read())
                        print("-----------------------")
                else:
                    print("There is no receipt yet.")
            else:
                print("There is no receipt yet")

        elif option == 5:
            auction_serialnumber = int(input("Auction Serial Number:"))
            msg = {"auction_id": auction_serialnumber, "type": "getAuction"}
            rsp = self.client.getAuction(msg)
            print(rsp)
            if rsp["result"]:
                index = 0
                maxi = len(rsp["blockchain"])
                while index < maxi:
                    try:
                        blockchain = ast.literal_eval(rsp["blockchain"][index])
                        print(blockchain)
                    except:
                        blockchain = rsp["blockchain"][index]
                        print(blockchain)
                    for k, v in blockchain.items():
                        print(str(k)+" : "+str(v))
                        print("--------------------------")
                    index +=1
            else:
                print("Blockchain não existe")

        else:
            return False

        print("-------------------------")
        return True


if __name__ == '__main__':
    client = Client()
