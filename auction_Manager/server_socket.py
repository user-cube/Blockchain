import socket
import json
from server_cipher2 import ServerCipher2


MSGLEN = 64 * 1024
TERMINATOR = "\r\n"


class ServerSocket:
    def __init__(self, mode, hmac_hash_type, host='', port=8081):
        """
        Create a client to connect to server socket.
        :param host: server IP
        :param port: server port
        """
        print("Establish Connection Repository")
        # init client cipher
        self.server_cipher = ServerCipher2(mode, hmac_hash_type)

        # try to connect with server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        # key rotation
        self.key_rotation_use = 10  # default 10

        # init bootstrap
        self.channel_bootstrap()

    def channel_bootstrap(self):
        # phase 1
        result = self.server_cipher.negotiate_session_key(phase=1)

        # send to the server
        msg = {"type": "session_key", "msg": result}
        self.sck_send(msg, cipher=False)

        # wait for response
        response = self.sck_receive()

        # phase 3
        result = self.server_cipher.negotiate_session_key(phase=response["result"]["phase"], val=response["result"])
        msg = {"type": "session_key", "msg": result}
        self.sck_send(msg, cipher=False)

        # wait for response
        response = self.sck_receive()

    def sck_send(self, msg, cipher=True):
        """
        https://docs.python.org/2/howto/sockets.html
        :param msg: message to send
        :return: None
        """
        # if cipher and key_rotation_use == 0, channel_bootstrap again
        if cipher and self.key_rotation_use == 0:
            self.channel_bootstrap()
            self.key_rotation_use = 10

        msg = json.dumps(msg)

        if cipher and self.server_cipher.session_key is not None:
            msg = self.server_cipher.secure_layer_encrypt(msg).decode()
            self.key_rotation_use -= 1
            #print("key rotation decrement: %d" % self.key_rotation_use)  # delete me

        msg = (msg + TERMINATOR).encode()

        self.sock.sendall(msg)

    def sck_receive(self):
        """
        https://docs.python.org/2/howto/sockets.html
        :return: received piece of message
        """
        chunks = []

        while True:
            chunk = self.sock.recv(MSGLEN)

            if not chunk:
                break

            chunks.append(chunk.decode())

            if TERMINATOR in chunk.decode():
                break

        chunks = ''.join(''.join(chunks).split(TERMINATOR)[:-1])

        try:
            raw_data = json.loads(chunks)
        except json.JSONDecodeError:
            raw_data = json.loads(self.server_cipher.secure_layer_decrypt(chunks.encode()))

        return raw_data
