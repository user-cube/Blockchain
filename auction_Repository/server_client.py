import json
import sys

from server_cipher import ServerCipher
from log import *

TERMINATOR = "\r\n"
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30


class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = bytearray()
        self.addr = addr
        self.id = None
        self.sa_data = None
        self.server_cipher = ServerCipher()
        self.me = None  # user id

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

    def asDict(self):
        return {'id': self.id}

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += str(data.decode())
        reqs = self.bufin.split(TERMINATOR)
        self.bufin = reqs[-1]

        return reqs[:-1]

    def sendResult(self, obj, sec_data=None):
        """Send an object to this client.
        """
        try:
            if isinstance(obj, set):
                obj = list(obj)

            to_send = ""

            if sec_data is not None and self.server_cipher.session_key is not None:
                # cipher to_send
                to_send += self.server_cipher.secure_layer_encrypt(json.dumps(obj).encode(), sec_data).decode()
            else:
                to_send += json.dumps(obj)

            to_send += "\r\n"

            self.bufout += to_send.encode()
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)
