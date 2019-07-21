import os
import sys
from log import *
import logging
import re
import json
import time

sys.tracebacklimit = 30

MBOXES_PATH = "mboxes"
RECEIPTS_PATH = "receipts"
DESC_FILENAME = "description"


class UserDescription(dict):

    def __init__(self, uid, description=None):
        dict.__init__(self, id=uid, description=description)
        self.id = uid
        self.description = description


class ServerRegistry:

    def __init__(self):

        self.users = {}

    def userExists(self, uid):
        return self.getUser(uid) is not None

    def userExists_uuid(self, uuid):
        for user in self.users.items():
            if user[1]["description"]["uuid"] == uuid:
                return True
        return False

    def getUser(self, uid):
        if isinstance(uid, int):
            if uid in self.users.keys():
                return self.users[uid]
            return None

        if isinstance(uid, str):
            for user in self.users.keys():
                if self.users[user]["description"]["uuid"] == uid:
                    return self.users[user]
        return None

    def addUser(self, description):
        uid = 1
        while self.userExists(uid):
            uid += 1

        if 'type' in description.keys():
            del description['type']

        log(logging.DEBUG, "add user \"%s\": %s" % (uid, description))

        user = UserDescription(uid, description)
        self.users[uid] = user

        for path in [self.userMessageBox(uid), self.userReceiptBox(uid)]:
            try:
                os.makedirs(path)
            except:
                logging.exception("Cannot create directory " + path)
                sys.exit(1)

        path = ""
        try:
            path = os.path.join(MBOXES_PATH, str(uid), DESC_FILENAME)
            log(logging.DEBUG, "add user description " + path)
            self.saveOnFile(path, json.dumps(description))
        except:
            logging.exception("Cannot create description file " + path)
            sys.exit(1)

        return user

    def listUsers(self, uid):
        if uid == 0:
            log(logging.DEBUG, "Looking for all connected users")
        else:
            log(logging.DEBUG, "Looking for \"%d\"" % uid)

        if uid != 0:
            user = self.getUser(uid)

            if user is not None:
                return [user]
            return None

        userList = []
        for k in self.users.keys():
            userList.append(self.users[k].description)

        return userList
