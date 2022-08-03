#!/usr/bin/env python3

import requests
from base64 import b64encode, b64decode
from binascii import hexlify
from code import interact
import sys

from http.client import HTTPConnection
# Set debug output level (1 = spam)
HTTPConnection.debuglevel = 0


# Code re-use from get_encrypted_key_db
def get_encrypted_key_db(data):
    encoded_data = bytearray()
    for _, key, path in data:
        encoded_data += len(key).to_bytes(4, byteorder='little')
        encoded_data += key
        encoded_data += b"\x00\x00\x00\x00"
        encoded_data += len(path).to_bytes(4, byteorder='little')
        encoded_data += f"{path}".encode()
        encoded_data += b"\x00\x00\x00\x00"
    res = requests.post("http://116.202.161.100:57689/encrypt_db", data=b64encode(encoded_data))
    return b64decode(res.text)


# Set null key based on sys.argv[1] 16/24/32 Bytes (128/192/256 Bit)
# Set file path to sys.argv[2]
# File path /home/challenge/notes/todo.txt.enc (found in keys.db)
key_len = int(sys.argv[1])
file_path = sys.argv[2]
key_db = get_encrypted_key_db([["unknown", b"\x00" * key_len, file_path]])
print(hexlify(key_db).decode())
