#!/usr/bin/env python3

import requests
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from code import interact
from Crypto.Cipher import AES

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

# Load keys.db

with open("./keys.db", "rb") as f:
  local_keys_db = f.read()
f.close()

# Verify option (nonce, key, tag) and (nonce, tag, key)
file_path = "/home/challenge/notes/todo.txt.enc"

# Send null key
nullkey_keys_db = get_encrypted_key_db([["unknown", b"\x00" * 16, file_path]])
encrypted_null_key = nullkey_keys_db[32:48]

# Recover plaintext key
file_encryption_key = bytearray([x^y for x,y in zip(encrypted_null_key, local_keys_db[32:48])])

# Decrypt todo.txt.enc
with open("./notes/todo.txt.enc", "rb") as g:
  todo = g.read()
g.close()

file_nonce = todo[0:12]
file_tag = todo[12:28]
file_content = todo[28:]

cipher = AES.new(file_encryption_key, AES.MODE_GCM, file_nonce)
decrypted_file_content = cipher.decrypt_and_verify(file_content, file_tag)
print(decrypted_file_content.decode())
