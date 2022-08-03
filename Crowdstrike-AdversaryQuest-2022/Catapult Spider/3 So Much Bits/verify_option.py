#!/usr/bin/env python3

import requests
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from code import interact

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

# Verify option (nonce, key, tag) and (nonce, tag, key)
file_path = "/home/challenge/notes/todo.txt.enc"

# Send null key
nullkey_keys_db = get_encrypted_key_db([["unknown", b"\x00" * 16, file_path]])

offset_16_to_32 = nullkey_keys_db[16:32]
offset_32_to_48 = nullkey_keys_db[32:48]

# option 1 (nonce, key, tag)
possible_plaintext_key_option_1 = bytearray([x^y for x,y in zip(offset_16_to_32, local_keys_db[16:32])])
option1_keys_db = get_encrypted_key_db([["unknown", possible_plaintext_key_option_1, file_path]])
if local_keys_db[16:32] == option1_keys_db[16:32]:
  print("[*] Successfully verified option 1")
  print(f"[=] Recovered file encryption key {hexlify(possible_plaintext_key_option_1)}")

# option 2 (nonce, tag, key)
possible_plaintext_key_option_2 = bytearray([x^y for x,y in zip(offset_32_to_48, local_keys_db[32:48])])
option2_keys_db = get_encrypted_key_db([["unknown", possible_plaintext_key_option_2, file_path]])
if local_keys_db[32:48] == option2_keys_db[32:48]:
  print("[*] Successfully verified option 2")
  print(f"[=] Recovered file encryption key {hexlify(possible_plaintext_key_option_2)}")

