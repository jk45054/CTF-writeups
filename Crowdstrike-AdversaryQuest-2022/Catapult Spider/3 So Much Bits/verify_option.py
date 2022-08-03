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

# Verify option (nonce, key, tag) and (nonce, tag, key)
file_path = "/home/challenge/notes/todo.txt.enc"

key_option_1 = "40e0e8690efcf4f60a0963e80e741c05"
possible_encrypted_key_option_1 = unhexlify("e7528b60753330a0ba74e24e4d2cef86")
key_option_2 = "a4c24b93fd9b12719400b635afa07282"
possible_encrypted_key_option_2 = unhexlify("8f5a76011d5b5bd5f7ddc6f25fdb1b42")

key_db_1 = get_encrypted_key_db([["unknown", unhexlify(key_option_1), file_path]])
key_db_2 = get_encrypted_key_db([["unknown", unhexlify(key_option_2), file_path]])

if key_db_1[16:32] == possible_encrypted_key_option_1:
  print("[*] Successfully verified option 1")
  print(f"[=] Recovered file encryption key {key_option_1}")

if key_db_2[32:48] == possible_encrypted_key_option_2:
  print("[*] Successfully verified option 2")
  print(f"[=] Recovered file encryption key {key_option_2}")


