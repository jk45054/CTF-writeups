#!/usr/bin/env python3
import sys

with open(sys.argv[1], "rb") as f:
    crypted_flag = f.read()

decrypted_flag = bytearray(len(crypted_flag))

# set initial XOR value
XOR_value = 0xA5 ^ len(crypted_flag)

for i in range(len(crypted_flag)):
    decrypted_flag[i] = crypted_flag[i] ^ XOR_value
    XOR_value <<= 2
    XOR_value ^= crypted_flag[i]
    XOR_value += 2
    XOR_value &= 0xFF

print(decrypted_flag)
