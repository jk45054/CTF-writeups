# Flare-On 10, Challenge 4, aimbot
#
# Bruteforce last 4 characters of AES key
# To decrypt DLL payload
#

from itertools import product
from string import ascii_letters, digits, printable
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

key_prefix = '"version": "'
known_plaintext = b"the decryption of this blob was successful"
alphabet = digits + "."
# alphabet = printable

with open("./program/aimbot_dll_payload_0xa6340_size_0x4470.bin", "rb") as f:
    ciphertext = f.read(16)
f.close()

print("Bruteforcing last 4 characters of AES key")
i = 0
for key_suffix in product(alphabet, repeat=4):
    i += 1
    key = bytes(key_prefix + "".join(key_suffix), "UTF-8")
    # if i % 100000 == 0:
    # print(f"{i}, {key}")
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    if plaintext == known_plaintext[:16]:
        print(f"Success, key = {key}")
        break

print("Decrypting aimbot.dll payload")
# read encrypted aimbot dll payload
with open("./program/aimbot_dll_payload_0xa6340_size_0x4470.bin", "rb") as f:
    ciphertext = f.read()
f.close()

# decrypt with bruteforced key
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
# calc SHA256 of decrypted payload
h = SHA256.new()
h.update(plaintext)

print(f"SHA256 = {h.hexdigest()}")
with open("./program/aimbot_dll_payload_0xa6340_size_0x4470_decrypted.bin", "wb") as f:
    f.write(plaintext)
f.close()
