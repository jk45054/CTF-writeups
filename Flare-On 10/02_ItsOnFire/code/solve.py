# Flare-On 10, Challenge 2, ItsOnFire
#
# Rebuild AES Key/IV from strings
# And decrypt the flag picture
#

from binascii import crc32
from Crypto.Cipher import AES
from code import interact

var_c2 = "https://flare-on.com/evilc2server/report_token/report_token.php?token="
var_O = "wednesday"
crc32_val = crc32(bytes(var_c2[4:10] + var_O[2:5], "UTF-8"))
interact(local=locals())
crc32_str = str(crc32_val)
key_str = (crc32_str + crc32_str)[0:16]
t = "abcdefghijklmnop"
iv = bytes(t, "UTF-8")
key = bytes(key_str, "UTF-8")
cipher = AES.new(key, AES.MODE_CBC, iv)
with open("../files/a.png", "rb") as f:
    ciphertext = f.read()
f.close()
plaintext = cipher.decrypt(ciphertext)
with open("../files/a_decrypted.png", "wb") as f:
    f.write(plaintext)
f.close()
