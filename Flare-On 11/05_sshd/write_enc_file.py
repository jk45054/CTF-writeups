from binascii import unhexlify

ciphertext = unhexlify("a9f63408422a9e1c0c03a8089470bb8daadc6d7b24ff7f247cda839e92f7071d0263902ec158")
filename = "/tmp/enc.bin"

with open(filename, "wb") as f:
    f.write(ciphertext)
f.close()

