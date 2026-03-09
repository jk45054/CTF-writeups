from Crypto.Hash import MD5, SHA256
from binascii import crc32
from string import printable
from itertools import product

for sequence in product(printable, repeat=2):
    bytes = "".join(sequence).encode('utf-8')
    # do the calcs
    crc32_hash = crc32(bytes)
    m = MD5.new(bytes)
    md5_hash = m.hexdigest()
    s = SHA256.new(bytes)
    sha256_hash = s.hexdigest()

    if crc32_hash == 0x61089c5c or crc32_hash == 0x5888fc1b or crc32_hash == 0x66715919 or crc32_hash == 0x7cab8d64:
        print(f"crc32({bytes}) = {hex(crc32_hash)}")

    if md5_hash == "89484b14b36a8d5329426a3d944d2983" or md5_hash == "f98ed07a4d5f50f7de1410d905f1477f" or md5_hash == "657dae0913ee12be6fb2a6f687aae1c7" or md5_hash == "738a656e8e8ec272ca17cd51e12f558b":
        print(f"md5({bytes}) = {md5_hash}")
    
    if sha256_hash == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f" or sha256_hash == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6":
        print(f"sha256({bytes}) = {sha256_hash}")
