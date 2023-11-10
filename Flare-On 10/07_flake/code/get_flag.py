# Flare-On 10, Challenge 7, flake
#
# Path 2: Decrypt the flag from the unpacked flake.exe
# The flag is encrypted with RC4
# The RC4 key is encrypted with an XOR key
#

from Crypto.Cipher import ARC4
from itertools import cycle
from struct import unpack
from binascii import unhexlify


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


# Main ###
if __name__ == "__main__":
    # Open the unpacked flake.exe
    flake_filename = "../files/flake.exe"
    with open(flake_filename, "rb") as f:
        # Grab the pylong values used as the key encryption key
        f.seek(0x9163D2)
        kek_raw = f.read(0x14)
        kek_list = unpack("<xLxLxLxL", kek_raw)
        kek = bytes(kek_list)
        assert kek == unhexlify("1BBA8C1B")
        # Grab the encrypted RC4 key bytes
        f.seek(0x916933)
        encrypted_key = f.read(0x32)
        assert encrypted_key == unhexlify(
            "5400C68867F95F6E787D915D58B25E675BF4308630E44419EA941336976DC9D8B9723F28E8EA0D33928EA903EFA88E9DB783"
        )
        # Grab the encrypted flag
        f.seek(0x91680E)
        encrypted_flag = f.read(0x22)
        assert encrypted_flag == unhexlify(
            "BB68D55088C3241B4DDCC29D89AA664778A6DB8202C656CEBB95407F272A60EEC069"
        )
    f.close()
    # Decrypt the RC4 key
    key = bxor(encrypted_key, kek)
    # Decrypt the flag
    cipher = ARC4.new(key)
    flag_bytes = cipher.decrypt(encrypted_flag)
    print(f"Flag: {flag_bytes.decode('UTF-8')}")

# > py .\get_flag.py
# Flag: b'n0Pe_N0t_T0dAy_Nu1TkA@flare-on.com'
