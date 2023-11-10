# Flare-On 10, Challenge 10, kupo
#
# input: c10.Z compressed challenge file
# extracts crypted flag
# decrypts it with ken thompson's password p/q2-q4!
# decodes it
# - which is just an adder. like a prefix sum mod 256
# - adds the last char code value to the current
#

from binascii import hexlify
from binascii import unhexlify
from itertools import cycle
from unlzw3 import unlzw


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


def decode(input: bytes) -> bytes:
    result = bytearray(len(input))
    cur_byte = 0
    for i in range(len(input)):
        # print(f"{i} {cur_byte} {input[i]} -> ", end="")
        cur_byte = (input[i] + cur_byte) & 0xFF
        # print(f"{cur_byte}")
        result[i] = cur_byte
    return bytes(result)


# Main
if __name__ == "__main__":
    # read compressed challenge file
    with open("../files/c10.Z", "rb") as f:
        c10z = f.read()
    f.close()
    # uncompress it
    c10 = unlzw(c10z)
    assert c10[:2] == b"\x07\x01"
    # extract len of crypted flag bytes
    flag_len = int.from_bytes(c10[0xAB8 : 0xAB8 + 2], "little")
    assert flag_len == 0x2E
    # extract flag
    crypted_flag = c10[0xAB8 + 2 : 0xAB8 + 2 + flag_len]
    assert crypted_flag == unhexlify(
        "1bd578c32f7cc2da752e7832d67bd8237dd98a313d86cc2c812d7cc4d6743f2782f65734d860c7e932d0b107218f"
    )
    print(f"[*] Crypted flag: {hexlify(crypted_flag)}")
    # decrypt flag with ken thompson's password
    decrypted_flag = bxor(crypted_flag, b"p/q2-q4!")
    print(f"[*] Derypted flag: {hexlify(decrypted_flag)}")
    assert decrypted_flag == unhexlify(
        "6bfa09f1020df6fb05010900fb0aec020df6fb0310f7f80df1020df6fb050b06f2d92606f511f3c842ffc0350cfe"
    )
    # decode flag
    flag = decode(decrypted_flag)
    print(f"[*] Decoded Flag: {flag}")
