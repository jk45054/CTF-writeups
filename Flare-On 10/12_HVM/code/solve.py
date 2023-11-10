# Flare-On 10, Challenge 12, HVM
#
# Final script to calculate the necessary argv2 value
# In order to decrypt to argv1 + 12 null bytes
#
# We then launch hvm.exe with both arguments to retrieve the flag
# We would not need to, if we just carve the encrypted
# Flag bytes and XOR them with the correct value of argv2
#

from binascii import unhexlify
from base64 import b64encode
from itertools import cycle
from subprocess import run


class salsa:
    # Helper class to retrieve qword values from the Salsa20 keystream
    s = b""

    def __init__(self):
        self.s = unhexlify(
            "026124F56D840C78FAFA18A3B91C245FB91C245F026124F56D840C78FAFA18A3FAFA18A3B91C245F026124F56D840C786D840C78FAFA18A3B91C245F026124F5"
        )

    def get_int(self, qword_index: int) -> int:
        return int.from_bytes(self.s[qword_index * 8 : qword_index * 8 + 8], "little")

    def get_bytes(self, qword_index: int) -> bytes:
        return self.s[qword_index * 8 : qword_index * 8 + 8]


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


# Main
if __name__ == "__main__":
    # Challenge executable
    filename = "../challenge_files/hvm.exe"

    # First argument / argv1
    #
    # From function 918 (check argv1) and function B3F (main) we know
    # That a string compare between argv1 and the result of
    # `*#37([@AF+ .  _YB@3!-=7W][C59,>*@U_Zpsumloremips`
    # ^ `loremipsumloremipsumloremipsumloremipsumloremips`
    # Should match for the first 36 characters
    argv1_bytes_w_padding = bxor(
        b"*#37([@AF+ .  _YB@3!-=7W][C59,>*@U_Zpsumloremips",
        b"loremipsumloremipsumloremipsumloremipsumloremips",
    )
    argv1_str = argv1_bytes_w_padding[0:36].decode("UTF-8")
    assert argv1_str == "FLARE2023FLARE2023FLARE2023FLARE2023"

    # Second argument / argv2
    #
    # the base64 decoded and decrypted argv2 value has to match
    # With the result of the above xor
    target_chunks = argv1_bytes_w_padding
    no_chunks = len(target_chunks) // 16
    sal = salsa()
    # print(f"---\nCalc'ing substituted equations to get argv2 input for c = {c.hex()}")
    argv2_binary = bytearray(no_chunks * 16)
    for j in range(0, no_chunks * 2, 2):
        #    print(f"---\nj={j}")
        q1_0_j = int.from_bytes(target_chunks[j * 8 : j * 8 + 8], "little")
        #    print(f"q1_0 = {int.to_bytes(q1_0_j, 8, 'little').decode('UTF-8')}")
        q2_0_j = int.from_bytes(target_chunks[(j + 1) * 8 : (j + 1) * 8 + 8], "little")
        #    print(f"q2_0 = {int.to_bytes(q2_0_j, 8, 'little').decode('UTF-8')}")
        q2_buf_j = (
            q1_0_j
            ^ sal.get_int(0)
            ^ sal.get_int(1)
            ^ sal.get_int(3)
            ^ sal.get_int(4)
            ^ sal.get_int(6)
            ^ sal.get_int(7)
        )
        q1_buf_j = (
            q1_0_j
            ^ q2_0_j
            ^ sal.get_int(0)
            ^ sal.get_int(2)
            ^ sal.get_int(3)
            ^ sal.get_int(5)
            ^ sal.get_int(6)
        )
        argv2_binary[j * 8 : j * 8 + 8] = int.to_bytes(q1_buf_j, 8, "little")
        argv2_binary[(j + 1) * 8 : (j + 1) * 8 + 8] = int.to_bytes(
            q2_buf_j, 8, "little"
        )
    # Finally base64 encode the value
    argv2 = b64encode(argv2_binary).decode("UTF-8")

    # Print the calculated argvs
    print(f"argv1 = {argv1_str}")
    print(f"argv2_binary = {argv2_binary.hex()}")
    print(f"argv2_base64 = {argv2}")

    # Run hvm.exe to get the flag
    run([filename, argv1_str, argv2])
