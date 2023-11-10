# Flare-On 10, Challenge 12, HVM
#
# Implementation of the unrolled inner loop function 421
# Through formula substitution
#

from binascii import unhexlify
from base64 import b64encode


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


# Main
if __name__ == "__main__":
    # Instantiate the Salsa20 keysteam getter class
    sal = salsa()

    # The inner loop (function 421)  can be unrolled with formula substitution
    #
    # q1_0 = q2_buf ^ s0 ^ s1 ^ s3 ^ s4 ^ s6 ^ s7
    # q2_0 = q1_buf ^ q2_buf ^ s1 ^ s2 ^ s4 ^ s5 ^ s7
    #
    # q1/2_buf -> input chunk from base64 decoded argv2
    # q1/2_0   -> target values
    #
    # We know from the forward implementation, that chunk
    # AAAABBBBCCCCDDDD decrypts to f83e43e92ba16cc9006326f76b820a7e
    #
    # If our formula is correct, we can from a given "target" value
    # of f83e43e92ba16cc9006326f76b820a7e calculate the necessary
    # input AAAABBBBCCCCDDDD

    c = unhexlify("f83e43e92ba16cc9006326f76b820a7e")
    print(f"---\nCalc'ing substituted equations to get argv2 input for chunk = {c.hex()}")
    # Limit to one chunk, size 16 bytes, assume outer loop counter variable j = 0
    argv2_binary = bytearray(16)
    j = 0
    print(f"---\nj={j}")
    q1_0_j = int.from_bytes(c[j * 8 : j * 8 + 8], "little")
    print(f"q1_0 = {hex(q1_0_j)}")
    q2_0_j = int.from_bytes(c[(j + 1) * 8 : (j + 1) * 8 + 8], "little")
    print(f"q2_0 = {hex(q2_0_j)}")
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
    print(f"argv2_binary = {argv2_binary.decode('UTF-8')}")
    print(f"argv2_base64 = {b64encode(argv2_binary)}")
