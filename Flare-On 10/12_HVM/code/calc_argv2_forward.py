# Flare-On 10, Challenge 12, HVM
#
# Forward implementation of the inner loop decryption function 421
#
# The second command-line argument - argv2 - is base64 decoded first
# And then decrypted in chunks of 16 bytes
# Each chunk operation is applied in QWORD size (8 bytes)
#
# Would the chunk result be the same for the same input chunk?  yes.
# Example:
# - using AAAABBBBCCCCDDDD x 3
# - yields F8 3E 43 E9 2B A1 6C C9 00 63 26 F7 6B 82 0A 7E x 3
#
# High level code logic for forward implemenation
#
# - outer loop j = 0, 2, 4 (function 4AF)
#   - inner loop i = 7..0 (function 421)
#        - calcs buf[ j*8 ] ^ buf[ (j+1) * 8 ] ^ salsa_block[ i*8 ]
#        - overwrites buf[ j*8 ] with last XOR result
#        - overwrites buf[ (j+1) * 8 ] with previously saved buf[ j*8 ]

from binascii import unhexlify

# Define salsa_keystream s for given init state of
# FLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLAR
#
# Can be achieved via debugging / breakpoint after call to function A7
# or with Binary Refinery
# $ emit 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 | hex | salsa FLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLARFLAR | hex -R
# 026124F56D840C78FAFA18A3B91C245FB91C245F026124F56D840C78FAFA18A3FAFA18A3B91C245F026124F56D840C786D840C78FAFA18A3B91C245F026124F5
s = unhexlify(
    "026124F56D840C78FAFA18A3B91C245FB91C245F026124F56D840C78FAFA18A3FAFA18A3B91C245F026124F56D840C786D840C78FAFA18A3B91C245F026124F5"
)
# One 16 byte chunk of buf / the b64decoded argv2
buf = bytearray(b"AAAABBBBCCCCDDDD")
print(
    f"---\nForward implementation of inner XOR loop / sub 421 for 16 bytes input chunk of {buf}"
)
# j is the outer loop counter (function 4AF)
# For processing just one chunk, j is 0
j = 0
# Inner loop (function 421)
for i in range(7, -1, -1):
    print(f"----\ni={i}")
    # Temporarily save buf[ j*8 ], the first half/QWORD of this chunk
    temp_q1_i_prev_bytes = buf[j * 8 : j * 8 + 8]
    print(f"temp_q1 = {temp_q1_i_prev_bytes.hex()} (bytes value = reversed endianness)")
    # Convert this QWORD to bytes
    q1_i_prev = int.from_bytes(temp_q1_i_prev_bytes, "little")
    print(f"q1_i_prev = {hex(q1_i_prev)}")
    # Get the second half/QWORD of this chunk
    q2_i_prev = int.from_bytes(buf[(j + 1) * 8 : (j + 1) * 8 + 8], "little")
    print(f"q2_i_prev = {hex(q2_i_prev)}")
    # Get the i-th QWORD of the salsa keystream
    s_i = int.from_bytes(s[i * 8 : i * 8 + 8], "little")
    print(f"s[{i}] = {hex(s_i)}")
    # Calculate temp = buf[ j*8 ] ^ buf[ (j+1) * 8 ] ^ salsa_keystream[ i*8 ]
    # This is going to overwrite buf[ j*8 ]
    q1_i = int.to_bytes(q1_i_prev ^ q2_i_prev ^ s_i, 8, "little")
    print(
        f"q1_i = {hex(q1_i_prev)} ^ {hex(q2_i_prev)} ^ {hex(s_i)} = {q1_i.hex()} (bytes value = reversed endianness)"
    )
    # Overwrite buf[ j*8 ] with temp = buf[ j*8 ] ^ buf[ (j+1) * 8 ] ^ salsa_keystream[ i*8 ]
    buf[j * 8 : j * 8 + 8] = q1_i
    # Overwrite buf[ (j+1) * 8 ] with preserved buf[ j*8 ]
    buf[(j + 1) * 8 : (j + 1) * 8 + 8] = temp_q1_i_prev_bytes
    print(f"q2_i = {temp_q1_i_prev_bytes.hex()} (bytes value = reversed endianness)")

# From debug run with input AAAABBBBCCCCDDDD
# We know that an iteration of the outer loop j
# yields f83e43e92ba16cc9006326f76b820a7e
assert bytes(buf) == unhexlify("f83e43e92ba16cc9006326f76b820a7e")
