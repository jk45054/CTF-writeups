# Flare-On 10, Challenge 11, over_the_rainbow
#
# Retrieve the flag by decrypting the encrypted challenge file
# With Sage maths, we already "broke" the weak RSA usage
# And got the key material
#
# It consists of 24 bytes XOR key and 64 bytes ChaCha20 init state
# 
from binascii import unhexlify
from itertools import cycle

def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])

# Result of m calculated via online sage
m = unhexlify(
    "06f7768ff2b963f356fc25b3443f7b729f68bcbdd65f22de685c3cb5c8a2697224368530e264fd388dc962f5d737cb873e24f39709d294224a5268c3512ddb6b3e54419b41c810cf657870616e642033322d62797465206b"
)

# Get encrypted file contents (challenge file minus 0x100 bytes suffix)
with open("../files/very_important_file.d3crypt_m3", "rb") as f:
    crypted_file_contents = f.read()
f.close()
c_flag_chacha20 = crypted_file_contents[:-0x100]
assert c_flag_chacha20 == unhexlify(
    "3d77b35daddbf4f9cb95a20d0ba0055e03aad1ed96aa9ba67a5d1d14106a2f7ea5c0613318d51971a6a759e90433f5577557bc161ab77c85c728917659"
)

xor_key = m[0:24]
assert xor_key == unhexlify("06f7768ff2b963f356fc25b3443f7b729f68bcbdd65f22de")

chacha_init_state = m[24:]
assert chacha_init_state == unhexlify("685c3cb5c8a2697224368530e264fd388dc962f5d737cb873e24f39709d294224a5268c3512ddb6b3e54419b41c810cf657870616e642033322d62797465206b")

# Use above ChaCha20 init state with binary refinery to recover flag bytes
# Or instrument the challenge binary to do so (patching buffers)
# $ emit 3d77b35daddbf4f9cb95a20d0ba0055e03aad1ed96aa9ba67a5d1d14106a2f7ea5c0613318d51971a6a759e90433f5577557bc161ab77c85c728917659 | hex | chacha h:685c3cb5c8a2697224368530e264fd388dc962f5d737cb873e24f39709d294224a5268c3512ddb6b3e54419b41c810cf657870616e642033322d62797465206b | hex -R
# 519643E186E6179B678F7AE0314F0B42EC5BD8E2A26F7DBC35A842D0808A1596248F14DD0360181AAB048DD8B838119E609B17FD97940C9D789F4ADE4E

c_flag_xor = unhexlify("519643E186E6179B678F7AE0314F0B42EC5BD8E2A26F7DBC35A842D0808A1596248F14DD0360181AAB048DD8B838119E609B17FD97940C9D789F4ADE4E")

flag_bytes = bxor(c_flag_xor, xor_key)
print(f"Flag: {flag_bytes.decode('UTF-8')}")
