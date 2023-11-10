# Flare-On 10, Challenge 11, over_the_rainbow
#
# Online Sage script to retrieve RSA encrypted plaintext message
# Implements Coppersmith Stereotyped Message attack
# Use with https://sagecell.sagemath.org/
# 
# --- Begin Online Sage script ---
# c, the ciphertext (0x100 bytes file suffix)
c = 0x1336e28042804094b2bf03051257aaaaba7eba3e3dd6facff7e3abdd571e9d2e2d2c84f512c0143b27207a3eac0ef965a23f4f4864c7a1ceb913ce1803dba02feb1b56cd8ebe16656abab222e8edca8e9c0dda17c370fce72fe7f6909eed1e6b02e92ebf720ba6051fd7f669cf309ba5467c1fb5d7bb2b7aeca07f11a575746c1047ea35cc3ce246ac0861f0778880d18b71fb2a8d7a736a646cf99b3dcec362d413414beb9f01815db7f72f6e081aee91f191572a28b9576f6c532349f8235b6daf31b39b5add7ade0cfbd30f704eb83d983c215de3261f73565843539f6bb46c9457df16e807449f99f3dabdddd5764fd63d09bc9c4e6844ec3410dc821ab4
# N, the modulus (from public certificate)
N = 0xc9c330728f68087afc60a133e49b9d3de49f0ff9995c5e12e5c65c11897bc718e3e4d272d5a58ce463755b2c63467f0d09f93c31cb67fe318809af7fc8b2c8c721ab547ce4db63dbdfff5d9b06c85799fdee690f90c479c6d0b9e3a3f66e55d63029ce5a02ef84c6aadc5e2241683024cc65d75642afe0babe76f29a677ceb159be48bb3265ebd2bd519a2af7e036cc2e6401c37555761a81c3d1d28a456c38b91b559035bff013dda0439053b9e96f4b278f719e939e677d058bc6e98005aff230814a497ab34b7fa902b666d180de84e24e90f753d79db0b7217acb5c46f4d1aa56bee573f2d47a4337ddd1e2b967edc7038feeb090dec7492d94d9689bb61
# e, the public exponent
e = 3
# m_suffix, the known plaintext message suffix ("expand 32-byte k")
m_suffix = 0x657870616E642033322D62797465206B

# (Online) sage magics
P.<x> = PolynomialRing(Zmod(N))
# We apply a 128 bit shift because we know the lower 128 bit of m
# are the known plaintext suffix m_suffix
# 16 byte * 8 bit/byte = 128 bit
m_shift = 2^128
# c = m^e mod N
# We try to solve m^e - c = 0 now
# With m consisting of unknown part x and known part m_suffix
poly = (x * m_shift + m_suffix)^e - c
poly = poly.monic()
roots = poly.small_roots(epsilon=1/20)
# p[0] is the (first) function solution for m_unk
# Let's test if p[0] is our correct m_unk
m_test = roots[0] * m_shift + m_suffix

# Proof that our found p[0] aka m_unk yields a true solution
c_test = m_test^e % N
assert c_test == c
print(hex(m_test))
# --- End Online Sage script ---

# Yields
# 0x6f7768ff2b963f356fc25b3443f7b729f68bcbdd65f22de685c3cb5c8a2697224368530e264fd388dc962f5d737cb873e24f39709d294224a5268c3512ddb6b3e54419b41c810cf657870616e642033322d62797465206b
