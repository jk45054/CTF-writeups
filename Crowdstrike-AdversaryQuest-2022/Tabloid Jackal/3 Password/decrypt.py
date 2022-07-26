#!/usr/bin/env python3

class PRNG_with_state_1651(object):
  def __init__(self, PRNG_state_value_1, PRNG_state_value_2, PRNG_state_value_3, PRNG_state_value_4):
    self.PRNG_state_value_1 = PRNG_state_value_1
    self.PRNG_state_value_2 = PRNG_state_value_2
    self.PRNG_state_value_3 = PRNG_state_value_3
    self.PRNG_state_value_4 = PRNG_state_value_4

  def next(self):
    self.PRNG_state_value_1 = (69069 * self.PRNG_state_value_1 + 12345) & 0xffffffff
    self.PRNG_state_value_2 ^= (self.PRNG_state_value_2 << 13) & 0xffffffff
    self.PRNG_state_value_2 ^= (self.PRNG_state_value_2 >> 17) & 0xffffffff
    self.PRNG_state_value_2 ^= (32 * self.PRNG_state_value_2) & 0xffffffff
    temp = 698769069 * self.PRNG_state_value_3 + self.PRNG_state_value_4
    self.PRNG_state_value_4 = temp >> 0x20
    self.PRNG_state_value_3 = temp & 0xffffffff
    return ((self.PRNG_state_value_2 + self.PRNG_state_value_1 + self.PRNG_state_value_3) & 0xffffffff)

def decrypt(buffer):
  PRNG = PRNG_with_state_1651(0x43525744, 0x159a55a0, 0x1f123bb5, 0x74cbb1)
  payload = bytearray()
  for j in range(len(buffer) >> 1):
    random = PRNG.next()
    XOR_key = (random & 0xff000000) >> 24 ^ (random & 0xff0000) >> 16 ^ (random & 0xff00) >> 8 ^ (random & 0xff)
    high_nibble = ord(chr(buffer[j * 2])) - ord('a')
    low_nibble = ord(chr(buffer[j * 2 + 1])) - ord('a')
    cipher_char = (high_nibble << 4) + low_nibble
    payload.append(XOR_key ^ cipher_char)
  return (payload)

print(decrypt(b"icadgbcnodimdjbeokbnnkajlcojablkicbedjmmhnklbjbboljk"))
