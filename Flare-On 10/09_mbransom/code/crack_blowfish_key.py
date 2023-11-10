# Flare-On 10, Challenge 9, mbransom
#
# Crack the blowfish key bytes that may have been corrupted
#

from binascii import hexlify, unhexlify
from itertools import cycle
from Crypto.Cipher import Blowfish


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


# Main
if __name__ == "__main__":
    victim_id = unhexlify("3487B3B41F20")
    # These might have been corrupted
    victim_id_suffix = b"\x90\x90"
    xor_key = b"\x55"
    blowfish_key = (
        bxor(victim_id + victim_id_suffix, xor_key) + victim_id + victim_id_suffix
    )
    # Blowfish key derived from partially corrupted victim ID bytes
    assert blowfish_key == unhexlify("61d2e6e14a75c5c53487b3b41f209090")
    # this key passes the "validation" check (victim id xor 0x55)
    # but it fails the "correctness" check (blowfish encrypt Test Str)
    test_str_plain = b"Test Str"
    test_str_cipher = unhexlify("2E2157823EA96C6E")  # 2E 21 57 82 3E A9 6C 6E
    # set up blowfish
    bs = Blowfish.block_size
    cipher = Blowfish.new(blowfish_key, Blowfish.MODE_ECB)
    # to decrypt arbitrary messages, they would need to be padded to block size
    # Test Str conveniantly fulfills that
    assert len(test_str_plain) == bs
    # test that our code yields the same ciphertext from debug run
    enc_test_str = cipher.encrypt(test_str_plain)
    assert enc_test_str == unhexlify("a7759d9fafd20ab4")
    # this is obviously not the same expected ciphertext as checked in the program
    # so we have to crack 2 bytes of the key at offset 6 and 7 (c5 c5)
    # and make sure that the correspondingbytes at offset 14/15 match these XOR 0x55
    cur_key = bytearray(blowfish_key)
    for attempt in range(65536):
        cur_bytes = attempt.to_bytes(2, "little")
        cur_key[6:8] = cur_bytes
        # key offset 6 = key offset 14 ^ 0x55
        # key offset 7 = key offset 15 ^ 0x55
        cur_key[14] = cur_key[6] ^ int.from_bytes(xor_key)
        cur_key[15] = cur_key[7] ^ int.from_bytes(xor_key)
        # create the cipher with this iteration's key, encrypt test string and compare result
        cipher = Blowfish.new(cur_key, Blowfish.MODE_ECB)
        enc_attempt = cipher.encrypt(test_str_plain)
        if enc_attempt == test_str_cipher:
            print(
                f"[*] YAY, found key {hexlify(cur_key)}, decryption key = {hexlify(cur_key[0:8])}, cipher = {hexlify(enc_attempt)}"
            )

    # interact(local=locals())
