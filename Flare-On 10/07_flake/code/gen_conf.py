# Flare-On 10, Challenge 7, flake
#
# Generate a valid flake configuration file
# Based on command line arguments
#

from base64 import b64encode
from json import dumps
from itertools import cycle
import sys


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


def gen_config(title: str, o1: int, o2: int, o3: int) -> bytes:
    # Decrypted demo file
    # {"0":"FLAKE Ultimate Pro v10 (Demo)","1":5,"2":0,"3":2}
    xor_key = b"\x22\x11\x91\xff"
    config_dict = {"0": title, "1": o1, "2": o2, "3": o3}
    config = dumps(config_dict, separators=(",", ":"))
    bconfig = config.encode("UTF-8")
    xor_bconfig = bxor(bconfig, xor_key)
    return b64encode(xor_bconfig)


# Main ###
if __name__ == "__main__":
    # param 1 = window title
    # param 2 = amount of food (max = 10)
    # param 3 = starting score
    # param 4 = score per food
    if len(sys.argv) != 5:
        print(
            f"Usage: {sys.argv[0]} window_title_string amount_of_food starting_score score_per_food"
        )
        sys.exit(1)
    if sys.argv[1] == "def":
        title_string = "FLAKE Ultimate Pro v10"
    else:
        title_string = sys.argv[1]
    encrypted_config = gen_config(
        title_string, int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    )
    print(encrypted_config.decode("UTF-8"))
