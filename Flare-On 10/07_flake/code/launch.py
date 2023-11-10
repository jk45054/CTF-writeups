# Flare-On 10, Challenge 7, flake
#
# Launcher script that will
# - Generate a flake configuration file with given arguments
#   - This allows to fulfill the first winning condition
#   - attaining a high score > 10k
#
# Requirements
# - Has to be run on the unpacked flake.exe, not the
#   - packed challenge file
#

from base64 import b64encode
from json import dumps
from itertools import cycle
from subprocess import run
from os import chdir
import sys


def bxor(input: bytes, key: bytes) -> bytes:
    return bytes([c ^ k for c, k in zip(input, cycle(key))])


def gen_config(title: str, o1: int, o2: int, o3: int) -> bytes:
    xor_key = b"\x22\x11\x91\xff"
    config_dict = {"0": title, "1": o1, "2": o2, "3": o3}
    config = dumps(config_dict, separators=(",", ":"))
    bconfig = config.encode("UTF-8")
    xor_bconfig = bxor(bconfig, xor_key)
    return b64encode(xor_bconfig)


def write_config(filename: str, enc_config: bytes):
    with open(filename, "wb") as f:
        f.write(enc_config)
    f.close()


# Main ###
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(
            f"Usage: {sys.argv[0]} window_title_string amount_of_food starting_score score_per_food"
        )
        sys.exit(1)
    if sys.argv[1] == "def":
        title_string = "FLAKE Ultimate Pro v10"
    else:
        title_string = sys.argv[1]
    # generate d3m0_c0nf.txt, patch and launch flake.exe
    conf_filename = "../files/unpacked/d3m0_c0nf.txt"
    print(f"[*] Generating {conf_filename} with given parameters")
    encrypted_config = gen_config(
        title_string, int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    )
    # write config
    write_config(conf_filename, encrypted_config)
    # launch game
    chdir("../files/unpacked/")
    print(f"Launching flake.exe with config: {encrypted_config}")
    run(["flake.exe"])
