# Crowdstrike Adversary Quest 2022 / Tabloid Jackal / #1 display0

## Challenge Description

We were approached by our customer "Daily Code" who detected suspicious activity on a VPN gateway. One of their sysadmins did some basic inspection of the system and was able to discover an unknown ELF binary.

For further analysis, the sysadmin sent us the ELF alongside an asciinema recording of their terminal session.

Note: Flags will be easily identifiable by the format “CS{some_secret_flag_text}”. They must be submitted in full, including “CS{“ and “}”).

## Analysis

**TODO**

### Python Implementation

See [solve.py](./solve.py) for the fully automated solution script.

## Now it's Flag Time!

```console
$ ./solve.py 
[*] Hashing Target OS Environment Data with SHA256 = fd25e9429d731f5b905a848f66675a3fdbfd028ef320d0497d80de1a0445bf22
[*] Using first 16 bytes of it as AES key = b'\xfd%\xe9B\x9ds\x1f[\x90Z\x84\x8ffgZ?'
[*] Carving Encrypted Payload from ELF binary display0 (offset = 0x40e0, len = 0x7c8d8)
[*] Decrypting Payload with AES-128-CTR... succeeded!
[*] Searching decrypted payload for the flag... succeeded!
[*] Flag = CS{3nc_b1nd_sh3ll}
```

Flag = **CS{3nc_b1nd_sh3ll}**
