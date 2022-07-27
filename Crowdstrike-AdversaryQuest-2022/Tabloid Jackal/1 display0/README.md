## Flag

See [solve.py](./solve.py) for the fully automated solution script.

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
