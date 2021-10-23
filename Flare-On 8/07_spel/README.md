# Flare-On 8, Challenge 7, spel

## Task

Pro-tip: start disassembling this one then take a nice long break, you've earned it kid.

## Files

Filename | Size | SHA256
--- | --- | ---
spel.exe | 4,376,064 bytes | 06221EF03A2F5B4F65C14E258096D02C37282E4440C0ECE0E730DFDD7A748E9A

## High Level Summary

- spel.exe is a 64 Bit Windows PE executable displaying an error message in a gui window when executed.
- It also executes nested stages of code.
  - Stage 1 is 192,512 bytes of Shellcode located in a stack string, which significantly slowed down disassembly in IDA Pro's default configuration.
    - The Shellcode reflectively loads an intermediate payload DLL of size 191,779 bytes.
  - Stage 2 (intermediate payload DLL)
    - Contains code in `DllMain` to reflectively load the final payload DLL of size 96,768 bytes and calls it's exported function `Start`.
  - Stage 3 (final payload DLL)
    - The final payload contains partly obfuscated code, dynamically resolving API functions by hash value (rol7+xor)
    - It contains irrelevant C2 functionality to a server named `inactive.flare-on.com` using UDP port 888.
      - It would be possible to setup a mock server and transfer shellcode to the final payload, but that's a possible rabbit hole.
    - The flag suffix **flare-on.com** is encrypted and saved in the registry as value name '1'.
      - Registry interaction is irrelevant as well.
    - The flag prefix is derived in two steps.
      - The ASCII string `l3rlcps_7r_vb33eehskc3` is decrypted with AES-CBC-256 from the 214 bytes sized rsrc id 128 of spel.exe (offset 0x5F, size 0x20).
      - This string is processed in a "switch loop", where the order to character accessing yields the correct prefix `b3s7_sp3llcheck3r_ev3r`.
- The flag is `b3s7_sp3llcheck3r_ev3r@flare-on.com`.
