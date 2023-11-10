# Flare-On 10 (2023)

Google Mandiant hosted their 10th [Flare-On CTF](http://flare-on.com) this year running from 2023-09-30 to 2023-11-11.

It consisted of 13 Reverse Engineering challenges ranging from mostly Windows executables (incl. obfuscation, multi-stage shellcodes), an Android App, 16 Bit DOS nostalgica (incl. a boot sector ransomware), a just-in-time code decrypting Windows Hypervisor guest partition and a Forth environment (in a 2.11BSD OS). Also included quite some crypto puzzling.

All-in-all it has been a blast participating, best CTF of the year! Thanks to everyone at Google Mandiant that makes this awesome go-to CTF event possible year after year, keep it up - especially the increased difficulty.

## Write-Ups

My write-ups (and more or less raw/dirty notes) for all challenges can be found here. The most detailed and polished ones are for challenges 7, 10, 12 and 13. For everything else I included extracted files, code snippets (IDA plugins/scripts, flag decryption) and *raw* notes.

Ch# | Name | Type | Notes | Polished Solution
--- | --- | --- | --- | ---
1 | [X](./01_X/) | .NET Core AppHost | Just a Warm-Up | n
2 | [ItsOnFire](./02_ItsOnFire/) | Android APK | DexGuard/ProGuard Protected App, Invader-Like Game, CRC32, AES-CBC with PKCS#5 | n
3 | [mypassion](./03_mypassion/) | Windows | Multi-Staged Shellcode, Importance of Modeling Custom Data Structure, PEB Walk & Export Filtering Shellcode Repair, CRC32, RC4, TEA | n
4 | [aimbot](./04_aimbot/) | Windows | Drops Monero Miner (XMRig?), AES-256-ECB, Anti-Debug Safari, Process Injection of an Aimbot for the Steam Game Sauerbraten | n
5 | [where_am_i](./05_where_am_i/) | Windows | VMProtect-like Control-Flow Obfuscation, RC4 and RC6, DTrack-like Key Material in DOS Header, Instrument Code to Decrypt Flag BLOB | n
6 | [FlareSay](./06_FlareSay/) | DOS COM/PE Polyglot | DOS: Simon Says like Game, 128 Level, Konami Code to pin LCG Seed, PE: Rol7XorAdd Hash, Custom/Modified ChaCha20 | n
7 | [flake](./07_flake/) | Nuitka compiled Python | Deep-dive into the Compiled Code, RC4 with Key-Encryption-Key | y
8 | [AmongRust](./08_AmongRust/) | Windows (Rust), PCAP | Process Injection, Multi-Byte XOR PE Payloads, PE File Infector, Rick-Roll ASEP, RAT with Encrypted C2 Upload, Leverage Replay from PCAP | n
9 | [mbransom](./09_mbransom/) | MBR Ransomware | 16-Bit Boot Sector Unpacking stub, RC4 Encrypted 2nd-Stage Code, Blowfish Key Bruteforce (2 Bytes) | n
10 | [kupo](./10_kupo/) | 2.11BSD Forth Environment | The MoogleForth 101 incl. adb & Forth magics, Multi-Byte XOR, Prefix Sum Mod 256 | y
11 | [over_the_rainbow](./11_over_the_rainbow/) | Windows | C++ Ransomware with Statically Linked OpenSSL, ChaCha20 & Multi-Byte XOR Encrypted Files, 2048-Bit RSA Encrypted Keys/Init State, Vulnerable to Coppersmith Attack | n
12 | [HVM](./12_HVM/) | Windows HVI | HVI Guest partition's VM Code does JIT Code De-/Re-encryption. Weird Salsa20 Block as XOR key, Math Substitutions | y
13 | [y0da](./13_y0da/) | Windows | RAT with JMP-fuscated Control-Flow, Remote Shell with Hidden Commands, ROP chain, MT19937, Custom Base32 Alpha | y

## Personal Result

I'm happy to have achieved this year's goal of reaching top 100 with finishing rank #82. Something to beat for Flare-On 11! ;-)

![pic1](pics/scoreboard_rank.png)

![pic2](pics/scoreboard_profile.png)

## Official Solutions

[Flare-On 10 Solution Page](N/A)

