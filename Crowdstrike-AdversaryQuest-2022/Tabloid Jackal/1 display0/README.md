# Crowdstrike Adversary Quest 2022 / Tabloid Jackal / #1 display0

## Challenge Description

We were approached by our customer "Daily Code" who detected suspicious activity on a VPN gateway. One of their sysadmins did some basic inspection of the system and was able to discover an unknown ELF binary.

For further analysis, the sysadmin sent us the ELF alongside an asciinema recording of their terminal session.

Note: Flags will be easily identifiable by the format “CS{some_secret_flag_text}”. They must be submitted in full, including “CS{“ and “}”).

## TL;DR Summary

- The provided challenge binary display0 is customized to a certain target operating system environment.
- It collects system specific values from different data points and calculates a SHA256 hash value.
- The first half of this hash value is used as a key to decrypt a payload with AES-128-CTR.
- After successful decryption, the payload is executed.
- In order to solve the challenge, the specific target operating system's environment data must be extracted from the provided terminal recording.

## Pre-Requisites

The Linux binary display0 requires at least GLIBC version 2.34.

Install asciinema to replay/dump the recording.
`$ sudo apt install asciinema`

## Analysis

We are provided with two files

- challenge.cast
- display0

The former is an `asciinema` recording of terminal output (see challenge description), the latter a 64 Bit Linux ELF executable.

```console
$ file display0
display0: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), for GNU/Linux 4.4.0, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, no section header
```

### Dumping the Recording

We can replay the recording with `asciinema play challenge.cast`. For some reason, it seems to lock up with certain terminal configurations.

We can also dump the recording with

```console
$ asciinema cat challenge.cast > asciinema_cat_out.txt
```

#### Initial Findings in the Dump

Taking a first look at the dump, we can find the following information regarding a similarly named file/process `display0`:

- The output of `ps auxf` shows a process named `.display0` with PID 1039 running with root permissions.
- The process' binary seems to be located in `/tmp/.Xorg`.
- The binary has a file size of 526.776 bytes and has the SHA256 hash of `102063b9ff275b49512bafe1f92c01dc513bfaae17eb22a7c0d2abb225bea18f`.

Our provided file `display0` has the same file size and SHA256 hash value.

We can also see the dump of an authorized ssh key, which might be usable for remotely logging into the target host without supplying a password. The dumped sshd configuration seems to allow root logins, but we do not know a public IP address of the host.

The output from `ss -tulpen` also shows, that the display0 process with PID 1039 is listening on TCP port 1337 for incoming connections. Fishy - could be a backdoor!

### Analysis of Binary display0

A first glance with a disassembler reveals some functions with excessive XOR and shift operations. It can be a very deep rabbit hole trying to understand these in detail, unless we (_cough_) - or one of our helper tools - recognizes them. Many crypto functions use (semi-) unique constant values, e.g. for initializing the algorithm or for higher speed look-up purposes.

Helpful tools/scripts can be

- [FLARE's capa](https://github.com/mandiant/capa)
- [Daniel Plohmann's IDAscope](https://github.com/danielplohmann/idascope)

IDAscope identifies **SHA256** by its initial setup of context array `h[]` as well as **AES** inverse/forward box values.

#### Function main_11A0

Spending enough - or maybe too much - time staring at disassembly and decompilation output, we can rename things in function **main()** to

```cpp
__int64 __fastcall main_11A0(int argc, char **argv, char **envp)
{
  v4 = fill_payload_struct_1380(&encryptedPayload);
  retval = 1LL;
  if ( !v4 )
  {
    SHA256_init_1620(SHA256_CTX_ish);
    LODWORD(SHA256_CTX_ish[0]) = -1;
    host_OS_data_hashing_1870(SHA256_CTX_ish);
    get_key_from_SHA256_final_1A20(SHA256_CTX_ish, &v10);
    AES_init_and_key_derivation_25E5(pos_AES_ctx, &v10, &v9);
    AES_decrypt_payload_26D1(pos_AES_ctx, encryptedPayload.pData, encryptedPayload.qwLen);
    return execve_decrypted_payload_13A0(&encryptedPayload, argv, envp);
  }
  return retval;
}
```

After initializing the SHA256_CTX somewhat unlike what we might have expected from staring at the source code of OpenSSL (function **SHA256_init_1620()**), the operation system's environment data points are queried by function **host_OS_data_hashing_1870()**.

Once done with that, the final SHA256 hash value is calculated inside of function **get_key_from_SHA256_final_1A20()**, which also puts the first half of the hash's digest into a variable used for initializing the AES cipher in function **AES_init_and_key_derivation_25E5()**.

Function **AES_decrypt_payload_26D1()** decrypts the payload, which is executed inside function **execve_decrypted_payload_13A0()**.

Pretty straight forwarded, if things are named like that (which took quite a while...).

#### Function host_OS_data_hashing_1870

This function queries the following data points from the operating system and keeps calling function **SHA256_update_1EE0()** on each result.

- The contents of all ssh public key files under `/etc`
- The MAC addresses of the host's network interfaces
- The IPv4 addresses of the host's network interfaces
- The IPv6 addresses of the host's network interfaces
- The CPU model name and flags output from `/proc/cpuinfo`
- The MemTotal line from `/proc/meminfo`
- Tthe contents of `/etc/fstab`
- The hostname

## Solution Approach

In case of failing to identify the SHA256 and AES crypto algorithms in the first attempt(s), one might be tempted trying to just mimick the target operating system's environment that can be carved out of the asciinema recording. Someone might have gone that road for a while ... *cough*. Might be nice to learn about configuring Ubuntu's network interfaces with netplan, setting up Wireguard VPN and other things that may come in handy in some other future life...

```python
while havent_stared_enough_at_disassembly_yet:
  stare_longer_at_disassembly()
```

But once we understood the logic of function **main_11A0()**, we can carve the values to-be-queried by display0 out of the asciinema recoding.

### Pulling the Target OS Data together...

```python
target_os_environment_data = [
  # 1) Contents of ssh public keys from /etc/ssh/
  # 1a) ssh_host_ecdsa_key.pub
  b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLGQefn2v3deeDhNnak8ZsMQrVdoT/zq/eeuBz7PVz1XGryG9zIpK8Doe6xzMVlJjhEOn5zYSie1jc5KJ/iAMK8= root@vpn-gw\n",
  # 1b) ssh_host_ed25519_key.pub
  b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZl4ktzKh5JJBBeQvYIf5F0h+XScU7NfJN1P0dWl7oL root@vpn-gw\n",
  # 1c) ssh_host_rsa_key.pub
  b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCvBZX5SN0I7OZjLCZ2KbD3KVw+MSSHBf2YDbTWlSPVZMQkBykdcOX0GDw58vHPD46QgCbL4x+p1MVCm/QiGEOifhZPY4BmMUWAyQgtJvCtKeSFHSqyRGpdMfqfl/VE+TPEcXsDn8ixFsqVm8VUVFS+ybd2dZnLiK69mhfzzr5disfxMSHz5lEiRA6mwad2C5b6SmL+Pse7wGN135XbM4w4KrWIPQiQnOkSHjlTZTpC3FkTouT7iJm5T4v5ZelqwF+raEwIIxsJXAls1S8biLVFAOW4vWb2oc0+2r1heR8IqKRHmb6s3koq2RCY5yucbq/BwQkpyXHlMQBTul1MOz0xb/mrwQs5K9k+GEFCKKK041zdmJLAZMleFYg9LctlzgtXyMccre3LRKuJGTEzuh6M9byL80ukVJkEy5vZTcvW3NGIvXdCNmuRUYImdDLvDQB8L6Zurgemdv1bR0rrxYYGSC3Qd4jioILNUunMRHOtOAxVpzizt/YWf+vOjzv16ic= root@vpn-gw\n",
  # 2) Network interface configuration // Network byte order!
  # 2a) Enumeration of MAC addresses
  # 2a1) lo0
  b"\x00\x00\x00\x00\x00\x00",
  # 2a2) enp1s0
  b"\x52\x54\x00\xFF\xEA\xEA",
  # 2b) Enumeration of IPv4 addresses
  # 2b1) lo0 = 127.0.0.1
  b"\x7F\x00\x00\x01",
  # 2b2) enp1s0 = 192.168.122.243
  b"\xC0\xA8\x7A\xF3",
  # 2b3) wg0 = 10.42.42.1
  b"\x0A\x2A\x2A\x01",
  # 2c) Enumeration of IPv6 addresses
  # 2c1) lo0 = ::1
  b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
  # 2c2) enp1s0 = fe80::5054:ff:feff:eaea
  b"\xFE\x80\x00\x00\x00\x00\x00\x00\x50\x54\x00\xFF\xFE\xFF\xEA\xEA",
  # 2c3) wg0 = fd0d:5555:1111::1
  b"\xFD\x0D\x55\x55\x11\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
  # 3) CPU model name and flags output from /proc/cpuinfo (mind the TAB!)
  # 3a) CPU0
  # 3a1) model name
  b"model name\t: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz\n",
  # 3a2) flags
  b"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq vmx ssse3 fma cx16 pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust sgx bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat umip sgx_lc md_clear arch_capabilities\n"
  # 3b) CPU1
  # 3b1) model name
  b"model name\t: Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz\n",
  # 3b2) flags
  b"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq vmx ssse3 fma cx16 pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch cpuid_fault invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust sgx bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat umip sgx_lc md_clear arch_capabilities\n",
  # 4) MemTotal line from /proc/meminfo (no TABS)
  b"MemTotal:        4019880 kB\n",
  # 5) Contents of /etc/fstab (no TABS)
  b"# /etc/fstab: static file system information.\n#\n# Use 'blkid' to print the universally unique identifier for a\n# device; this may be used with UUID= as a more robust way to name devices\n# that works even if disks are added and removed. See fstab(5).\n#\n# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation\n/dev/disk/by-id/dm-uuid-LVM-YTxLSbvzj4B2t3M2PjE6NMLc10jaz1cW017SpPSEoWo1lonZNahKyMgRrnbRejpu / ext4 defaults 0 1\n# /boot was on /dev/vda2 during curtin installation\n/dev/disk/by-uuid/0371b26f-9b92-4fdf-a485-8d15c42f2f4e /boot ext4 defaults 0 1\n",
  # 6) The hostname (without trailing newline)
  b"vpn-gw"]
```

### Calculate the SHA256 Hash Value

```python
sha256 = hashlib.sha256()
for i in target_os_environment_data:
  sha256.update(i)
```

The correct hash value will be `fd25e9429d731f5b905a848f66675a3fdbfd028ef320d0497d80de1a0445bf22`.

### Decrypt the encrypted Payload with AES-128-CTR

```python
aes_key = sha256.digest()[:16]
cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"\x00")
decrypted_payload = cipher.decrypt(encrypted_payload)
```

The decrypted payload is another ELF binary, which is executed right away.

How did we know about the specific AES variant being used?

Here is the CTF approach when on time pressure: Fire up CyberChef, click through all possible variants and see if anything useful is spit out.

While that doesn't sound very sophisticated, it may be way faster than trying to identify matching source code to compare the disassembly/decompilation with. ;-)

### Find the Flag in the decrypted Payload

```console
$ strings --radix=x  payload_decrypted.bin | egrep "CS{"
  63100 CS{3nc_b1nd_sh3ll}
```

### Python Implementation

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

## Conclusion

Pay attention to tabs vs spaces output from /proc filesystem. The actor's name is TABLOID Jackal after all.

Also: Do your first malware triaging like a pro and find AES _and_ SHA256 constants instantely. Saves time wasted on rabbit-holing!
