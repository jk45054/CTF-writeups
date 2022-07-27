#!/usr/bin/env python3

import sys
import hashlib
import re
from Crypto.Cipher import AES

# The binary display0 seems to be highly customized to the target operating system
# Only if several data points have a certain value, the encrypted payload is decrypted & executed
# The data points that display0 collects can be identified by reverse engineering function
# "host_OS_data_hashing_1870()" @ RVA 0x1870.
# The target operating system's data point values can be extracted from the asciinema
# terminal recording.

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


# display0 calculates the SHA256 hash value, updating its internal context with each collected piece
sha256 = hashlib.sha256()
for i in target_os_environment_data:
  sha256.update(i)
target_hash = sha256.hexdigest()
print(f"[*] Hashing Target OS Environment Data with SHA256 = {target_hash}")

# display0 uses the first 16 bytes of the (binary representation of) the SHA256 hash value as an AES key
aes_key = sha256.digest()[:16]
print(f"[*] Using first 16 bytes of it as AES key = {aes_key}")

# display0 carries an encrypted payload that is executed upon successful decryption
encrypted_payload_offset = 0x40e0 
encrypted_payload_len = 0x7c8d8
print(f"[*] Carving Encrypted Payload from ELF binary display0 (offset = {hex(encrypted_payload_offset)}, len = {hex(encrypted_payload_len)})")

try:
  with open("./display0", "rb") as f:
    f.seek(encrypted_payload_offset)
    encrypted_payload = f.read(encrypted_payload_len)
except:
  print("[!] Oops, couldn't carve the payload")
  sys.exit(-1)

# The payload is encrypted with AES-128-CTR
print("[*] Decrypting Payload with AES-128-CTR... ", end = "")
cipher = AES.new(aes_key, AES.MODE_CTR, nonce=b"\x00")
decrypted_payload = cipher.decrypt(encrypted_payload)

if decrypted_payload[1:4] != b"ELF":
  print("failed, tough luck!")
  sys.exit(-1)
else:
  print("succeeded!")

# The decrypted payload contains the flag as a string with expected pattern CS{\w+}
print("[*] Searching decrypted payload for the flag... ", end = "")
p = re.compile(b"CS{\w+}")
m = p.findall(decrypted_payload)

if m:
  print("succeeded")
  print(f"[*] Flag = {m[0].decode('utf-8')}")
else:
  print("failed, tough luck!")
  sys.exit(-1)

