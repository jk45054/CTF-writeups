# CrowdStrike Adversary Quest 2021 / Space Jackal / #2 Matrix

## Challenge
With the help of your analysis, we got onto the trail of the group and found their [hidden forum](http://spacesftw5q4uyamog5qgcf75a5hbhmr2g24jqsdcpjnew63zkq7ueyd.onion/) on the Deep Dark Web. Unfortunately, all messages are encrypted. While we believe that we have found their encryption tool, we are unsure how to decrypt these messages. Can you assist?

## Approach
- Retrieve encrypted messages
- Analyze encryption tool
- Derive decryption key
- Decrypt messages

### Encrypted Messages
```
Forum Entries
Welcome on board!
259F8D014A44C2BE8FC573EAD944BA63 21BB02BE026D599AA43B7AE224E221CF 00098D47F8FFF3A7DBFF21376FF4EB79 B01B8877012536C10394DF7A943731F8 9117B49349E078809EA2EECE4AA86D84 4E94DF7A265574A379EB17E4E1905DB8 49280BD0040C23C98B05F160905DB849 280B6CB9DFECC6C09A0921314BD94ABF 3049280B5BFD8953CA73C8D1F6D0040C 1B967571354BAAB7992339507BBB59C6 5CDA5335A7D575C970F1C9D0040C23C9 8B08F78D3F40B198659B4CB137DEB437 08EB47FB978EF4EB7919BF3E97EA5F40 9F5CF66370141E345024AC7BB966AEDF 5F870F407BB9666F7C4DC85039CBD819 994515C4459F1B96750716906CB9DF34 5106F58B3448E12B87AFE754C0DD802C 41C25C7AAAFF7900B574FC6867EA35C5 BB4E51542C2D0B5645FB9DB1C6D12C8E F62524A12D5D5E622CD443E02515E7EB 991ACCC0C08CE8783F7E2BAD4B16D758 530C79003E5ED61DFE2BE70F50A6F9CA 288C
Let's fight back!
259F8D014A44C2BE8F7FA3BC3656CFB3 DF178DEA8313DBD33A8BAC2CD4432D66 3BC75139ECC6C0FFFBB38FB17F448C08 17BF508074D723AAA722D4239328C6B3 7F57C0A5249EA4E79B780DF081E997C0 6058F702E2BF9F50C4EC1B5966DF27EC 56149F253325CFE57A00B57494692921 94F383A3535024ACA7009088E70E6128 9BD30B2FCFE57A00B5749469292194F3 83A3533BAB08CA7FD9DC778386803149 280BE0895C0984C6DC77838C2085B10B 3ED0040C3759B05029F8085EDBE26DE3 DF25AA87CE0BBBD1169B780D1BCAA097 9A6412CCBE5B68BD2FB780C5DBA34137 C102DBE48D3F0AE471B77387E7FA8BEC 305671785D725930C3E1D05B8BD884C0 A5246EF0BF468E332E0E70009CCCB4C2 ED84137DB4C2EDE078807E1616AA9A7F 4055844821AB16F842
FLAGZ!
259F8D014A44C2BE8FC50A5A2C1EF0C1 3D7F2E0E70009CCCB4C2ED84137DB4C2 EDE078807E1616C266D5A15DC6DDB60E 4B7337E851E739A61EED83D2E06D6184 11DF61222EED83D2E06D612C8EB5294B CD4954E0855F4D71D0F06D05EE
```
At a very first glance: All three encrypted messages begin with the same 18 hexadecimal digits `259F8D014A44C2BE8F`.

### Encryption Tool
```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''              ,
                /|      ,
   ,--.________/ /-----/|-------------------------------------.._
  (    /_/_/_/_  |--------- DEATH TO ALL TABS ---------------<  _`>
   `--´        \ \-----\|-------------------------------------''´
                \|      '
'''#             '
assert __name__ == '__main__'
import sys
def die(E):
    print(F'E:',E,file=sys.stderr)
    sys.exit(1)
T=lambda A,B,C,D,E,F,G,H,I:A*E*I+B*F*G+C*D*H-G*E*C-H*F*A-I*D*B&255
def U(K):
    R=pow(T(*K),-1,256)
    A,B,C,D,E,F,G,H,I=K
    return [R*V%256 for V in
     [E*I-F*H,C*H-B*I,B*F-C*E,F*G-D*I,A*I-C*G,C*D-A*F,D*H-E*G,B*G-A*H,A*E-B*D]]
def C(K,M):
    B=lambda A,B,C,D,E,F,G,H,I,X,Y,Z:bytes((A*X+B*Y+C*Z&0xFF,
        D*X+E*Y+F*Z&0xFF,G*X+H*Y+I*Z&0xFF))
    N=len(M)
    R=N%3
    R=R and 3-R
    M=M+R*B'\0'
    return B''.join(B(*K,*W) for W in zip(*[iter(M)]*3)).rstrip(B'\0')
len(sys.argv) == 3 or die('FOOL')
K=bytes(sys.argv[2], 'ascii')
len(K)==9 and T(*K)&1 or die('INVALID')
M=sys.stdin.read()
if sys.argv[1].upper() == 'E':
    M=B'SPACEARMY'+bytes(M,'ascii')
    print(C(U(K),M).hex().upper())
else:
    M=C(K,bytes.fromhex(M))
    M[:9]==B'SPACEARMY' or die('INVALID')
    print(M[9:].decode('ascii'))
```

### Derive Decryption Key
Known plaintext: every plaintext message begins with SPACEARMY (9 chars).
Crypto is applied in 3 bytes at a time, plaintext is padded to multiple of 3.
B lambda function applies linear equation as crypto

259F8D014A44C2BE8F <- thats encrypted SPACEARMY (seen in all 3 messages)

B=lambda A,B,C,D,E,F,G,H,I,X,Y,Z:bytes((A*X+B*Y+C*Z&0xFF,D*X+E*Y+F*Z&0xFF,G*X+H*Y+I*Z&0xFF))
return B''.join(B(*K,*W) for W in zip(*[iter(M)]*3)).rstrip(B'\0')

-> X, Y, Z are the next three chars of the message

0x25 = (A * 83 + B * 80 + C * 65) & 0xFF
0x9F = (D * 83 + E * 80 + F * 65) & 0xFF
0x8D = (G * 83 + H * 80 + I * 65) & 0xFF

0x01 = (A * 67 + B * 69 + C * 65) & 0xFF
0x4A = (D * 67 + E * 69 + F * 65) & 0xFF
0x44 = (G * 67 + H * 69 + I * 65) & 0xFF

0xC2 = (A * 82 + B * 77 + C * 89) & 0xFF
0xBE = (D * 82 + E * 77 + F * 89) & 0xFF
0x8F = (G * 82 + H * 77 + I * 89) & 0xFF

sort linear equations

0x25 = (A * 83 + B * 80 + C * 65) & 0xFF
0x01 = (A * 67 + B * 69 + C * 65) & 0xFF
0xC2 = (A * 82 + B * 77 + C * 89) & 0xFF

0x9F = (D * 83 + E * 80 + F * 65) & 0xFF
0x4A = (D * 67 + E * 69 + F * 65) & 0xFF
0xBE = (D * 82 + E * 77 + F * 89) & 0xFF

0x8D = (G * 83 + H * 80 + I * 65) & 0xFF
0x44 = (G * 67 + H * 69 + I * 65) & 0xFF
0x8F = (G * 82 + H * 77 + I * 89) & 0xFF

solve equations with z3

[A = 207, B = 28, C = 72]
[D = 76, F = 139, E = 223]
[G = 109, I = 70, H = 11]
b'\xcf\x1cHL\xdf\x8bm\x0bF'

we calced U(K) and had to apply U on it again to get K

[83, 80, 52, 101, 118, 97, 67, 69, 83]

key: SP4evaCES

### Decrypt Messages
```
Welcome on board and congratulations on joining the Order of 0x20.

Together we will fight the good fight and bring enlightenment to the non-believers: Let's stop the global TAB infestation once and for all. This forum is a place to share news and coordinate action, but be careful: you never know who's watching.

 040 == 32 == 0x20

-- admin.
```

```
My name is rudi. i was fired by my Old employer because I refused to use TABs. THIS madness must be STOPPED! These people must be STOPPED!1! But I fought back! I hacked their network established access. Let me know if you have an idea how to take revegne!

 040 == 32 == 0x20

-- rudi.
```

```
$ cat flagz.txt | python3 crypter.py D SP4evaCES
Good job!

 040 == 32 == 0x20

CS{if_computers_could_think_would_they_like_spaces?}
```

Flag: **CS{if_computers_could_think_would_they_like_spaces?}**

### Conclusions
- Don't apply custom crypto
- Beware of known plaintext attacks
