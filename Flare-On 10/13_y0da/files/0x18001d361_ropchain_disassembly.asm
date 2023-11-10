Gadget  60: 8b4524       mov     eax, [rbp+24h] ; unk stack variable (possibly local var j from sub 4936e, the loop var to call rop chain)
Gadget  6c: 488b4d40     mov     rcx, [rbp+40h] ; flag bytes
Gadget  7b: 0fb60401     movzx   eax, byte ptr [rcx+rax]
Gadget  4b: 884520       mov     [rbp+20h], al ; flag byte
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9f: c1f803       sar     eax, 3
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  ba: c1e105       shl     ecx, 5
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget   0: 05ac000000   add     eax, 0ACh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 104: 83e804       sub     eax, 4
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9f: c1f803       sar     eax, 3
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  ba: c1e105       shl     ecx, 5
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a7: c1f806       sar     eax, 6
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b2: c1e102       shl     ecx, 2
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 153: 83f00d       xor     eax, 0Dh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  1e: 83c07b       add     eax, 7Bh ; '{'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 13b: 35bf000000   xor     eax, 0BFh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  d2: 2dc3000000   sub     eax, 0C3h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  16: 83c060       add     eax, 60h ; '`'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a3: c1f805       sar     eax, 5
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b6: c1e103       shl     ecx, 3
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  f0: 83e818       sub     eax, 18h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  e4: 2df3000000   sub     eax, 0F3h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  d8: 2dc5000000   sub     eax, 0C5h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ab: c1f807       sar     eax, 7
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  af: d1e1         shl     ecx, 1
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ea: 2dff000000   sub     eax, 0FFh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ab: c1f807       sar     eax, 7
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  af: d1e1         shl     ecx, 1
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h] ; possibly j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 17f: 358f000000   xor     eax, 8Fh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  1a: 83c070       add     eax, 70h ; 'p'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 100: 83e836       sub     eax, 36h ; '6'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget   c: 05e8000000   add     eax, 0E8h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 10c: 83e856       sub     eax, 56h ; 'V'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a7: c1f806       sar     eax, 6
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b2: c1e102       shl     ecx, 2
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h] ; possibly j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a3: c1f805       sar     eax, 5
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b6: c1e103       shl     ecx, 3
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 173: 83f040       xor     eax, 40h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 120: 2d9a000000   sub     eax, 9Ah
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 163: 83f016       xor     eax, 16h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 114: 2d81000000   sub     eax, 81h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  cc: 2db2000000   sub     eax, 0B2h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 11a: 2d90000000   sub     eax, 90h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  fc: 83e828       sub     eax, 28h ; '('
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  de: 2ddc000000   sub     eax, 0DCh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ab: c1f807       sar     eax, 7
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  af: d1e1         shl     ecx, 1
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 17b: 83f07c       xor     eax, 7Ch
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9b: c1f802       sar     eax, 2
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  be: c1e106       shl     ecx, 6
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  28: 0596000000   add     eax, 96h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 12f: 35a3000000   xor     eax, 0A3h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a7: c1f806       sar     eax, 6
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b2: c1e102       shl     ecx, 2
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 14d: 35cb000000   xor     eax, 0CBh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  f4: 83e81a       sub     eax, 1Ah
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 135: 35b6000000   xor     eax, 0B6h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  c6: 2db1000000   sub     eax, 0B1h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 157: 35e1000000   xor     eax, 0E1h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  22: 058f000000   add     eax, 8Fh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  98: d1f8         sar     eax, 1
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  c2: c1e107       shl     ecx, 7
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  12: 83c05a       add     eax, 5Ah ; 'Z'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 177: 83f078       xor     eax, 78h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 15d: 35eb000000   xor     eax, 0EBh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 16f: 83f025       xor     eax, 25h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ab: c1f807       sar     eax, 7
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  af: d1e1         shl     ecx, 1
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 147: 35c9000000   xor     eax, 0C9h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  9f: c1f803       sar     eax, 3
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  ba: c1e105       shl     ecx, 5
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h] ; j
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 108: 83e849       sub     eax, 49h ; 'I'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  f8: 83e81e       sub     eax, 1Eh
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a3: c1f805       sar     eax, 5
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b6: c1e103       shl     ecx, 3
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 167: 83f020       xor     eax, 20h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 16b: 83f022       xor     eax, 22h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 110: 83e858       sub     eax, 58h ; 'X'
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  a7: c1f806       sar     eax, 6
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  b2: c1e102       shl     ecx, 2
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget   6: 05e4000000   add     eax, 0E4h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 185: 334524       xor     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 141: 35c2000000   xor     eax, 0C2h
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget 126: 2b4524       sub     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  2e: 034524       add     eax, [rbp+24h]
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  92: f7d0         not     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  8f: f7d8         neg     eax
Gadget  4b: 884520       mov     [rbp+20h], al
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  ab: c1f807       sar     eax, 7
Gadget  8a: 0fb64d20     movzx   ecx, byte ptr [rbp+20h]
Gadget  af: d1e1         shl     ecx, 1
Gadget  95: 0bc1         or      eax, ecx
Gadget  4b: 884520       mov     [rbp+20h], al ; last write = plaintext flag char
Gadget  80: 0fb64520     movzx   eax, byte ptr [rbp+20h]
Gadget  68: 8b4d24       mov     ecx, [rbp+24h] ; j
Gadget  76: 488b5550     mov     rdx, [rbp+50h] ; MT rands
Gadget  85: 0fb60c0a     movzx   ecx, byte ptr [rdx+rcx] ; MT rands[j]
Gadget 18c: 33c1         xor     eax, ecx ; xor with MT rands[j]
Gadget  68: 8b4d24       mov     ecx, [rbp+24h] ; j
Gadget 18f: ffc1         inc     ecx ; j+1
Gadget 192: 8bc9         mov     ecx, ecx
Gadget  76: 488b5550     mov     rdx, [rbp+50h] ; MT rands
Gadget  85: 0fb60c0a     movzx   ecx, byte ptr [rdx+rcx] ; MT rands[j+1]
Gadget  af: d1e1         shl     ecx, 1
Gadget 195: 81e1ff000000 and     ecx, 0FFh
Gadget 19c: 8b5524       mov     edx, [rbp+24h] ; j
Gadget 1a0: 83c202       add     edx, 2
Gadget 1a4: 8bd2         mov     edx, edx
Gadget 1a7: 4c8b4550     mov     r8, [rbp+50h] ; MT rands
Gadget 1ac: 410fb61410   movzx   edx, byte ptr [r8+rdx] ; MT rands[j+2]
Gadget 1b2: d1fa         sar     edx, 1
Gadget 1b5: 81e2ff000000 and     edx, 0FFh
Gadget 1bc: 23ca         and     ecx, edx
Gadget 18c: 33c1         xor     eax, ecx
Gadget  68: 8b4d24       mov     ecx, [rbp+24h] ; j
Gadget 1bf: 83c103       add     ecx, 3
Gadget 192: 8bc9         mov     ecx, ecx
Gadget  76: 488b5550     mov     rdx, [rbp+50h] ; MT rands
Gadget  85: 0fb60c0a     movzx   ecx, byte ptr [rdx+rcx] ; MT rands[j+3]
Gadget  b2: c1e102       shl     ecx, 2
Gadget 195: 81e1ff000000 and     ecx, 0FFh
Gadget 18c: 33c1         xor     eax, ecx
Gadget  68: 8b4d24       mov     ecx, [rbp+24h] ; j
Gadget  71: 488b5540     mov     rdx, [rbp+40h] ; flag bytes
Gadget  3e: 88040a       mov     [rdx+rcx], al ; overwrite flag bytes[j] = result
