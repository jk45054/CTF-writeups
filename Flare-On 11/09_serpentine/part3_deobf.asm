0x330AF2: 49BF8B71C7C900000000             mov     r15, 0C9C7718Bh
0x330B5B: 4981C75D47C276                   add     r15, 76C2475Dh
0x02F560: 498B7128                         mov     rsi, [r9+28h]
0x330C29: 4C8BA6D8000000                   mov     r12, [rsi+0D8h]
0x02F56B: 4D0FB6E4                         movzx   r12, r12b
0x02F652: 4D8B7928                         mov     r15, [r9+28h]
0x330CF5: 498B87D8000000                   mov     rax, [r15+0D8h]
0x330D5A: 48C7C35488D4D5                   mov     rbx, 0FFFFFFFFD5D48854h
0x330DC8: 4881C3AC3C742A                   add     rbx, 2A743CACh
0x02F66B: 53                               push    rbx
0x02F66C: 48F72424                         mul     qword ptr [rsp]
0x02F670: 4889C6                           mov     rsi, rax
0x02F758: 4D8B6128                         mov     r12, [r9+28h]
0x330E9C: 498B8424A8000000                 mov     rax, [r12+0A8h]
0x02F764: 50                               push    rax
0x02F765: 4889E6                           mov     rsi, rsp
0x330F02: 498BAC24A8000000                 mov     rbp, [r12+0A8h]
0x02F85F: 4D8B7128                         mov     r14, [r9+28h]
0x330FD6: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x331043: 4D8BA6A0000000                   mov     r12, [r14+0A0h]
0x02F871: 480FB6ED                         movzx   rbp, bpl
0x02F941: 498B5928                         mov     rbx, [r9+28h]
0x331111: 0FAE93A0000000                   ldmxcsr dword ptr [rbx+0A0h]
0x331178: 49BEC661F1E200000000             mov     r14, 0E2F161C6h
0x3311E9: 4981C6FA10185D                   add     r14, 5D1810FAh
0x331255: 4D8BB6E0050000                   mov     r14, [r14+5E0h]
0x3312C1: 4C03B3A0000000                   add     r14, [rbx+0A0h]
0x02F96B: 458A3E                           mov     r15b, [r14]
0x02F96E: 4D0FB6FF                         movzx   r15, r15b
0x02F972: 49C1E708                         shl     r15, 8
0x33132A: 4C29BBD8000000                   sub     [rbx+0D8h], r15
0x02F97D: 498B4128                         mov     rax, [r9+28h]
0x331393: 4C8BA8D8000000                   mov     r13, [rax+0D8h]
0x3313FC: 48BDD85EFD3C01000000             mov     rbp, 13CFD5ED8h
0x331469: 4881C5E80B0C03                   add     rbp, 30C0BE8h
0x02FA86: 4D8B5928                         mov     r11, [r9+28h]
0x02FA8A: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x33153D: 498B9B88000000                   mov     rbx, [r11+88h]
0x3315A6: 498BB3E0000000                   mov     rsi, [r11+0E0h]
0x02FB92: 4D8B7928                         mov     r15, [r9+28h]
0x331678: 498BBFA8000000                   mov     rdi, [r15+0A8h]
0x02FB9D: 418B5734                         mov     edx, [r15+34h]
0x3316DF: 49039790000000                   add     rdx, [r15+90h]
0x02FBA8: 448A1A                           mov     r11b, [rdx]
0x02FBAB: 4488DF                           mov     dil, r11b
0x02FC85: 498B7928                         mov     rdi, [r9+28h]
0x3317B0: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x02FC90: 55                               push    rbp
0x02FC91: 4989E4                           mov     r12, rsp
0x331817: 488B9FB0000000                   mov     rbx, [rdi+0B0h]
0x02FD66: 498B5128                         mov     rdx, [r9+28h]
0x3318EB: 4C8B9AD8000000                   mov     r11, [rdx+0D8h]
0x331956: 4C8BBA90000000                   mov     r15, [rdx+90h]
0x02FD78: 4153                             push    r11
0x02FD7A: 68A908211F                       push    1F2108A9h
0x02FD7F: 68E2561266                       push    661256E2h
0x02FD84: 68565D7F70                       push    707F5D56h
0x02FD89: 68696C2C2C                       push    2C2C6C69h
0x02FE72: 4D8B6128                         mov     r12, [r9+28h]
0x331A27: 498BAC24E8000000                 mov     rbp, [r12+0E8h]
0x331A91: 4D8BA424F0000000                 mov     r12, [r12+0F0h]
0x02FE86: 480FB6ED                         movzx   rbp, bpl
0x02FF68: 498B5128                         mov     rdx, [r9+28h]
0x331B62: 0FAE92A0000000                   ldmxcsr dword ptr [rdx+0A0h]
0x331BCC: 48BE5035473A01000000             mov     rsi, 13A473550h
0x331C34: 4881C6703DC205                   add     rsi, 5C23D70h
0x331C99: 488BB608050000                   mov     rsi, [rsi+508h]
0x331D05: 4803B2A0000000                   add     rsi, [rdx+0A0h]
0x02FF92: 8A06                             mov     al, [rsi]
0x02FF94: 480FB6C0                         movzx   rax, al
0x02FF98: 48C1E010                         shl     rax, 10h
0x331D6E: 482982D8000000                   sub     [rdx+0D8h], rax
0x331DDB: 49BDDB48D2DE00000000             mov     r13, 0DED248DBh
0x02FFAD: 4155                             push    r13
0x02FFAF: 687F07DF0E                       push    0EDF077Fh
0x02FFB4: 684355F94A                       push    4AF95543h
0x02FFB9: 68E533ED6C                       push    6CED33E5h
0x02FFBE: 68A17A0D79                       push    790D7AA1h
0x331E45: 4881442420E5213761               add     qword ptr [rsp+20h], 613721E5h
0x02FFCC: 4D8B4928                         mov     r9, [r9+28h]
0x331EB1: 498BB1D8000000                   mov     rsi, [r9+0D8h]
0x0300BC: 4D8B4128                         mov     r8, [r9+28h]
0x0300C0: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x331F83: 4D8BB0E0000000                   mov     r14, [r8+0E0h]
0x331FED: 498B98A8000000                   mov     rbx, [r8+0A8h]
0x0301C1: 498B5928                         mov     rbx, [r9+28h]
0x3320B7: 488BAB90000000                   mov     rbp, [rbx+90h]
0x0301CC: 448B6334                         mov     r12d, [rbx+34h]
0x332123: 4C03A3E8000000                   add     r12, [rbx+0E8h]
0x0301D7: 458A1424                         mov     r10b, [r12]
0x332188: 48C7C1FF000000                   mov     rcx, 0FFh
0x0301E2: 48C1E108                         shl     rcx, 8
0x0301E6: 48F7D1                           not     rcx
0x0301E9: 4821CD                           and     rbp, rcx
0x0301EC: 490FB6CA                         movzx   rcx, r10b
0x0301F0: 48C1E108                         shl     rcx, 8
0x0301F4: 4809CD                           or      rbp, rcx
0x0302CC: 4D8B6928                         mov     r13, [r9+28h]
0x332250: 4D8BB5A0000000                   mov     r14, [r13+0A0h]
0x0302D7: 4156                             push    r14
0x0302D9: 4989E7                           mov     r15, rsp
0x3322B9: 498BADA0000000                   mov     rbp, [r13+0A0h]
0x0303BA: 4D8B5128                         mov     r10, [r9+28h]
0x332387: 498B8AF0000000                   mov     rcx, [r10+0F0h]
0x3323F3: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x0303CC: 51                               push    rcx
0x0303CD: 68DC0C483F                       push    3F480CDCh
0x0303D2: 687F0F1953                       push    53190F7Fh
0x0303D7: 687E6BE738                       push    38E76B7Eh
0x0304C8: 498B4928                         mov     rcx, [r9+28h]
0x3324C5: 488BB188000000                   mov     rsi, [rcx+88h]
0x332532: 488BB9E8000000                   mov     rdi, [rcx+0E8h]
0x0304DA: 480FB6F6                         movzx   rsi, sil
0x0305BC: 498B4928                         mov     rcx, [r9+28h]
0x332601: 0FAE91A8000000                   ldmxcsr dword ptr [rcx+0A8h]
0x33266D: 49BABF0A4F1901000000             mov     r10, 1194F0ABFh
0x3326D8: 4981C20168BA26                   add     r10, 26BA6801h
0x332746: 4D8B92D0060000                   mov     r10, [r10+6D0h]
0x3327AE: 4C0391A8000000                   add     r10, [rcx+0A8h]
0x0305E6: 458A02                           mov     r8b, [r10]
0x0305E9: 4D0FB6C0                         movzx   r8, r8b
0x0305ED: 49C1E018                         shl     r8, 18h
0x332815: 4C2981B0000000                   sub     [rcx+0B0h], r8
0x0305F8: 498B5128                         mov     rdx, [r9+28h]
0x332882: 4C8BB2B0000000                   mov     r14, [rdx+0B0h]
0x3328E8: 49BC9331C6DC00000000             mov     r12, 0DCC63193h
0x332953: 4981C42D394363                   add     r12, 6343392Dh
0x030712: 498B5128                         mov     rdx, [r9+28h]
0x030716: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x332A22: 4C8BBAA8000000                   mov     r15, [rdx+0A8h]
0x332A8E: 4C8BAAE8000000                   mov     r13, [rdx+0E8h]
0x030800: 4D8B6128                         mov     r12, [r9+28h]
0x332B65: 498BBC24E0000000                 mov     rdi, [r12+0E0h]
0x03080C: 418B6C2434                       mov     ebp, [r12+34h]
0x332BD0: 4903AC24F0000000                 add     rbp, [r12+0F0h]
0x030819: 8A4D00                           mov     cl, [rbp+0]
0x332C3D: 48C7C3FF000000                   mov     rbx, 0FFh
0x030823: 48C1E310                         shl     rbx, 10h
0x030827: 48F7D3                           not     rbx
0x03082A: 4821DF                           and     rdi, rbx
0x03082D: 480FB6D9                         movzx   rbx, cl
0x030831: 48C1E310                         shl     rbx, 10h
0x030835: 4809DF                           or      rdi, rbx
0x030900: 498B6928                         mov     rbp, [r9+28h]
0x332D0E: 488B8DB0000000                   mov     rcx, [rbp+0B0h]
0x03090B: 51                               push    rcx
0x03090C: 4989E6                           mov     r14, rsp
0x332D74: 4C8BADB0000000                   mov     r13, [rbp+0B0h]
0x0309FB: 4D8B4128                         mov     r8, [r9+28h]
0x332E49: 498B98F0000000                   mov     rbx, [r8+0F0h]
0x332EB0: 498BA8E0000000                   mov     rbp, [r8+0E0h]
0x030A0D: 480FB6DB                         movzx   rbx, bl
0x030AFF: 4D8B5928                         mov     r11, [r9+28h]
0x332F78: 410FAE9390000000                 ldmxcsr dword ptr [r11+90h]
0x332FDE: 49BEE9210A0B01000000             mov     r14, 10B0A21E9h
0x33304F: 4981C6D750FF34                   add     r14, 34FF50D7h
0x3330BB: 4D8BB678040000                   mov     r14, [r14+478h]
0x333128: 4D03B390000000                   add     r14, [r11+90h]
0x030B2A: 418A06                           mov     al, [r14]
0x030B2D: 480FB6C0                         movzx   rax, al
0x030B31: 48C1E020                         shl     rax, 20h
0x333195: 492983A0000000                   sub     [r11+0A0h], rax
0x333201: 49BA98F5F8D100000000             mov     r10, 0D1F8F598h
0x030B46: 4152                             push    r10
0x030B48: 68304DBA78                       push    78BA4D30h
0x030B4D: 680A68401E                       push    1E40680Ah
0x030B52: 685B214850                       push    5048215Bh
0x030B57: 68EC57B060                       push    60B057ECh
0x33326B: 48814424202875106E               add     qword ptr [rsp+20h], 6E107528h
0x030B65: 4D8B6928                         mov     r13, [r9+28h]
0x3332D4: 4D8BBDA0000000                   mov     r15, [r13+0A0h]
0x030C46: 4D8B4928                         mov     r9, [r9+28h]
0x030C4A: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x3333A4: 4D8BA9A0000000                   mov     r13, [r9+0A0h]
0x33340A: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x030D46: 498B4128                         mov     rax, [r9+28h]
0x3334DA: 4C8BB8B0000000                   mov     r15, [rax+0B0h]
0x030D51: 8B4834                           mov     ecx, [rax+34h]
0x333547: 480388E0000000                   add     rcx, [rax+0E0h]
0x030D5B: 8A11                             mov     dl, [rcx]
0x3335AD: 48C7C0FF000000                   mov     rax, 0FFh
0x030D64: 48C1E018                         shl     rax, 18h
0x030D68: 48F7D0                           not     rax
0x030D6B: 4921C7                           and     r15, rax
0x030D6E: 480FB6C2                         movzx   rax, dl
0x030D72: 48C1E018                         shl     rax, 18h
0x030D76: 4909C7                           or      r15, rax
0x030E61: 4D8B6128                         mov     r12, [r9+28h]
0x333683: 4D8BBC24F0000000                 mov     r15, [r12+0F0h]
0x030E6D: 4157                             push    r15
0x030E6F: 4889E3                           mov     rbx, rsp
0x3336EC: 498BBC24F0000000                 mov     rdi, [r12+0F0h]
0x030F59: 4D8B7928                         mov     r15, [r9+28h]
0x3337B7: 498BB788000000                   mov     rsi, [r15+88h]
0x33381E: 498B9FB0000000                   mov     rbx, [r15+0B0h]
0x030F6B: 480FB6F6                         movzx   rsi, sil
0x03105D: 498B5128                         mov     rdx, [r9+28h]
0x3338F2: 0FAE92A8000000                   ldmxcsr dword ptr [rdx+0A8h]
0x33395F: 49B8502F3DCB00000000             mov     r8, 0CB3D2F50h
0x3339CE: 4981C07043CC74                   add     r8, 74CC4370h
0x031079: 4D8B00                           mov     r8, [r8]
0x333A3A: 4C0382A8000000                   add     r8, [rdx+0A8h]
0x031083: 458A38                           mov     r15b, [r8]
0x031086: 4D0FB6FF                         movzx   r15, r15b
0x03108A: 49C1E738                         shl     r15, 38h
0x333AA3: 4C29BA90000000                   sub     [rdx+90h], r15
0x031095: 4D8B5128                         mov     r10, [r9+28h]
0x333B0E: 4D8BA290000000                   mov     r12, [r10+90h]
0x333B7C: 49BFE83680FD00000000             mov     r15, 0FD8036E8h
0x333BEB: 4981C7D8338942                   add     r15, 428933D8h
0x0311A2: 498B4128                         mov     rax, [r9+28h]
0x0311A6: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x333CB7: 488BB088000000                   mov     rsi, [rax+88h]
0x333D23: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x031296: 498B6928                         mov     rbp, [r9+28h]
0x333DF5: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x0312A1: 448B5D34                         mov     r11d, [rbp+34h]
0x333E5E: 4C039DA8000000                   add     r11, [rbp+0A8h]
0x0312AC: 458A33                           mov     r14b, [r11]
0x333EC9: 49C7C7FF000000                   mov     r15, 0FFh
0x0312B6: 49C1E730                         shl     r15, 30h
0x0312BA: 49F7D7                           not     r15
0x0312BD: 4C21FE                           and     rsi, r15
0x0312C0: 4D0FB6FE                         movzx   r15, r14b
0x0312C4: 49C1E730                         shl     r15, 30h
0x0312C8: 4C09FE                           or      rsi, r15
0x031397: 498B7128                         mov     rsi, [r9+28h]
0x333F9D: 4C8BA6A8000000                   mov     r12, [rsi+0A8h]
0x0313A2: 4154                             push    r12
0x0313A4: 4989E6                           mov     r14, rsp
0x334007: 488BBEA8000000                   mov     rdi, [rsi+0A8h]
0x03149A: 4D8B7128                         mov     r14, [r9+28h]
0x03149E: 4D8B6678                         mov     r12, [r14+78h]
0x3340D8: 4D8BAEB0000000                   mov     r13, [r14+0B0h]
0x0314A9: 4D0FB6E4                         movzx   r12, r12b
0x031590: 498B7928                         mov     rdi, [r9+28h]
0x3341A4: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x33420A: 49BEB6637F2C01000000             mov     r14, 12C7F63B6h
0x0315A5: 4156                             push    r14
0x0315A7: 68CC3B727E                       push    7E723BCCh
0x0315AC: 682E56233A                       push    3A23562Eh
0x0315B1: 68372ED20D                       push    0DD22E37h
0x334274: 48814424180A078A13               add     qword ptr [rsp+18h], 138A070Ah
0x0315BF: 4D8B4128                         mov     r8, [r9+28h]
0x3342DB: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x0316A7: 4D8B7928                         mov     r15, [r9+28h]
0x0316AB: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x3343B0: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x33441A: 4D8BA7E0000000                   mov     r12, [r15+0E0h]
0x03179D: 4D8B5928                         mov     r11, [r9+28h]
0x3344E5: 498BBBD8000000                   mov     rdi, [r11+0D8h]
0x0317A8: 418B5B34                         mov     ebx, [r11+34h]
0x33454B: 49039BE8000000                   add     rbx, [r11+0E8h]
0x0317B3: 408A2B                           mov     bpl, [rbx]
0x3345B0: 49C7C5FF000000                   mov     r13, 0FFh
0x0317BD: 49C1E538                         shl     r13, 38h
0x0317C1: 49F7D5                           not     r13
0x0317C4: 4C21EF                           and     rdi, r13
0x0317C7: 4C0FB6ED                         movzx   r13, bpl
0x0317CB: 49C1E538                         shl     r13, 38h
0x0317CF: 4C09EF                           or      rdi, r13
0x33467C: 48BDBA4400D300000000             mov     rbp, 0D30044BAh
0x0318C8: 55                               push    rbp
0x0318C9: 68C1692F20                       push    202F69C1h
0x0318CE: 68CF0FA20B                       push    0BA20FCFh
0x0318D3: 68C66D7965                       push    65796DC6h
0x3346EC: 48814424182E74896D               add     [rsp-8+arg_18], 6D89742Eh
0x0318E1: 4D8B6128                         mov     r12, [r9+28h]
0x33475B: 498BAC24B0000000                 mov     rbp, [r12+0B0h]
0x0319DF: 4D8B5928                         mov     r11, [r9+28h]
0x33482B: 4D8BA3E8000000                   mov     r12, [r11+0E8h]
0x334898: 4D8BBBA0000000                   mov     r15, [r11+0A0h]
0x0319F1: 4D0FB6E4                         movzx   r12, r12b
0x031AE4: 4D8B4128                         mov     r8, [r9+28h]
0x33496A: 498B80D8000000                   mov     rax, [r8+0D8h]
0x3349D4: 49C7C52B0D77B5                   mov     r13, 0FFFFFFFFB5770D2Bh
0x334A3D: 4981C55C1B9E4A                   add     r13, 4A9E1B5Ch
0x031AFD: 4155                             push    r13
0x334AA8: 4D8BB0F0000000                   mov     r14, [r8+0F0h]
0x031B06: 48F72424                         mul     qword ptr [rsp]
0x031B0A: 4989C4                           mov     r12, rax
0x031C01: 4D8B6128                         mov     r12, [r9+28h]
0x334B77: 4D8BBC24E8000000                 mov     r15, [r12+0E8h]
0x334BE3: 4D2BBC24D8000000                 sub     r15, [r12+0D8h]
0x031CFB: 498B6928                         mov     rbp, [r9+28h]
0x334CB7: 488B8DF0000000                   mov     rcx, [rbp+0F0h]
0x031D06: 51                               push    rcx
0x031D07: 4889E6                           mov     rsi, rsp
0x334D25: 4C8BADF0000000                   mov     r13, [rbp+0F0h]
0x031DF2: 4D8B4128                         mov     r8, [r9+28h]
0x334DF7: 498BB0C0000000                   mov     rsi, [r8+0C0h]
0x334E64: 498BB8E0000000                   mov     rdi, [r8+0E0h]
0x031E04: 480FB6F6                         movzx   rsi, sil
0x031EF4: 498B6928                         mov     rbp, [r9+28h]
0x334F30: 0FAE95A8000000                   ldmxcsr dword ptr [rbp+0A8h]
0x334F9E: 48BB5362C22601000000             mov     rbx, 126C26253h
0x33500E: 4881C36D004719                   add     rbx, 1947006Dh
0x335079: 488B9B40020000                   mov     rbx, [rbx+240h]
0x3350DE: 48039DA8000000                   add     rbx, [rbp+0A8h]
0x031F1E: 448A1B                           mov     r11b, [rbx]
0x031F21: 4D0FB6DB                         movzx   r11, r11b
0x031F25: 49C1E308                         shl     r11, 8
0x335145: 4C019DB0000000                   add     [rbp+0B0h], r11
0x031F30: 498B7128                         mov     rsi, [r9+28h]
0x3351AF: 488BB6B0000000                   mov     rsi, [rsi+0B0h]
0x335217: 49BD1D045D3B01000000             mov     r13, 13B5D041Dh
0x335285: 4981C5A356AC04                   add     r13, 4AC56A3h
0x032033: 4D8B4928                         mov     r9, [r9+28h]
0x032037: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x33535A: 4D8BA1C8000000                   mov     r12, [r9+0C8h]
0x3353C3: 498BA9A8000000                   mov     rbp, [r9+0A8h]
0x032120: 4D8B7928                         mov     r15, [r9+28h]
0x335495: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x03212B: 458B4734                         mov     r8d, [r15+34h]
0x335501: 4D0387D8000000                   add     r8, [r15+0D8h]
0x032136: 418A28                           mov     bpl, [r8]
0x032139: 4088EB                           mov     bl, bpl
0x032216: 498B4928                         mov     rcx, [r9+28h]
0x3355D1: 4C8B9190000000                   mov     r10, [rcx+90h]
0x032221: 4152                             push    r10
0x032223: 4889E6                           mov     rsi, rsp
0x33563A: 4C8BA190000000                   mov     r12, [rcx+90h]
0x032302: 4D8B6128                         mov     r12, [r9+28h]
0x335702: 498BAC24A8000000                 mov     rbp, [r12+0A8h]
0x335769: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x032316: 55                               push    rbp
0x032317: 68CF3A597B                       push    7B593ACFh
0x03231C: 689775BB4D                       push    4DBB7597h
0x032321: 6869410040                       push    40004169h
0x03241E: 4D8B4128                         mov     r8, [r9+28h]
0x33583B: 4D8BB8B0000000                   mov     r15, [r8+0B0h]
0x3358A1: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x032430: 4D0FB6FF                         movzx   r15, r15b
0x03250F: 4D8B6928                         mov     r13, [r9+28h]
0x335970: 410FAE95F0000000                 ldmxcsr dword ptr [r13+0F0h]
0x3359D8: 48BFF7FD191C01000000             mov     rdi, 11C19FDF7h
0x335A46: 4881C7C964EF23                   add     rdi, 23EF64C9h
0x335AB3: 488BBF70020000                   mov     rdi, [rdi+270h]
0x335B1A: 4903BDF0000000                   add     rdi, [r13+0F0h]
0x03253A: 408A37                           mov     sil, [rdi]
0x03253D: 480FB6F6                         movzx   rsi, sil
0x032541: 48C1E610                         shl     rsi, 10h
0x335B80: 4901B5A8000000                   add     [r13+0A8h], rsi
0x03254C: 4D8B6128                         mov     r12, [r9+28h]
0x335BE8: 498BAC24A8000000                 mov     rbp, [r12+0A8h]
0x335C53: 48BF0BE7151901000000             mov     rdi, 11915E70Bh
0x335CBD: 4881C7B573F326                   add     rdi, 26F373B5h
0x032654: 4D8B7128                         mov     r14, [r9+28h]
0x032658: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x335D8F: 4D8BA6B0000000                   mov     r12, [r14+0B0h]
0x335DF8: 4D8BAEA0000000                   mov     r13, [r14+0A0h]
0x032741: 498B4128                         mov     rax, [r9+28h]
0x335ECA: 488BB8E0000000                   mov     rdi, [rax+0E0h]
0x03274C: 448B5034                         mov     r10d, [rax+34h]
0x335F36: 4C0390D8000000                   add     r10, [rax+0D8h]
0x032757: 458A22                           mov     r12b, [r10]
0x335FA4: 48C7C3FF000000                   mov     rbx, 0FFh
0x032761: 48C1E308                         shl     rbx, 8
0x032765: 48F7D3                           not     rbx
0x032768: 4821DF                           and     rdi, rbx
0x03276B: 490FB6DC                         movzx   rbx, r12b
0x03276F: 48C1E308                         shl     rbx, 8
0x032773: 4809DF                           or      rdi, rbx
0x032850: 498B7928                         mov     rdi, [r9+28h]
0x336079: 4C8BAFB0000000                   mov     r13, [rdi+0B0h]
0x03285B: 4155                             push    r13
0x03285D: 4989E4                           mov     r12, rsp
0x3360E1: 4C8BBFB0000000                   mov     r15, [rdi+0B0h]
0x03293E: 4D8B6128                         mov     r12, [r9+28h]
0x3361B0: 498BBC24D8000000                 mov     rdi, [r12+0D8h]
0x336219: 4D8BBC24F0000000                 mov     r15, [r12+0F0h]
0x032952: 57                               push    rdi
0x032953: 68F26F277D                       push    7D276FF2h
0x032958: 689F7E2271                       push    71227E9Fh
0x03295D: 68461E820C                       push    0C821E46h
0x032962: 684D1F3A6F                       push    6F3A1F4Dh
0x032A5D: 4D8B5928                         mov     r11, [r9+28h]
0x032A61: 498B6B78                         mov     rbp, [r11+78h]
0x3362EA: 4D8BABF0000000                   mov     r13, [r11+0F0h]
0x032A6C: 480FB6ED                         movzx   rbp, bpl
0x032B57: 4D8B4128                         mov     r8, [r9+28h]
0x3363B9: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x336426: 49BD6D2C373401000000             mov     r13, 134372C6Dh
0x336491: 4981C55336D20B                   add     r13, 0BD23653h
0x3364FF: 4D8BAD80070000                   mov     r13, [r13+780h]
0x336564: 4D03A8A0000000                   add     r13, [r8+0A0h]
0x032B82: 458A6D00                         mov     r13b, [r13+0]
0x032B86: 4D0FB6ED                         movzx   r13, r13b
0x032B8A: 49C1E518                         shl     r13, 18h
0x3365CE: 4D01A8E0000000                   add     [r8+0E0h], r13
0x032B95: 4D8B4128                         mov     r8, [r9+28h]
0x336633: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x33669E: 49BE90FCE4CB00000000             mov     r14, 0CBE4FC90h
0x336709: 4981C6305E2474                   add     r14, 74245E30h
0x032CA3: 498B7128                         mov     rsi, [r9+28h]
0x032CA7: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x3367D8: 4C8BAEA8000000                   mov     r13, [rsi+0A8h]
0x336845: 488BBEE0000000                   mov     rdi, [rsi+0E0h]
0x032DB0: 4D8B7928                         mov     r15, [r9+28h]
0x33691D: 498B9FB0000000                   mov     rbx, [r15+0B0h]
0x032DBB: 418B4734                         mov     eax, [r15+34h]
0x336988: 490387E0000000                   add     rax, [r15+0E0h]
0x032DC6: 448A18                           mov     r11b, [rax]
0x3369F5: 48C7C6FF000000                   mov     rsi, 0FFh
0x032DD0: 48C1E610                         shl     rsi, 10h
0x032DD4: 48F7D6                           not     rsi
0x032DD7: 4821F3                           and     rbx, rsi
0x032DDA: 490FB6F3                         movzx   rsi, r11b
0x032DDE: 48C1E610                         shl     rsi, 10h
0x032DE2: 4809F3                           or      rbx, rsi
0x032EC5: 4D8B7128                         mov     r14, [r9+28h]
0x336AC6: 4D8BAE90000000                   mov     r13, [r14+90h]
0x032ED0: 4155                             push    r13
0x032ED2: 4889E3                           mov     rbx, rsp
0x336B30: 498BBE90000000                   mov     rdi, [r14+90h]
0x032FCA: 498B7928                         mov     rdi, [r9+28h]
0x336C00: 4C8BA7C8000000                   mov     r12, [rdi+0C8h]
0x336C68: 4C8BAFB0000000                   mov     r13, [rdi+0B0h]
0x032FDC: 4D0FB6E4                         movzx   r12, r12b
0x0330C6: 4D8B4128                         mov     r8, [r9+28h]
0x336D3C: 410FAE90D8000000                 ldmxcsr dword ptr [r8+0D8h]
0x336DAB: 48B96B21DB1B01000000             mov     rcx, 11BDB216Bh
0x336E1C: 4881C155412E24                   add     rcx, 242E4155h
0x336E83: 488B8928030000                   mov     rcx, [rcx+328h]
0x336EEF: 490388D8000000                   add     rcx, [r8+0D8h]
0x0330F1: 448A11                           mov     r10b, [rcx]
0x0330F4: 4D0FB6D2                         movzx   r10, r10b
0x0330F8: 49C1E220                         shl     r10, 20h
0x336F5A: 4D0190E0000000                   add     [r8+0E0h], r10
0x033103: 4D8B4928                         mov     r9, [r9+28h]
0x336FC2: 4D8BA9E0000000                   mov     r13, [r9+0E0h]
0x337029: 49BCC94228C800000000             mov     r12, 0C82842C9h
0x337091: 4981C4F717E177                   add     r12, 77E117F7h
0x0331F8: 498B4128                         mov     rax, [r9+28h]
0x0331FC: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x33715D: 488BA890000000                   mov     rbp, [rax+90h]
0x3371C2: 488BB0E0000000                   mov     rsi, [rax+0E0h]
0x0332E2: 4D8B6928                         mov     r13, [r9+28h]
0x337292: 498B9DA8000000                   mov     rbx, [r13+0A8h]
0x0332ED: 458B4D34                         mov     r9d, [r13+34h]
0x3372F8: 4D038DA0000000                   add     r9, [r13+0A0h]
0x0332F8: 458A29                           mov     r13b, [r9]
0x337365: 48C7C6FF000000                   mov     rsi, 0FFh
0x033302: 48C1E618                         shl     rsi, 18h
0x033306: 48F7D6                           not     rsi
0x033309: 4821F3                           and     rbx, rsi
0x03330C: 490FB6F5                         movzx   rsi, r13b
0x033310: 48C1E618                         shl     rsi, 18h
0x033314: 4809F3                           or      rbx, rsi
0x0333F5: 4D8B5928                         mov     r11, [r9+28h]
0x33743B: 4D8B9390000000                   mov     r10, [r11+90h]
0x033400: 4152                             push    r10
0x033402: 4889E3                           mov     rbx, rsp
0x3374A5: 4D8BB390000000                   mov     r14, [r11+90h]
0x0334FD: 498B5928                         mov     rbx, [r9+28h]
0x337570: 4C8BA3D8000000                   mov     r12, [rbx+0D8h]
0x3375D5: 4C8BBBE8000000                   mov     r15, [rbx+0E8h]
0x03350F: 4D0FB6E4                         movzx   r12, r12b
0x0335F5: 498B6928                         mov     rbp, [r9+28h]
0x3376A5: 0FAE95D8000000                   ldmxcsr dword ptr [rbp+0D8h]
0x337712: 49BF6840C3FB00000000             mov     r15, 0FBC34068h
0x33777B: 4981C758224644                   add     r15, 44462258h
0x033611: 4D8B3F                           mov     r15, [r15]
0x3377E2: 4C03BDD8000000                   add     r15, [rbp+0D8h]
0x03361B: 418A3F                           mov     dil, [r15]
0x03361E: 480FB6FF                         movzx   rdi, dil
0x033622: 48C1E728                         shl     rdi, 28h
0x33784F: 4801BDF0000000                   add     [rbp+0F0h], rdi
0x03362D: 4D8B4928                         mov     r9, [r9+28h]
0x3378B5: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x33791A: 49BC59E2CFC700000000             mov     r12, 0C7CFE259h
0x33798A: 4981C467783978                   add     r12, 78397867h
0x03372A: 4D8B5928                         mov     r11, [r9+28h]
0x03372E: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x337A5F: 498BB380000000                   mov     rsi, [r11+80h]
0x337AC6: 498BABB0000000                   mov     rbp, [r11+0B0h]
0x03381C: 498B6928                         mov     rbp, [r9+28h]
0x337B96: 488B9DA0000000                   mov     rbx, [rbp+0A0h]
0x033827: 8B4534                           mov     eax, [rbp+34h]
0x337C02: 480385A8000000                   add     rax, [rbp+0A8h]
0x033831: 448A20                           mov     r12b, [rax]
0x337C6D: 49C7C3FF000000                   mov     r11, 0FFh
0x03383B: 49C1E320                         shl     r11, 20h
0x03383F: 49F7D3                           not     r11
0x033842: 4C21DB                           and     rbx, r11
0x033845: 4D0FB6DC                         movzx   r11, r12b
0x033849: 49C1E320                         shl     r11, 20h
0x03384D: 4C09DB                           or      rbx, r11
0x033929: 498B5128                         mov     rdx, [r9+28h]
0x337D39: 4C8BAA90000000                   mov     r13, [rdx+90h]
0x033934: 4155                             push    r13
0x033936: 4889E6                           mov     rsi, rsp
0x337DA2: 4C8BBA90000000                   mov     r15, [rdx+90h]
0x033A39: 4D8B6128                         mov     r12, [r9+28h]
0x337E74: 498B8424A8000000                 mov     rax, [r12+0A8h]
0x337EDF: 498BB424F0000000                 mov     rsi, [r12+0F0h]
0x033A4D: 50                               push    rax
0x033A4E: 680915A963                       push    63A91509h
0x033A53: 68B5473D66                       push    663D47B5h
0x033A58: 684F3B0938                       push    38093B4Fh
0x033B44: 498B4928                         mov     rcx, [r9+28h]
0x033B48: 488B5978                         mov     rbx, [rcx+78h]
0x337FB6: 488BA9A8000000                   mov     rbp, [rcx+0A8h]
0x033B53: 480FB6DB                         movzx   rbx, bl
0x033C4B: 498B5928                         mov     rbx, [r9+28h]
0x338088: 0FAE9390000000                   ldmxcsr dword ptr [rbx+90h]
0x3380F6: 49B82AFA99DC00000000             mov     r8, 0DC99FA2Ah
0x338162: 4981C096686F63                   add     r8, 636F6896h
0x033C67: 4D8B00                           mov     r8, [r8]
0x3381C8: 4C038390000000                   add     r8, [rbx+90h]
0x033C71: 418A10                           mov     dl, [r8]
0x033C74: 480FB6D2                         movzx   rdx, dl
0x033C78: 48C1E238                         shl     rdx, 38h
0x33822E: 480193A0000000                   add     [rbx+0A0h], rdx
0x338295: 48BEE1EFD32601000000             mov     rsi, 126D3EFE1h
0x033C8D: 56                               push    rsi
0x033C8E: 680D0BAA14                       push    14AA0B0Dh
0x033C93: 685819EA29                       push    29EA1958h
0x033C98: 68D552E564                       push    64E552D5h
0x033C9D: 6810029F64                       push    649F0210h
0x3382FF: 4881442420DF6A3519               add     [rsp-8+arg_20], 19356ADFh
0x033CAB: 4D8B7128                         mov     r14, [r9+28h]
0x33836B: 4D8BA6A0000000                   mov     r12, [r14+0A0h]
0x033D94: 4D8B4928                         mov     r9, [r9+28h]
0x033D98: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x338439: 498B99B0000000                   mov     rbx, [r9+0B0h]
0x3384A3: 498BA9D8000000                   mov     rbp, [r9+0D8h]
0x033E91: 498B5928                         mov     rbx, [r9+28h]
0x338573: 4C8BBBA0000000                   mov     r15, [rbx+0A0h]
0x033E9C: 8B4334                           mov     eax, [rbx+34h]
0x3385D9: 48038390000000                   add     rax, [rbx+90h]
0x033EA6: 448A28                           mov     r13b, [rax]
0x33863E: 49C7C2FF000000                   mov     r10, 0FFh
0x033EB0: 49C1E230                         shl     r10, 30h
0x033EB4: 49F7D2                           not     r10
0x033EB7: 4D21D7                           and     r15, r10
0x033EBA: 4D0FB6D5                         movzx   r10, r13b
0x033EBE: 49C1E230                         shl     r10, 30h
0x033EC2: 4D09D7                           or      r15, r10
0x338710: 48BF4254573501000000             mov     rdi, 135575442h
0x033FA8: 57                               push    rdi
0x033FA9: 68654FFA4F                       push    4FFA4F65h
0x033FAE: 689D48C209                       push    9C2489Dh
0x033FB3: 689A36ED4A                       push    4AED369Ah
0x033FB8: 683030DD66                       push    66DD3030h
0x338778: 4881442420A664320B               add     [rsp-8+arg_20], 0B3264A6h
0x033FC6: 4D8B4928                         mov     r9, [r9+28h]
0x3387E6: 4D8BB9F0000000                   mov     r15, [r9+0F0h]
0x0340C5: 4D8B4928                         mov     r9, [r9+28h]
0x3388AF: 498BA9B0000000                   mov     rbp, [r9+0B0h]
0x33891C: 4D8BB1F0000000                   mov     r14, [r9+0F0h]
0x0340D7: 480FB6ED                         movzx   rbp, bpl
0x0341B7: 4D8B7928                         mov     r15, [r9+28h]
0x3389E4: 498B87A0000000                   mov     rax, [r15+0A0h]
0x338A4F: 49C7C2B73617AE                   mov     r10, 0FFFFFFFFAE1736B7h
0x338ABC: 4981C2900B9352                   add     r10, 52930B90h
0x0341D0: 4152                             push    r10
0x338B24: 4D8BB7E8000000                   mov     r14, [r15+0E8h]
0x0341D9: 48F72424                         mul     qword ptr [rsp]
0x0341DD: 4889C7                           mov     rdi, rax
0x0342C5: 4D8B7128                         mov     r14, [r9+28h]
0x338BF3: 498BB6E8000000                   mov     rsi, [r14+0E8h]
0x338C5F: 492BB6B0000000                   sub     rsi, [r14+0B0h]
0x0343B9: 4D8B6128                         mov     r12, [r9+28h]
0x338D2D: 4D8BBC24A8000000                 mov     r15, [r12+0A8h]
0x0343C5: 4157                             push    r15
0x0343C7: 4989E6                           mov     r14, rsp
0x338D99: 498B9C24A8000000                 mov     rbx, [r12+0A8h]
0x0344A8: 4D8B6128                         mov     r12, [r9+28h]
0x338E6F: 4D8BB424E8000000                 mov     r14, [r12+0E8h]
0x338EDA: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x0344BC: 4156                             push    r14
0x0344BE: 68537CBE0E                       push    0EBE7C53h
0x0344C3: 68C76B7D71                       push    717D6BC7h
0x0344C8: 68DB3C726C                       push    6C723CDBh
0x0344CD: 68CB7FD515                       push    15D57FCBh
0x0345BB: 498B5928                         mov     rbx, [r9+28h]
0x338FAA: 4C8BABA8000000                   mov     r13, [rbx+0A8h]
0x339013: 488B9BF0000000                   mov     rbx, [rbx+0F0h]
0x0345CD: 4D0FB6ED                         movzx   r13, r13b
0x0346AE: 498B4128                         mov     rax, [r9+28h]
0x3390E1: 0FAE90E0000000                   ldmxcsr dword ptr [rax+0E0h]
0x339148: 48BA95D9F2DC00000000             mov     rdx, 0DCF2D995h
0x0346C3: 52                               push    rdx
0x0346C4: 68517DA05B                       push    5BA07D51h
0x0346C9: 68E202FF2A                       push    2AFF02E2h
0x0346CE: 68A86B9A06                       push    69A6BA8h
0x3391B5: 48814424182B711663               add     qword ptr [rsp+18h], 6316712Bh
0x0346DC: 4D8B6928                         mov     r13, [r9+28h]
0x339225: 498BAD90000000                   mov     rbp, [r13+90h]
0x0347C9: 498B4128                         mov     rax, [r9+28h]
0x0347CD: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x3392F3: 4C8BB0B8000000                   mov     r14, [rax+0B8h]
0x33935D: 488B98A0000000                   mov     rbx, [rax+0A0h]
0x0348BE: 4D8B5928                         mov     r11, [r9+28h]
0x33942A: 498BBB90000000                   mov     rdi, [r11+90h]
0x0348C9: 418B6B34                         mov     ebp, [r11+34h]
0x339492: 4903ABE8000000                   add     rbp, [r11+0E8h]
0x0348D4: 448A4500                         mov     r8b, [rbp+0]
0x0348D8: 4488C7                           mov     dil, r8b
0x0349B5: 4D8B5128                         mov     r10, [r9+28h]
0x33955A: 498BAAB0000000                   mov     rbp, [r10+0B0h]
0x0349C0: 55                               push    rbp
0x0349C1: 4889E7                           mov     rdi, rsp
0x3395C1: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x034AB1: 498B4128                         mov     rax, [r9+28h]
0x339693: 488B98B0000000                   mov     rbx, [rax+0B0h]
0x339701: 488BA890000000                   mov     rbp, [rax+90h]
0x034AC3: 53                               push    rbx
0x034AC4: 68251C4F58                       push    584F1C25h
0x034AC9: 683E24D757                       push    57D7243Eh
0x034ACE: 68CF6CD17C                       push    7CD16CCFh
0x034AD3: 681E11464E                       push    4E46111Eh
0x034BC1: 498B7928                         mov     rdi, [r9+28h]
0x3397D2: 4C8BA7D8000000                   mov     r12, [rdi+0D8h]
0x33983E: 4C8BAFA0000000                   mov     r13, [rdi+0A0h]
0x034BD3: 4D0FB6E4                         movzx   r12, r12b
0x034CB4: 4D8B5128                         mov     r10, [r9+28h]
0x33990F: 410FAE92D8000000                 ldmxcsr dword ptr [r10+0D8h]
0x33997E: 48BBBDF5311E01000000             mov     rbx, 11E31F5BDh
0x034CCA: 53                               push    rbx
0x034CCB: 6873494908                       push    8494973h
0x034CD0: 68F74ACB64                       push    64CB4AF7h
0x034CD5: 686913306E                       push    6E301369h
0x034CDA: 68DA58B240                       push    40B258DAh
0x3399ED: 48814424200355D721               add     qword ptr [rsp+20h], 21D75503h
0x034CE8: 498B4128                         mov     rax, [r9+28h]
0x339A5A: 4C8BB0E0000000                   mov     r14, [rax+0E0h]
0x034DCE: 498B7928                         mov     rdi, [r9+28h]
0x034DD2: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x339B2F: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x339B95: 488BB7E8000000                   mov     rsi, [rdi+0E8h]
0x034EC5: 4D8B6128                         mov     r12, [r9+28h]
0x339C6D: 498BBC24A8000000                 mov     rdi, [r12+0A8h]
0x034ED1: 458B742434                       mov     r14d, [r12+34h]
0x339CDB: 4D03B424E0000000                 add     r14, [r12+0E0h]
0x034EDE: 458A16                           mov     r10b, [r14]
0x339D43: 48C7C1FF000000                   mov     rcx, 0FFh
0x034EE8: 48C1E108                         shl     rcx, 8
0x034EEC: 48F7D1                           not     rcx
0x034EEF: 4821CF                           and     rdi, rcx
0x034EF2: 490FB6CA                         movzx   rcx, r10b
0x034EF6: 48C1E108                         shl     rcx, 8
0x034EFA: 4809CF                           or      rdi, rcx
0x034FDC: 4D8B4128                         mov     r8, [r9+28h]
0x339E13: 4D8B98B0000000                   mov     r11, [r8+0B0h]
0x034FE7: 4153                             push    r11
0x034FE9: 4889E7                           mov     rdi, rsp
0x339E78: 4D8BA0B0000000                   mov     r12, [r8+0B0h]
0x0350CF: 4D8B7128                         mov     r14, [r9+28h]
0x339F45: 4D8B86B0000000                   mov     r8, [r14+0B0h]
0x339FAC: 4D8BBED8000000                   mov     r15, [r14+0D8h]
0x0350E1: 4150                             push    r8
0x0350E3: 68941BA060                       push    60A01B94h
0x0350E8: 68BF230A4B                       push    4B0A23BFh
0x0350ED: 68E64C0C43                       push    430C4CE6h
0x0350F2: 68734E1916                       push    16194E73h
0x0351E5: 4D8B4128                         mov     r8, [r9+28h]
0x33A085: 498BA888000000                   mov     rbp, [r8+88h]
0x33A0F2: 4D8BA8F0000000                   mov     r13, [r8+0F0h]
0x0351F7: 480FB6ED                         movzx   rbp, bpl
0x0352DA: 498B5128                         mov     rdx, [r9+28h]
0x33A1BF: 0FAE92A0000000                   ldmxcsr dword ptr [rdx+0A0h]
0x33A229: 49BFB70F350D01000000             mov     r15, 10D350FB7h
0x0352EF: 4157                             push    r15
0x0352F1: 686A27332D                       push    2D33276Ah
0x0352F6: 68EA4A8417                       push    17844AEAh
0x0352FB: 68A767DE1F                       push    1FDE67A7h
0x33A299: 4881442418093BD432               add     qword ptr [rsp+18h], 32D43B09h
0x035309: 498B5128                         mov     rdx, [r9+28h]
0x33A307: 4C8BA2E0000000                   mov     r12, [rdx+0E0h]
0x0353F5: 498B5128                         mov     rdx, [r9+28h]
0x0353F9: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x33A3DF: 4C8BAAC8000000                   mov     r13, [rdx+0C8h]
0x33A449: 488BBAD8000000                   mov     rdi, [rdx+0D8h]
0x0354ED: 4D8B4928                         mov     r9, [r9+28h]
0x33A517: 4D8BA1B0000000                   mov     r12, [r9+0B0h]
0x0354F8: 458B7934                         mov     r15d, [r9+34h]
0x33A584: 4D03B9E0000000                   add     r15, [r9+0E0h]
0x035503: 458A37                           mov     r14b, [r15]
0x33A5E9: 48C7C7FF000000                   mov     rdi, 0FFh
0x03550D: 48C1E710                         shl     rdi, 10h
0x035511: 48F7D7                           not     rdi
0x035514: 4921FC                           and     r12, rdi
0x035517: 490FB6FE                         movzx   rdi, r14b
0x03551B: 48C1E710                         shl     rdi, 10h
0x03551F: 4909FC                           or      r12, rdi
0x035603: 498B7128                         mov     rsi, [r9+28h]
0x33A6C3: 4C8B96D8000000                   mov     r10, [rsi+0D8h]
0x03560E: 4152                             push    r10
0x035610: 4889E5                           mov     rbp, rsp
0x33A72A: 4C8BB6D8000000                   mov     r14, [rsi+0D8h]
0x035713: 498B6928                         mov     rbp, [r9+28h]
0x33A7FE: 4C8BADA8000000                   mov     r13, [rbp+0A8h]
0x33A863: 4C8BB5E8000000                   mov     r14, [rbp+0E8h]
0x035725: 4D0FB6ED                         movzx   r13, r13b
0x035819: 4D8B7128                         mov     r14, [r9+28h]
0x33A930: 410FAE96E0000000                 ldmxcsr dword ptr [r14+0E0h]
0x33A99A: 48BE2C1B51F500000000             mov     rsi, 0F5511B2Ch
0x03582F: 56                               push    rsi
0x035830: 686772B87A                       push    7AB87267h
0x035835: 689863B263                       push    63B26398h
0x03583A: 68A932A519                       push    19A532A9h
0x33AA04: 4881442418942FB84A               add     qword ptr [rsp+18h], 4AB82F94h
0x035848: 4D8B6928                         mov     r13, [r9+28h]
0x33AA6E: 4D8BBDE8000000                   mov     r15, [r13+0E8h]
0x035927: 498B7128                         mov     rsi, [r9+28h]
0x03592B: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x33AB41: 488BBE90000000                   mov     rdi, [rsi+90h]
0x33ABAC: 4C8BB6F0000000                   mov     r14, [rsi+0F0h]
0x035A11: 4D8B4928                         mov     r9, [r9+28h]
0x33AC79: 4D8BA9E8000000                   mov     r13, [r9+0E8h]
0x035A1C: 458B5934                         mov     r11d, [r9+34h]
0x33ACDE: 4D0399B0000000                   add     r11, [r9+0B0h]
0x035A27: 418A03                           mov     al, [r11]
0x33AD48: 49C7C6FF000000                   mov     r14, 0FFh
0x035A31: 49C1E618                         shl     r14, 18h
0x035A35: 49F7D6                           not     r14
0x035A38: 4D21F5                           and     r13, r14
0x035A3B: 4C0FB6F0                         movzx   r14, al
0x035A3F: 49C1E618                         shl     r14, 18h
0x035A43: 4D09F5                           or      r13, r14
0x035B21: 498B4128                         mov     rax, [r9+28h]
0x33AE15: 4C8B98E0000000                   mov     r11, [rax+0E0h]
0x035B2C: 4153                             push    r11
0x035B2E: 4989E6                           mov     r14, rsp
0x33AE7A: 4C8BA0E0000000                   mov     r12, [rax+0E0h]
0x035C14: 498B7928                         mov     rdi, [r9+28h]
0x33AF44: 4C8BBF80000000                   mov     r15, [rdi+80h]
0x33AFAB: 488BB7D8000000                   mov     rsi, [rdi+0D8h]
0x035C26: 4D0FB6FF                         movzx   r15, r15b
0x035D0E: 498B7128                         mov     rsi, [r9+28h]
0x33B07A: 0FAE96F0000000                   ldmxcsr dword ptr [rsi+0F0h]
0x035D19: 498B7928                         mov     rdi, [r9+28h]
0x33B0E7: 488B9FA8000000                   mov     rbx, [rdi+0A8h]
0x33B14E: 48BE6B207EF200000000             mov     rsi, 0F27E206Bh
0x33B1BC: 4881C6552A8B4D                   add     rsi, 4D8B2A55h
0x035E0B: 4D8B4128                         mov     r8, [r9+28h]
0x035E0F: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x33B290: 498BB0A0000000                   mov     rsi, [r8+0A0h]
0x33B2F5: 498BB890000000                   mov     rdi, [r8+90h]
0x035F0A: 498B5128                         mov     rdx, [r9+28h]
0x33B3C4: 488BBAB0000000                   mov     rdi, [rdx+0B0h]
0x035F15: 8B5A34                           mov     ebx, [rdx+34h]
0x33B430: 48039AA8000000                   add     rbx, [rdx+0A8h]
0x035F1F: 8A03                             mov     al, [rbx]
0x33B49C: 48C7C3FF000000                   mov     rbx, 0FFh
0x035F28: 48C1E328                         shl     rbx, 28h
0x035F2C: 48F7D3                           not     rbx
0x035F2F: 4821DF                           and     rdi, rbx
0x035F32: 480FB6D8                         movzx   rbx, al
0x035F36: 48C1E328                         shl     rbx, 28h
0x035F3A: 4809DF                           or      rdi, rbx
0x036026: 4D8B6128                         mov     r12, [r9+28h]
0x33B56A: 498B9C24B0000000                 mov     rbx, [r12+0B0h]
0x036032: 53                               push    rbx
0x036033: 4889E3                           mov     rbx, rsp
0x33B5D2: 498BB424B0000000                 mov     rsi, [r12+0B0h]
0x03611D: 498B6928                         mov     rbp, [r9+28h]
0x33B6A3: 4C8B8D90000000                   mov     r9, [rbp+90h]
0x33B70D: 488BBDA8000000                   mov     rdi, [rbp+0A8h]
0x03612F: 4151                             push    r9
0x036131: 686705A165                       push    65A10567h
0x036136: 68143DCC36                       push    36CC3D14h
0x03613B: 681D50AC1C                       push    1CAC501Dh
0x036140: 681A363814                       push    1438361Ah
0x036237: 4D8B6928                         mov     r13, [r9+28h]
0x33B7DA: 4D8BB5C0000000                   mov     r14, [r13+0C0h]
0x33B842: 498BADB0000000                   mov     rbp, [r13+0B0h]
0x036249: 4D0FB6F6                         movzx   r14, r14b
0x036332: 4D8B5128                         mov     r10, [r9+28h]
0x33B917: 410FAE92E8000000                 ldmxcsr dword ptr [r10+0E8h]
0x03633E: 4D8B6128                         mov     r12, [r9+28h]
0x33B97D: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x33B9E3: 48BB0636D4CE00000000             mov     rbx, 0CED43606h
0x33BA51: 4881C3BA143571                   add     rbx, 713514BAh
0x03643D: 4D8B7128                         mov     r14, [r9+28h]
0x036441: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x33BB25: 4D8BAEA8000000                   mov     r13, [r14+0A8h]
0x33BB8E: 498BB6E0000000                   mov     rsi, [r14+0E0h]
0x036532: 498B7128                         mov     rsi, [r9+28h]
0x33BC63: 4C8BB6A8000000                   mov     r14, [rsi+0A8h]
0x03653D: 8B7E34                           mov     edi, [rsi+34h]
0x33BCC8: 4803BEE0000000                   add     rdi, [rsi+0E0h]
0x036547: 448A1F                           mov     r11b, [rdi]
0x33BD30: 48C7C6FF000000                   mov     rsi, 0FFh
0x036551: 48C1E638                         shl     rsi, 38h
0x036555: 48F7D6                           not     rsi
0x036558: 4921F6                           and     r14, rsi
0x03655B: 490FB6F3                         movzx   rsi, r11b
0x03655F: 48C1E638                         shl     rsi, 38h
0x036563: 4909F6                           or      r14, rsi
0x036649: 498B7128                         mov     rsi, [r9+28h]
0x33BDFD: 4C8BA6E8000000                   mov     r12, [rsi+0E8h]
0x33BE67: 48BBBD489C2101000000             mov     rbx, 1219C48BDh
0x33BED1: 4881C32B70ED1E                   add     rbx, 1EED702Bh
0x036751: 498B5928                         mov     rbx, [r9+28h]
0x33BF9F: 4C8BABF0000000                   mov     r13, [rbx+0F0h]
0x33C00C: 488BB3D8000000                   mov     rsi, [rbx+0D8h]
0x036763: 4D0FB6ED                         movzx   r13, r13b
0x036847: 498B6928                         mov     rbp, [r9+28h]
0x33C0D9: 488B85E0000000                   mov     rax, [rbp+0E0h]
0x33C13E: 49C7C04D6C0E00                   mov     r8, 0E6C4Dh
0x33C1AC: 4981C0E06B2A00                   add     r8, 2A6BE0h
0x036860: 4150                             push    r8
0x33C215: 488BADA8000000                   mov     rbp, [rbp+0A8h]
0x036869: 48F72424                         mul     qword ptr [rsp]
0x03686D: 4989C5                           mov     r13, rax
0x03695E: 498B7928                         mov     rdi, [r9+28h]
0x33C2EA: 488BB7A0000000                   mov     rsi, [rdi+0A0h]
0x33C351: 4833B7E0000000                   xor     rsi, [rdi+0E0h]
0x036A49: 498B4128                         mov     rax, [r9+28h]
0x33C424: 4C8B90A8000000                   mov     r10, [rax+0A8h]
0x036A54: 4152                             push    r10
0x036A56: 4889E6                           mov     rsi, rsp
0x33C48D: 4C8BA0A8000000                   mov     r12, [rax+0A8h]
0x036B31: 498B5128                         mov     rdx, [r9+28h]
0x33C55E: 4C8BBAC0000000                   mov     r15, [rdx+0C0h]
0x33C5C5: 488B9AD8000000                   mov     rbx, [rdx+0D8h]
0x036B43: 4D0FB6FF                         movzx   r15, r15b
0x036C1D: 498B4128                         mov     rax, [r9+28h]
0x33C691: 0FAE90F0000000                   ldmxcsr dword ptr [rax+0F0h]
0x33C6F8: 48BB1625B6E900000000             mov     rbx, 0E9B62516h
0x036C32: 53                               push    rbx
0x036C33: 688B44BD29                       push    29BD448Bh
0x036C38: 6843194E21                       push    214E1943h
0x036C3D: 688B292903                       push    329298Bh
0x036C42: 685F62C674                       push    74C6625Fh
0x33C766: 4881442420AA255356               add     qword ptr [rsp+20h], 565325AAh
0x036C50: 4D8B6128                         mov     r12, [r9+28h]
0x33C7D0: 498BAC2490000000                 mov     rbp, [r12+90h]
0x036D40: 4D8B6128                         mov     r12, [r9+28h]
0x33C8A6: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x33C90C: 498BBC24F0000000                 mov     rdi, [r12+0F0h]
0x33C979: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x036E33: 498B7128                         mov     rsi, [r9+28h]
0x33CA4E: 4C8BAEE0000000                   mov     r13, [rsi+0E0h]
0x036E3E: 448B4634                         mov     r8d, [rsi+34h]
0x33CAB7: 4C0386B0000000                   add     r8, [rsi+0B0h]
0x036E49: 418A08                           mov     cl, [r8]
0x036E4C: 4188CD                           mov     r13b, cl
0x036F28: 4D8B4128                         mov     r8, [r9+28h]
0x33CB83: 498BA8E0000000                   mov     rbp, [r8+0E0h]
0x036F33: 55                               push    rbp
0x036F34: 4889E5                           mov     rbp, rsp
0x33CBF0: 4D8BA0E0000000                   mov     r12, [r8+0E0h]
0x037019: 4D8B6928                         mov     r13, [r9+28h]
0x33CCBE: 498B8DA0000000                   mov     rcx, [r13+0A0h]
0x33CD27: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x03702B: 51                               push    rcx
0x03702C: 68CE5BA75A                       push    5AA75BCEh
0x037031: 68EA09AC0E                       push    0EAC09EAh
0x037036: 68F946CA0F                       push    0FCA46F9h
0x03703B: 68FF30BC16                       push    16BC30FFh
0x037121: 4D8B7128                         mov     r14, [r9+28h]
0x037125: 4D8B6E78                         mov     r13, [r14+78h]
0x33CDFF: 498BB6A8000000                   mov     rsi, [r14+0A8h]
0x037130: 4D0FB6ED                         movzx   r13, r13b
0x03721D: 498B7128                         mov     rsi, [r9+28h]
0x33CED4: 0FAE96E0000000                   ldmxcsr dword ptr [rsi+0E0h]
0x33CF3D: 48BA36DE493F01000000             mov     rdx, 13F49DE36h
0x037232: 52                               push    rdx
0x037233: 68E52E8F79                       push    798F2EE5h
0x037238: 68EF19AB78                       push    78AB19EFh
0x03723D: 680D1A9145                       push    45911A0Dh
0x037242: 681A409A5D                       push    5D9A401Ah
0x33CFA8: 48814424208A6CBF00               add     qword ptr [rsp+20h], 0BF6C8Ah
0x037250: 4D8B7928                         mov     r15, [r9+28h]
0x33D017: 4D8BAFA8000000                   mov     r13, [r15+0A8h]
0x037339: 498B4928                         mov     rcx, [r9+28h]
0x03733D: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x33D0EA: 488BA9A0000000                   mov     rbp, [rcx+0A0h]
0x33D151: 4C8BA9E0000000                   mov     r13, [rcx+0E0h]
0x03741E: 4D8B5128                         db  4Dh ; M
0x33D227: 4D8BAAE0000000                   mov     r13, [r10+0E0h]
0x037429: 458B7A34                         mov     r15d, [r10+34h]
0x33D295: 4D03BAA0000000                   add     r15, [r10+0A0h]
0x037434: 458A27                           mov     r12b, [r15]
0x33D2FA: 49C7C2FF000000                   mov     r10, 0FFh
0x03743E: 49C1E208                         shl     r10, 8
0x037442: 49F7D2                           not     r10
0x037445: 4D21D5                           and     r13, r10
0x037448: 4D0FB6D4                         movzx   r10, r12b
0x03744C: 49C1E208                         shl     r10, 8
0x037450: 4D09D5                           or      r13, r10
0x03754A: 498B4128                         mov     rax, [r9+28h]
0x33D3CF: 488BB0E0000000                   mov     rsi, [rax+0E0h]
0x037555: 56                               push    rsi
0x037556: 4889E7                           mov     rdi, rsp
0x33D437: 488BA8E0000000                   mov     rbp, [rax+0E0h]
0x037632: 4D8B6928                         mov     r13, [r9+28h]
0x33D504: 4D8BA5E8000000                   mov     r12, [r13+0E8h]
0x33D570: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x037644: 4D0FB6E4                         movzx   r12, r12b
0x037735: 498B4128                         mov     rax, [r9+28h]
0x33D63D: 0FAE90D8000000                   ldmxcsr dword ptr [rax+0D8h]
0x037740: 498B4928                         mov     rcx, [r9+28h]
0x33D6A9: 488BA9B0000000                   mov     rbp, [rcx+0B0h]
0x33D713: 49BCF92FFC2D01000000             mov     r12, 12DFC2FF9h
0x33D780: 4981C4C71A0D12                   add     r12, 120D1AC7h
0x037853: 498B5928                         mov     rbx, [r9+28h]
0x037857: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x33D84F: 4C8BB3B8000000                   mov     r14, [rbx+0B8h]
0x33D8B8: 4C8BABA0000000                   mov     r13, [rbx+0A0h]
0x03793E: 4D8B5128                         mov     r10, [r9+28h]
0x33D98E: 498BBAE0000000                   mov     rdi, [r10+0E0h]
0x037949: 458B6A34                         mov     r13d, [r10+34h]
0x33D9F7: 4D03AAE8000000                   add     r13, [r10+0E8h]
0x037954: 458A5D00                         mov     r11b, [r13+0]
0x33DA5D: 49C7C6FF000000                   mov     r14, 0FFh
0x03795F: 49C1E610                         shl     r14, 10h
0x037963: 49F7D6                           not     r14
0x037966: 4C21F7                           and     rdi, r14
0x037969: 4D0FB6F3                         movzx   r14, r11b
0x03796D: 49C1E610                         shl     r14, 10h
0x037971: 4C09F7                           or      rdi, r14
0x037A50: 4D8B5128                         mov     r10, [r9+28h]
0x33DB33: 4D8BB2B0000000                   mov     r14, [r10+0B0h]
0x037A5B: 4156                             push    r14
0x037A5D: 4889E3                           mov     rbx, rsp
0x33DB9D: 4D8BAAB0000000                   mov     r13, [r10+0B0h]
0x037B47: 498B4928                         mov     rcx, [r9+28h]
0x33DC6E: 4C8BA9A0000000                   mov     r13, [rcx+0A0h]
0x33DCD3: 4C8BB9E0000000                   mov     r15, [rcx+0E0h]
0x037B59: 4D0FB6ED                         movzx   r13, r13b
0x037C3E: 498B6928                         mov     rbp, [r9+28h]
0x33DD9E: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x037C49: 498B5128                         mov     rdx, [r9+28h]
0x33DE0C: 4C8BA2F0000000                   mov     r12, [rdx+0F0h]
0x33DE76: 48BB81240D2B01000000             mov     rbx, 12B0D2481h
0x33DEE3: 4881C33F26FC14                   add     rbx, 14FC263Fh
0x037D53: 498B4928                         mov     rcx, [r9+28h]
0x037D57: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x33DFB8: 4C8BA1C0000000                   mov     r12, [rcx+0C0h]
0x33E024: 488BA9D8000000                   mov     rbp, [rcx+0D8h]
0x037E44: 4D8B7128                         mov     r14, [r9+28h]
0x33E0F6: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x037E4F: 458B6634                         mov     r12d, [r14+34h]
0x33E15F: 4D03A6D8000000                   add     r12, [r14+0D8h]
0x037E5A: 458A3424                         mov     r14b, [r12]
0x33E1CD: 48C7C5FF000000                   mov     rbp, 0FFh
0x037E65: 48C1E518                         shl     rbp, 18h
0x037E69: 48F7D5                           not     rbp
0x037E6C: 4821EF                           and     rdi, rbp
0x037E6F: 490FB6EE                         movzx   rbp, r14b
0x037E73: 48C1E518                         shl     rbp, 18h
0x037E77: 4809EF                           or      rdi, rbp
0x037F4D: 498B5128                         mov     rdx, [r9+28h]
0x33E298: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x037F58: 4154                             push    r12
0x037F5A: 4889E5                           mov     rbp, rsp
0x33E2FD: 4C8BB2B0000000                   mov     r14, [rdx+0B0h]
0x03803D: 4D8B5128                         mov     r10, [r9+28h]
0x33E3D4: 4D8BAAA0000000                   mov     r13, [r10+0A0h]
0x33E43C: 498BBAE8000000                   mov     rdi, [r10+0E8h]
0x03804F: 4155                             push    r13
0x038051: 685F1B7A36                       push    367A1B5Fh
0x038056: 68F158E623                       push    23E658F1h
0x03805B: 68EA426061                       push    616042EAh
0x038060: 682D21A662                       push    62A6212Dh
0x038147: 4D8B4928                         mov     r9, [r9+28h]
0x33E510: 4D8BA1C0000000                   mov     r12, [r9+0C0h]
0x33E575: 498B99B0000000                   mov     rbx, [r9+0B0h]
0x038159: 4D0FB6E4                         movzx   r12, r12b
0x03824D: 4D8B5128                         mov     r10, [r9+28h]
0x33E64C: 410FAE92D8000000                 ldmxcsr dword ptr [r10+0D8h]
0x038259: 4D8B6928                         mov     r13, [r9+28h]
0x33E6B3: 4D8BB590000000                   mov     r14, [r13+90h]
0x33E71A: 48BDA20BF1EF00000000             mov     rbp, 0EFF10BA2h
0x33E78B: 4881C51E3F1850                   add     rbp, 50183F1Eh
0x038361: 4D8B5128                         mov     r10, [r9+28h]
0x038365: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x33E858: 4D8BB290000000                   mov     r14, [r10+90h]
0x33E8BF: 4D8BBAE8000000                   mov     r15, [r10+0E8h]
0x038453: 498B5128                         mov     rdx, [r9+28h]
0x33E98D: 488B9AF0000000                   mov     rbx, [rdx+0F0h]
0x03845E: 448B5A34                         mov     r11d, [rdx+34h]
0x33E9F2: 4C039AE8000000                   add     r11, [rdx+0E8h]
0x038469: 458A33                           mov     r14b, [r11]
0x33EA5A: 49C7C3FF000000                   mov     r11, 0FFh
0x038473: 49C1E328                         shl     r11, 28h
0x038477: 49F7D3                           not     r11
0x03847A: 4C21DB                           and     rbx, r11
0x03847D: 4D0FB6DE                         movzx   r11, r14b
0x038481: 49C1E328                         shl     r11, 28h
0x038485: 4C09DB                           or      rbx, r11
0x03856B: 4D8B6928                         mov     r13, [r9+28h]
0x33EB26: 4D8BA590000000                   mov     r12, [r13+90h]
0x038576: 4154                             push    r12
0x038578: 4889E6                           mov     rsi, rsp
0x33EB92: 4D8BA590000000                   mov     r12, [r13+90h]
0x03864C: 498B4128                         mov     rax, [r9+28h]
0x33EC6A: 488B90A8000000                   mov     rdx, [rax+0A8h]
0x33ECD2: 4C8BA8D8000000                   mov     r13, [rax+0D8h]
0x03865E: 52                               push    rdx
0x03865F: 68F41F5B63                       push    635B1FF4h
0x038664: 68642F7E22                       push    227E2F64h
0x038669: 68BE35CA1F                       push    1FCA35BEh
0x038767: 498B5128                         mov     rdx, [r9+28h]
0x33EDA6: 488BAAD8000000                   mov     rbp, [rdx+0D8h]
0x33EE0C: 4C8BAAE0000000                   mov     r13, [rdx+0E0h]
0x038779: 480FB6ED                         movzx   rbp, bpl
0x03885F: 4D8B5928                         mov     r11, [r9+28h]
0x33EEE5: 410FAE93A0000000                 ldmxcsr dword ptr [r11+0A0h]
0x33EF4E: 49B8D734322401000000             mov     r8, 1243234D7h
0x038875: 4150                             push    r8
0x038877: 68DE62436D                       push    6D4362DEh
0x03887C: 68D3315572                       push    725531D3h
0x038881: 68EB19C56C                       push    6CC519EBh
0x33EFBB: 4881442418E915D71B               add     qword ptr [rsp+18h], 1BD715E9h
0x03888F: 4D8B6128                         mov     r12, [r9+28h]
0x33F023: 4D8BAC24E0000000                 mov     r13, [r12+0E0h]
0x03898F: 4D8B4928                         mov     r9, [r9+28h]
0x038993: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x33F0F4: 498BA9C0000000                   mov     rbp, [r9+0C0h]
0x33F162: 4D8BB9E0000000                   mov     r15, [r9+0E0h]
0x038A7E: 4D8B6128                         mov     r12, [r9+28h]
0x33F237: 498BBC24F0000000                 mov     rdi, [r12+0F0h]
0x038A8A: 418B6C2434                       mov     ebp, [r12+34h]
0x33F2A1: 4903AC24A0000000                 add     rbp, [r12+0A0h]
0x038A97: 408A6D00                         mov     bpl, [rbp+0]
0x33F30B: 49C7C1FF000000                   mov     r9, 0FFh
0x038AA2: 49C1E130                         shl     r9, 30h
0x038AA6: 49F7D1                           not     r9
0x038AA9: 4C21CF                           and     rdi, r9
0x038AAC: 4C0FB6CD                         movzx   r9, bpl
0x038AB0: 49C1E130                         shl     r9, 30h
0x038AB4: 4C09CF                           or      rdi, r9
0x038B94: 4D8B5928                         mov     r11, [r9+28h]
0x33F3E0: 4D8B83B0000000                   mov     r8, [r11+0B0h]
0x038B9F: 4150                             push    r8
0x038BA1: 4989E7                           mov     r15, rsp
0x33F44A: 498BB3B0000000                   mov     rsi, [r11+0B0h]
0x038C8C: 4D8B5128                         mov     r10, [r9+28h]
0x33F518: 498BAAF0000000                   mov     rbp, [r10+0F0h]
0x33F583: 4D8BBAA8000000                   mov     r15, [r10+0A8h]
0x038C9E: 55                               push    rbp
0x038C9F: 68F1398D26                       push    268D39F1h
0x038CA4: 68A0796272                       push    726279A0h
0x038CA9: 681D3C1465                       push    65143C1Dh
0x038D9A: 4D8B4928                         mov     r9, [r9+28h]
0x33F657: 498BA9A8000000                   mov     rbp, [r9+0A8h]
0x33F6BF: 4D8BA9F0000000                   mov     r13, [r9+0F0h]
0x038DAC: 480FB6ED                         movzx   rbp, bpl
0x038E8C: 498B5928                         mov     rbx, [r9+28h]
0x33F796: 0FAE93A0000000                   ldmxcsr dword ptr [rbx+0A0h]
0x038E97: 4D8B7928                         mov     r15, [r9+28h]
0x33F802: 498BB7E0000000                   mov     rsi, [r15+0E0h]
0x33F86E: 49BFC023B6CB00000000             mov     r15, 0CBB623C0h
0x33F8DC: 4981C700275374                   add     r15, 74532700h
0x038F84: 498B6928                         mov     rbp, [r9+28h]
0x038F88: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x33F9AA: 4C8BADA0000000                   mov     r13, [rbp+0A0h]
0x33FA14: 4C8BB5A8000000                   mov     r14, [rbp+0A8h]
0x039084: 4D8B6128                         mov     r12, [r9+28h]
0x33FAE0: 498BB424E8000000                 mov     rsi, [r12+0E8h]
0x039090: 418B4C2434                       mov     ecx, [r12+34h]
0x33FB48: 49038C24E0000000                 add     rcx, [r12+0E0h]
0x03909D: 8A01                             mov     al, [rcx]
0x33FBB1: 49C7C7FF000000                   mov     r15, 0FFh
0x0390A6: 49C1E738                         shl     r15, 38h
0x0390AA: 49F7D7                           not     r15
0x0390AD: 4C21FE                           and     rsi, r15
0x0390B0: 4C0FB6F8                         movzx   r15, al
0x0390B4: 49C1E738                         shl     r15, 38h
0x0390B8: 4C09FE                           or      rsi, r15
0x0391AF: 4D8B6928                         mov     r13, [r9+28h]
0x33FC89: 4D8BBDA8000000                   mov     r15, [r13+0A8h]
0x33FCF6: 48BB7B4D6E3101000000             mov     rbx, 1316E4D7Bh
0x33FD5E: 4881C36D6B1B0F                   add     rbx, 0F1B6B6Dh
0x0392AD: 4D8B5128                         mov     r10, [r9+28h]
0x33FE38: 4D8BB2A8000000                   mov     r14, [r10+0A8h]
0x33FEA0: 4D8BA2F0000000                   mov     r12, [r10+0F0h]
0x0392BF: 4D0FB6F6                         movzx   r14, r14b
0x0393B9: 498B6928                         mov     rbp, [r9+28h]
0x33FF6D: 488B85E8000000                   mov     rax, [rbp+0E8h]
0x33FFDA: 49C7C6750FDAFA                   mov     r14, 0FFFFFFFFFADA0F75h
0x340042: 4981C637111706                   add     r14, 6171137h
0x0393D2: 4156                             push    r14
0x3400AA: 4C8BB5D8000000                   mov     r14, [rbp+0D8h]
0x0393DB: 48F72424                         mul     qword ptr [rsp]
0x0393DF: 4889C3                           mov     rbx, rax
0x0394C4: 498B5928                         mov     rbx, [r9+28h]
0x340183: 4C8BBBE8000000                   mov     r15, [rbx+0E8h]
0x3401E9: 4C33BB90000000                   xor     r15, [rbx+90h]
0x0395B0: 498B4928                         mov     rcx, [r9+28h]
0x3402C1: 488BB1F0000000                   mov     rsi, [rcx+0F0h]
0x0395BB: 56                               push    rsi
0x0395BC: 4989E6                           mov     r14, rsp
0x340326: 4C8BA9F0000000                   mov     r13, [rcx+0F0h]
0x03969A: 498B4128                         mov     rax, [r9+28h]
0x3403F3: 488B98F0000000                   mov     rbx, [rax+0F0h]
0x340458: 488BB8E0000000                   mov     rdi, [rax+0E0h]
0x0396AC: 480FB6DB                         movzx   rbx, bl
0x039783: 4D8B6128                         mov     r12, [r9+28h]
0x34052A: 410FAE942490000000               ldmxcsr dword ptr [r12+90h]
0x340594: 49BEDC28191B01000000             mov     r14, 11B1928DCh
0x340603: 4981C6E439F024                   add     r14, 24F039E4h
0x34066A: 4D8BB678060000                   mov     r14, [r14+678h]
0x3406D8: 4D03B42490000000                 add     r14, [r12+90h]
0x0397B0: 418A3E                           mov     dil, [r14]
0x0397B3: 480FB6FF                         movzx   rdi, dil
0x0397B7: 48C1E708                         shl     rdi, 8
0x340742: 4901BC24B0000000                 add     [r12+0B0h], rdi
0x3407AC: 48BA8E40BECB00000000             mov     rdx, 0CBBE408Eh
0x0397CD: 52                               push    rdx
0x0397CE: 68233DE338                       push    38E33D23h
0x0397D3: 68BF6F0306                       push    6036FBFh
0x0397D8: 681927E51A                       push    1AE52719h
0x340815: 4881442418321A4B74               add     qword ptr [rsp+18h], 744B1A32h
0x0397E6: 4D8B4128                         mov     r8, [r9+28h]
0x340885: 498BB8B0000000                   mov     rdi, [r8+0B0h]
0x0398DF: 498B4128                         mov     rax, [r9+28h]
0x0398E3: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x340958: 488BB8D8000000                   mov     rdi, [rax+0D8h]
0x3409BE: 4C8BB0B0000000                   mov     r14, [rax+0B0h]
0x0399D9: 4D8B7128                         mov     r14, [r9+28h]
0x340A8B: 4D8BBEE8000000                   mov     r15, [r14+0E8h]
0x0399E4: 418B4634                         mov     eax, [r14+34h]
0x340AF5: 490386B0000000                   add     rax, [r14+0B0h]
0x0399EF: 448A28                           mov     r13b, [rax]
0x0399F2: 4588EF                           mov     r15b, r13b
0x039ACC: 4D8B7928                         mov     r15, [r9+28h]
0x340BC1: 4D8BA7F0000000                   mov     r12, [r15+0F0h]
0x039AD7: 4154                             push    r12
0x039AD9: 4889E3                           mov     rbx, rsp
0x340C2C: 4D8BBFF0000000                   mov     r15, [r15+0F0h]
0x039BCC: 498B7928                         mov     rdi, [r9+28h]
0x340CFD: 4C8BB790000000                   mov     r14, [rdi+90h]
0x340D6B: 488BB7F0000000                   mov     rsi, [rdi+0F0h]
0x039BDE: 4156                             push    r14
0x039BE0: 685F60437C                       push    7C43605Fh
0x039BE5: 68802ABC22                       push    22BC2A80h
0x039BEA: 682557C030                       push    30C05725h
0x039BEF: 687655D34D                       push    4DD35576h
0x039CDA: 498B5128                         mov     rdx, [r9+28h]
0x340E3F: 488BBAD0000000                   mov     rdi, [rdx+0D0h]
0x340EA7: 4C8BAAA8000000                   db  4Ch ; L
0x039CEC: 480FB6FF                         movzx   rdi, dil
0x039DC6: 498B5128                         mov     rdx, [r9+28h]
0x340F77: 0FAE92B0000000                   ldmxcsr dword ptr [rdx+0B0h]
0x340FE5: 49B888238C2701000000             mov     r8, 1278C2388h
0x341051: 4981C0383F7D18                   add     r8, 187D3F38h
0x3410BE: 4D8B80E8050000                   mov     r8, [r8+5E8h]
0x341126: 4C0382B0000000                   add     r8, [rdx+0B0h]
0x039DF0: 418A28                           mov     bpl, [r8]
0x039DF3: 480FB6ED                         movzx   rbp, bpl
0x039DF7: 48C1E510                         shl     rbp, 10h
0x341193: 4801AAE0000000                   add     [rdx+0E0h], rbp
0x3411FD: 48B84FED04E900000000             mov     rax, 0E904ED4Fh
0x039E0C: 50                               push    rax
0x039E0D: 685830E17A                       push    7AE13058h
0x039E12: 68A90D5C5C                       push    5C5C0DA9h
0x039E17: 689100B132                       push    32B10091h
0x34126E: 4881442418716D0457               add     qword ptr [rsp+18h], 57046D71h
0x039E25: 498B7128                         mov     rsi, [r9+28h]
0x3412D8: 4C8BAEE0000000                   mov     r13, [rsi+0E0h]
0x039F22: 498B4928                         mov     rcx, [r9+28h]
0x039F26: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x039F2A: 4C8B7978                         mov     r15, [rcx+78h]
0x3413A5: 4C8BA1E0000000                   mov     r12, [rcx+0E0h]
0x03A012: 4D8B7928                         mov     r15, [r9+28h]
0x341470: 498BBFD8000000                   mov     rdi, [r15+0D8h]
0x03A01D: 458B7734                         mov     r14d, [r15+34h]
0x3414DA: 4D03B7F0000000                   add     r14, [r15+0F0h]
0x03A028: 458A3E                           mov     r15b, [r14]
0x341548: 49C7C5FF000000                   mov     r13, 0FFh
0x03A032: 49C1E508                         shl     r13, 8
0x03A036: 49F7D5                           not     r13
0x03A039: 4C21EF                           and     rdi, r13
0x03A03C: 4D0FB6EF                         movzx   r13, r15b
0x03A040: 49C1E508                         shl     r13, 8
0x03A044: 4C09EF                           or      rdi, r13
0x03A11E: 498B6928                         mov     rbp, [r9+28h]
0x341615: 488BBDB0000000                   mov     rdi, [rbp+0B0h]
0x03A129: 57                               push    rdi
0x03A12A: 4989E7                           mov     r15, rsp
0x341681: 488BADB0000000                   mov     rbp, [rbp+0B0h]
0x03A216: 498B7928                         mov     rdi, [r9+28h]
0x341753: 488BAFD8000000                   mov     rbp, [rdi+0D8h]
0x3417B8: 488B9FA0000000                   mov     rbx, [rdi+0A0h]
0x03A228: 480FB6ED                         movzx   rbp, bpl
0x03A308: 4D8B5128                         mov     r10, [r9+28h]
0x341888: 410FAE92A0000000                 ldmxcsr dword ptr [r10+0A0h]
0x3418F1: 49BDFFE5CEDE00000000             mov     r13, 0DECEE5FFh
0x34195E: 4981C5C17C3A61                   add     r13, 613A7CC1h
0x3419C4: 4D8BADE8010000                   mov     r13, [r13+1E8h]
0x341A32: 4D03AAA0000000                   add     r13, [r10+0A0h]
0x03A333: 458A7500                         mov     r14b, [r13+0]
0x03A337: 4D0FB6F6                         movzx   r14, r14b
0x03A33B: 49C1E618                         shl     r14, 18h
0x341A9C: 4D01B290000000                   add     [r10+90h], r14
0x341B06: 49BF3BE405DB00000000             mov     r15, 0DB05E43Bh
0x03A350: 4157                             push    r15
0x03A352: 68487D6E57                       push    576E7D48h
0x03A357: 688A354215                       push    1542358Ah
0x03A35C: 68E608C032                       push    32C008E6h
0x341B77: 488144241885760365               add     [rsp-8+arg_18], 65037685h
0x03A36A: 4D8B5928                         mov     r11, [r9+28h]
0x341BE4: 498B9B90000000                   mov     rbx, [r11+90h]
0x03A467: 4D8B7128                         mov     r14, [r9+28h]
0x03A46B: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x341CB8: 4D8BBEE8000000                   mov     r15, [r14+0E8h]
0x341D1D: 4D8BAE90000000                   mov     r13, [r14+90h]
0x03A55B: 498B4128                         mov     rax, [r9+28h]
0x341DEE: 488BB0E0000000                   mov     rsi, [rax+0E0h]
0x03A566: 448B7034                         mov     r14d, [rax+34h]
0x341E57: 4C03B0F0000000                   add     r14, [rax+0F0h]
0x03A571: 418A16                           mov     dl, [r14]
0x341EC5: 48C7C7FF000000                   mov     rdi, 0FFh
0x03A57B: 48C1E710                         shl     rdi, 10h
0x03A57F: 48F7D7                           not     rdi
0x03A582: 4821FE                           and     rsi, rdi
0x03A585: 480FB6FA                         movzx   rdi, dl
0x03A589: 48C1E710                         shl     rdi, 10h
0x03A58D: 4809FE                           or      rsi, rdi
0x03A667: 498B7928                         mov     rdi, [r9+28h]
0x341F98: 488BB7A8000000                   mov     rsi, [rdi+0A8h]
0x03A672: 56                               push    rsi
0x03A673: 4989E5                           mov     r13, rsp
0x341FFF: 488BBFA8000000                   mov     rdi, [rdi+0A8h]
0x03A768: 498B6928                         mov     rbp, [r9+28h]
0x3420CE: 4C8B85E0000000                   mov     r8, [rbp+0E0h]
0x342136: 488BADB0000000                   mov     rbp, [rbp+0B0h]
0x03A77A: 4150                             push    r8
0x03A77C: 686841E731                       push    31E74168h
0x03A781: 68C55A0C4C                       push    4C0C5AC5h
0x03A786: 68C363700C                       push    0C7063C3h
0x03A78B: 6853089C71                       push    719C0853h
0x03A875: 498B4128                         mov     rax, [r9+28h]
0x342210: 488BA8C8000000                   mov     rbp, [rax+0C8h]
0x34227A: 4C8BB0A0000000                   mov     r14, [rax+0A0h]
0x03A887: 480FB6ED                         movzx   rbp, bpl
0x03A96C: 4D8B5128                         mov     r10, [r9+28h]
0x34234D: 410FAE92A0000000                 ldmxcsr dword ptr [r10+0A0h]
0x3423B7: 48BBFF1726E400000000             mov     rbx, 0E42617FFh
0x342426: 4881C3C14AE35B                   add     rbx, 5BE34AC1h
0x342492: 488B9B00040000                   mov     rbx, [rbx+400h]
0x3424F7: 49039AA0000000                   add     rbx, [r10+0A0h]
0x03A997: 8A03                             mov     al, [rbx]
0x03A999: 480FB6C0                         movzx   rax, al
0x03A99D: 48C1E020                         shl     rax, 20h
0x342560: 490182E8000000                   add     [r10+0E8h], rax
0x3425C9: 49BAE14FE8FA00000000             mov     r10, 0FAE84FE1h
0x03A9B2: 4152                             push    r10
0x03A9B4: 685D131008                       push    810135Dh
0x03A9B9: 687048D535                       push    35D54870h
0x03A9BE: 684E045C2E                       push    2E5C044Eh
0x03A9C3: 684E0F8A3B                       push    3B8A0F4Eh
0x342632: 4881442420DF0A2145               add     qword ptr [rsp+20h], 45210ADFh
0x03A9D1: 4D8B6128                         mov     r12, [r9+28h]
0x34269B: 4D8BA424E8000000                 mov     r12, [r12+0E8h]
0x03AACB: 4D8B4128                         mov     r8, [r9+28h]
0x03AACF: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x342772: 4D8BB0C8000000                   mov     r14, [r8+0C8h]
0x3427DA: 498BB8D8000000                   mov     rdi, [r8+0D8h]
0x03ABBE: 498B5128                         mov     rdx, [r9+28h]
0x3428AD: 488B9AB0000000                   mov     rbx, [rdx+0B0h]
0x03ABC9: 8B4A34                           mov     ecx, [rdx+34h]
0x342915: 48038AE8000000                   add     rcx, [rdx+0E8h]
0x03ABD3: 448A19                           mov     r11b, [rcx]
0x34297A: 48C7C6FF000000                   mov     rsi, 0FFh
0x03ABDD: 48C1E618                         shl     rsi, 18h
0x03ABE1: 48F7D6                           not     rsi
0x03ABE4: 4821F3                           and     rbx, rsi
0x03ABE7: 490FB6F3                         movzx   rsi, r11b
0x03ABEB: 48C1E618                         shl     rsi, 18h
0x03ABEF: 4809F3                           or      rbx, rsi
0x03ACC9: 498B5928                         mov     rbx, [r9+28h]
0x342A43: 4C8B8390000000                   mov     r8, [rbx+90h]
0x03ACD4: 4150                             push    r8
0x03ACD6: 4989E7                           mov     r15, rsp
0x342AAD: 488B9B90000000                   mov     rbx, [rbx+90h]
0x03ADCC: 498B7928                         mov     rdi, [r9+28h]
0x342B7B: 4C8B97F0000000                   mov     r10, [rdi+0F0h]
0x342BE9: 488BB790000000                   mov     rsi, [rdi+90h]
0x03ADDE: 4152                             push    r10
0x03ADE0: 68EF0D7703                       push    3770DEFh
0x03ADE5: 68CA197E68                       push    687E19CAh
0x03ADEA: 6805247B24                       push    247B2405h
0x03AEE0: 498B7128                         mov     rsi, [r9+28h]
0x342CBA: 488BBE80000000                   mov     rdi, [rsi+80h]
0x342D21: 4C8BAEA8000000                   mov     r13, [rsi+0A8h]
0x03AEF2: 480FB6FF                         movzx   rdi, dil
0x03AFD7: 4D8B7928                         mov     r15, [r9+28h]
0x342DF2: 410FAE97B0000000                 ldmxcsr dword ptr [r15+0B0h]
0x342E5D: 48B8264C0ACA00000000             mov     rax, 0CA0A4C26h
0x342EC8: 48059A16FF75                     add     rax, 75FF169Ah
0x03AFF3: 488B00                           mov     rax, [rax]
0x342F2F: 490387B0000000                   add     rax, [r15+0B0h]
0x03AFFD: 408A28                           mov     bpl, [rax]
0x03B000: 480FB6ED                         movzx   rbp, bpl
0x03B004: 48C1E530                         shl     rbp, 30h
0x342F9B: 4901AFE0000000                   add     [r15+0E0h], rbp
0x343008: 49BB5D1CC83F01000000             mov     r11, 13FC81C5Dh
0x03B019: 4153                             push    r11
0x03B01B: 68C2711F4B                       push    4B1F71C2h
0x03B020: 68DD7BD81F                       push    1FD87BDDh
0x03B025: 68350B6015                       push    15600B35h
0x03B02A: 68D63E9208                       push    8923ED6h
0x343078: 4881442420633E4100               add     qword ptr [rsp+20h], 413E63h
0x03B038: 4D8B7928                         mov     r15, [r9+28h]
0x3430DF: 4D8BBFE0000000                   mov     r15, [r15+0E0h]
0x03B136: 4D8B4928                         mov     r9, [r9+28h]
0x03B13A: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x3431B4: 498BB1B8000000                   mov     rsi, [r9+0B8h]
0x34321C: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x03B224: 498B4128                         mov     rax, [r9+28h]
0x3432EC: 4C8BA890000000                   mov     r13, [rax+90h]
0x03B22F: 448B4834                         mov     r9d, [rax+34h]
0x343354: 4C0388A8000000                   add     r9, [rax+0A8h]
0x03B23A: 458A11                           mov     r10b, [r9]
0x3433C2: 48C7C5FF000000                   mov     rbp, 0FFh
0x03B244: 48C1E528                         shl     rbp, 28h
0x03B248: 48F7D5                           not     rbp
0x03B24B: 4921ED                           and     r13, rbp
0x03B24E: 490FB6EA                         movzx   rbp, r10b
0x03B252: 48C1E528                         shl     rbp, 28h
0x03B256: 4909ED                           or      r13, rbp
0x03B339: 4D8B6128                         mov     r12, [r9+28h]
0x343492: 4D8BB424E0000000                 mov     r14, [r12+0E0h]
0x343501: 48BDBFACECE700000000             mov     rbp, 0E7ECACBFh
0x343571: 4881C5290C9D58                   add     rbp, 589D0C29h
0x03B43A: 4D8B5128                         mov     r10, [r9+28h]
0x343643: 498BBAD0000000                   mov     rdi, [r10+0D0h]
0x3436B0: 498BAAE8000000                   mov     rbp, [r10+0E8h]
0x03B44C: 480FB6FF                         movzx   rdi, dil
0x03B52B: 4D8B5128                         mov     r10, [r9+28h]
0x34377B: 498B82B0000000                   mov     rax, [r10+0B0h]
0x3437E9: 48C7C33A4AB2E7                   mov     rbx, 0FFFFFFFFE7B24A3Ah
0x343854: 4881C3B5037318                   add     rbx, 187303B5h
0x03B544: 53                               push    rbx
0x3438BA: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x03B54C: 48F72424                         mul     qword ptr [rsp]
0x03B550: 4889C5                           mov     rbp, rax
0x03B632: 498B7128                         mov     rsi, [r9+28h]
0x343989: 4C8BAEE8000000                   mov     r13, [rsi+0E8h]
0x3439F7: 4C03AEA0000000                   add     r13, [rsi+0A0h]
0x03B727: 4D8B6128                         mov     r12, [r9+28h]
0x343AC8: 498B8C24E0000000                 mov     rcx, [r12+0E0h]
0x03B733: 51                               push    rcx
0x03B734: 4889E7                           mov     rdi, rsp
0x343B31: 4D8BBC24E0000000                 mov     r15, [r12+0E0h]
0x03B82E: 4D8B6928                         mov     r13, [r9+28h]
0x343C03: 4D8B85B0000000                   mov     r8, [r13+0B0h]
0x343C69: 4D8BADF0000000                   mov     r13, [r13+0F0h]
0x03B840: 4150                             push    r8
0x03B842: 68220BDE06                       push    6DE0B22h
0x03B847: 682672087D                       push    7D087226h
0x03B84C: 68A17DCB41                       push    41CB7DA1h
0x03B942: 498B4928                         mov     rcx, [r9+28h]
0x343D38: 4C8BA1F0000000                   mov     r12, [rcx+0F0h]
0x343D9F: 488BB9E0000000                   mov     rdi, [rcx+0E0h]
0x03B954: 4D0FB6E4                         movzx   r12, r12b
0x03BA2D: 4D8B6128                         mov     r12, [r9+28h]
0x343E74: 410FAE9424D8000000               ldmxcsr dword ptr [r12+0D8h]
0x03BA3A: 4D8B7128                         mov     r14, [r9+28h]
0x343EE0: 4D8BA6B0000000                   mov     r12, [r14+0B0h]
0x343F4D: 48BBE83ECAC300000000             mov     rbx, 0C3CA3EE8h
0x343FBE: 4881C3D80B3F7C                   add     rbx, 7C3F0BD8h
0x03BB2C: 4D8B5128                         mov     r10, [r9+28h]
0x03BB30: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x344097: 4D8BB2B0000000                   mov     r14, [r10+0B0h]
0x344104: 4D8BA2D8000000                   mov     r12, [r10+0D8h]
0x03BC21: 4D8B7928                         mov     r15, [r9+28h]
0x3441CF: 4D8BA7D8000000                   mov     r12, [r15+0D8h]
0x03BC2C: 418B7734                         mov     esi, [r15+34h]
0x344236: 4903B7E8000000                   add     rsi, [r15+0E8h]
0x03BC37: 408A36                           mov     sil, [rsi]
0x03BC3A: 4188F4                           mov     r12b, sil
0x03BD1B: 4D8B5928                         mov     r11, [r9+28h]
0x344308: 4D8BA3D8000000                   mov     r12, [r11+0D8h]
0x03BD26: 4154                             push    r12
0x03BD28: 4889E7                           mov     rdi, rsp
0x34436D: 4D8BA3D8000000                   mov     r12, [r11+0D8h]
0x03BE0E: 498B7128                         mov     rsi, [r9+28h]
0x34443C: 488B96B0000000                   mov     rdx, [rsi+0B0h]
0x3444A3: 4C8BAED8000000                   mov     r13, [rsi+0D8h]
0x03BE20: 52                               push    rdx
0x03BE21: 684663C22D                       push    2DC26346h
0x03BE26: 68616EFB38                       push    38FB6E61h
0x03BE2B: 68BD2DF923                       push    23F92DBDh
0x03BE30: 6894514919                       push    19495194h
0x03BF25: 498B5128                         mov     rdx, [r9+28h]
0x34456F: 4C8BBAA0000000                   mov     r15, [rdx+0A0h]
0x3445DA: 488B9AE0000000                   mov     rbx, [rdx+0E0h]
0x03BF37: 4D0FB6FF                         movzx   r15, r15b
0x03C00D: 4D8B6128                         mov     r12, [r9+28h]
0x3446AB: 410FAE9424F0000000               ldmxcsr dword ptr [r12+0F0h]
0x03C01A: 498B7928                         mov     rdi, [r9+28h]
0x344714: 488BB790000000                   mov     rsi, [rdi+90h]
0x34477F: 48BD81DE422C01000000             mov     rbp, 12C42DE81h
0x3447EB: 4881C53F6CC613                   add     rbp, 13C66C3Fh
0x03C11F: 4D8B6928                         mov     r13, [r9+28h]
0x03C123: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x3448BD: 4D8BA5B8000000                   mov     r12, [r13+0B8h]
0x344929: 4D8BADA8000000                   mov     r13, [r13+0A8h]
0x03C201: 498B4128                         mov     rax, [r9+28h]
0x3449FD: 4C8BB0E0000000                   mov     r14, [rax+0E0h]
0x03C20C: 448B7834                         mov     r15d, [rax+34h]
0x344A67: 4C03B8D8000000                   add     r15, [rax+0D8h]
0x03C217: 458A17                           mov     r10b, [r15]
0x344AD3: 48C7C0FF000000                   mov     rax, 0FFh
0x03C221: 48C1E008                         shl     rax, 8
0x03C225: 48F7D0                           not     rax
0x03C228: 4921C6                           and     r14, rax
0x03C22B: 490FB6C2                         movzx   rax, r10b
0x03C22F: 48C1E008                         shl     rax, 8
0x03C233: 4909C6                           or      r14, rax
0x03C318: 4D8B6928                         mov     r13, [r9+28h]
0x344BA8: 498BB5E8000000                   mov     rsi, [r13+0E8h]
0x03C323: 56                               push    rsi
0x03C324: 4989E7                           mov     r15, rsp
0x344C13: 4D8BB5E8000000                   mov     r14, [r13+0E8h]
0x03C417: 498B5128                         mov     rdx, [r9+28h]
0x344CE1: 488BAAE0000000                   mov     rbp, [rdx+0E0h]
0x344D49: 4C8BBAE8000000                   mov     r15, [rdx+0E8h]
0x03C429: 480FB6ED                         movzx   rbp, bpl
0x03C508: 4D8B4128                         mov     r8, [r9+28h]
0x344E1C: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x344E83: 48B8782E083101000000             mov     rax, 131082E78h
0x03C51E: 50                               push    rax
0x03C51F: 68E5577E7E                       push    7E7E57E5h
0x03C524: 689319A123                       push    23A11993h
0x03C529: 68C31BEA37                       push    37EA1BC3h
0x344EED: 4881442418481C010F               add     qword ptr [rsp+18h], 0F011C48h
0x03C537: 498B4128                         mov     rax, [r9+28h]
0x344F55: 488BB0F0000000                   mov     rsi, [rax+0F0h]
0x03C62F: 4D8B6928                         mov     r13, [r9+28h]
0x03C633: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x345028: 4D8BA5E0000000                   mov     r12, [r13+0E0h]
0x345090: 4D8BBDA8000000                   mov     r15, [r13+0A8h]
0x03C719: 4D8B4928                         mov     r9, [r9+28h]
0x34515B: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x03C724: 418B5134                         mov     edx, [r9+34h]
0x3451C5: 490391D8000000                   add     rdx, [r9+0D8h]
0x03C72F: 448A3A                           mov     r15b, [rdx]
0x34522A: 48C7C0FF000000                   mov     rax, 0FFh
0x03C739: 48C1E010                         shl     rax, 10h
0x03C73D: 48F7D0                           not     rax
0x03C740: 4821C7                           and     rdi, rax
0x03C743: 490FB6C7                         movzx   rax, r15b
0x03C747: 48C1E010                         shl     rax, 10h
0x03C74B: 4809C7                           or      rdi, rax
0x03C827: 498B5928                         mov     rbx, [r9+28h]
0x3452FD: 4C8BBBB0000000                   mov     r15, [rbx+0B0h]
0x03C832: 4157                             push    r15
0x03C834: 4989E6                           mov     r14, rsp
0x345363: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x03C927: 4D8B6928                         mov     r13, [r9+28h]
0x345431: 4D8B85E8000000                   mov     r8, [r13+0E8h]
0x34549D: 4D8BA5B0000000                   mov     r12, [r13+0B0h]
0x03C939: 4150                             push    r8
0x03C93B: 681608164E                       push    4E160816h
0x03C940: 687308B343                       push    43B30873h
0x03C945: 689964E614                       push    14E66499h
0x03C94A: 68161AB613                       push    13B61A16h
0x03CA2F: 4D8B6928                         mov     r13, [r9+28h]
0x345577: 498B9DE0000000                   mov     rbx, [r13+0E0h]
0x3455E3: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x03CA41: 480FB6DB                         movzx   rbx, bl
0x03CB2F: 4D8B6928                         mov     r13, [r9+28h]
0x3456AF: 410FAE9590000000                 ldmxcsr dword ptr [r13+90h]
0x03CB3B: 4D8B5928                         mov     r11, [r9+28h]
0x345718: 498BB3A8000000                   mov     rsi, [r11+0A8h]
0x345786: 48BD570C9EC200000000             mov     rbp, 0C29E0C57h
0x3457F2: 4881C5693E6B7D                   add     rbp, 7D6B3E69h
0x03CC2E: 498B7128                         mov     rsi, [r9+28h]
0x03CC32: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x3458C1: 488BAEE0000000                   mov     rbp, [rsi+0E0h]
0x34592E: 488BB6A8000000                   mov     rsi, [rsi+0A8h]
0x03CD1C: 4D8B5128                         mov     r10, [r9+28h]
0x345A03: 498BAAA8000000                   mov     rbp, [r10+0A8h]
0x03CD27: 418B7234                         mov     esi, [r10+34h]
0x345A6E: 4903B2A0000000                   add     rsi, [r10+0A0h]
0x03CD32: 448A0E                           mov     r9b, [rsi]
0x345ADA: 49C7C6FF000000                   mov     r14, 0FFh
0x03CD3C: 49C1E618                         shl     r14, 18h
0x03CD40: 49F7D6                           not     r14
0x03CD43: 4C21F5                           and     rbp, r14
0x03CD46: 4D0FB6F1                         movzx   r14, r9b
0x03CD4A: 49C1E618                         shl     r14, 18h
0x03CD4E: 4C09F5                           or      rbp, r14
0x03CE1E: 4D8B7928                         mov     r15, [r9+28h]
0x345BAD: 4D8B9FA0000000                   mov     r11, [r15+0A0h]
0x03CE29: 4153                             push    r11
0x03CE2B: 4889E6                           mov     rsi, rsp
0x345C1B: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x03CF20: 4D8B5928                         mov     r11, [r9+28h]
0x345CF4: 498BB3E0000000                   mov     rsi, [r11+0E0h]
0x345D62: 498BBB90000000                   mov     rdi, [r11+90h]
0x03CF32: 480FB6F6                         movzx   rsi, sil
0x03CFFD: 4D8B6928                         mov     r13, [r9+28h]
0x345E39: 410FAE95A8000000                 ldmxcsr dword ptr [r13+0A8h]
0x03D009: 498B6928                         mov     rbp, [r9+28h]
0x345EA0: 4C8BA5B0000000                   mov     r12, [rbp+0B0h]
0x345F08: 48BBDD18703A01000000             mov     rbx, 13A7018DDh
0x345F76: 4881C3E3319905                   add     rbx, 59931E3h
0x03D0FF: 4D8B6128                         mov     r12, [r9+28h]
0x346047: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x3460B2: 498BBC24A0000000                 mov     rdi, [r12+0A0h]
0x34611A: 498BB424D8000000                 mov     rsi, [r12+0D8h]
0x03D1F4: 498B5928                         mov     rbx, [r9+28h]
0x3461F3: 488BB3A8000000                   mov     rsi, [rbx+0A8h]
0x03D1FF: 448B4B34                         mov     r9d, [rbx+34h]
0x346259: 4C038BB0000000                   add     r9, [rbx+0B0h]
0x03D20A: 418A39                           mov     dil, [r9]
0x3462C5: 49C7C6FF000000                   mov     r14, 0FFh
0x03D214: 49C1E628                         shl     r14, 28h
0x03D218: 49F7D6                           not     r14
0x03D21B: 4C21F6                           and     rsi, r14
0x03D21E: 4C0FB6F7                         movzx   r14, dil
0x03D222: 49C1E628                         shl     r14, 28h
0x03D226: 4C09F6                           or      rsi, r14
0x03D30C: 4D8B4128                         mov     r8, [r9+28h]
0x346395: 4D8BA8A8000000                   mov     r13, [r8+0A8h]
0x03D317: 4155                             push    r13
0x03D319: 4889E7                           mov     rdi, rsp
0x346401: 4D8BA8A8000000                   mov     r13, [r8+0A8h]
0x03D3FF: 4D8B7928                         mov     r15, [r9+28h]
0x3464D5: 4D8BB7B0000000                   mov     r14, [r15+0B0h]
0x346542: 4D8BBFE0000000                   mov     r15, [r15+0E0h]
0x03D411: 4156                             push    r14
0x03D413: 6884698B44                       push    448B6984h
0x03D418: 68EF324A00                       push    4A32EFh
0x03D41D: 68DA49B626                       push    26B649DAh
0x03D422: 68AB4DC929                       push    29C94DABh
0x03D512: 4D8B4128                         mov     r8, [r9+28h]
0x346613: 4D8BA0B8000000                   mov     r12, [r8+0B8h]
0x346679: 498BA8F0000000                   mov     rbp, [r8+0F0h]
0x03D524: 4D0FB6E4                         movzx   r12, r12b
0x03D600: 4D8B5928                         mov     r11, [r9+28h]
0x34674B: 410FAE93D8000000                 ldmxcsr dword ptr [r11+0D8h]
0x3467B3: 48BD11E927D400000000             mov     rbp, 0D427E911h
0x03D616: 55                               push    rbp
0x03D617: 682568BB4E                       push    4EBB6825h
0x03D61C: 6806456F6F                       push    6F6F4506h
0x03D621: 680266D307                       push    7D36602h
0x34681B: 4881442418AF61E16B               add     qword ptr [rsp+18h], 6BE161AFh
0x03D62F: 4D8B6928                         mov     r13, [r9+28h]
0x346889: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x03D71E: 498B5128                         mov     rdx, [r9+28h]
0x03D722: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x346957: 4C8BBAE0000000                   mov     r15, [rdx+0E0h]
0x3469BC: 488BBAA8000000                   mov     rdi, [rdx+0A8h]
0x03D810: 4D8B5928                         mov     r11, [r9+28h]
0x346A92: 498BBBB0000000                   mov     rdi, [r11+0B0h]
0x03D81B: 458B6B34                         mov     r13d, [r11+34h]
0x346AFC: 4D03ABF0000000                   add     r13, [r11+0F0h]
0x03D826: 458A4500                         mov     r8b, [r13+0]
0x346B65: 49C7C7FF000000                   mov     r15, 0FFh
0x03D831: 49C1E738                         shl     r15, 38h
0x03D835: 49F7D7                           not     r15
0x03D838: 4C21FF                           and     rdi, r15
0x03D83B: 4D0FB6F8                         movzx   r15, r8b
0x03D83F: 49C1E738                         shl     r15, 38h
0x03D843: 4C09FF                           or      rdi, r15
0x03D91D: 498B4928                         mov     rcx, [r9+28h]
0x346C30: 488BA9B0000000                   mov     rbp, [rcx+0B0h]
0x346C9A: 49BF1B734FDA00000000             mov     r15, 0DA4F731Bh
0x346D02: 4981C7CD453A66                   add     r15, 663A45CDh
0x03DA2A: 4D8B4928                         mov     r9, [r9+28h]
0x346DD1: 4D8BB990000000                   mov     r15, [r9+90h]
0x346E38: 498BB9A0000000                   mov     rdi, [r9+0A0h]
0x03DA3C: 4D0FB6FF                         movzx   r15, r15b
0x03DB22: 4D8B7928                         mov     r15, [r9+28h]
0x346F0A: 498B87F0000000                   mov     rax, [r15+0F0h]
0x346F73: 48C7C238A35CB2                   mov     rdx, 0FFFFFFFFB25CA338h
0x346FE1: 4881C2AF50424E                   add     rdx, 4E4250AFh
0x03DB3B: 52                               push    rdx
0x347048: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x03DB43: 48F72424                         mul     qword ptr [rsp]
0x03DB47: 4989C6                           mov     r14, rax
0x03DC28: 4D8B5928                         mov     r11, [r9+28h]
0x347116: 4D8BA3B0000000                   mov     r12, [r11+0B0h]
0x347184: 4D33A3E8000000                   xor     r12, [r11+0E8h]
0x03DD1F: 498B6928                         mov     rbp, [r9+28h]
0x347259: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x03DD2A: 56                               push    rsi
0x03DD2B: 4889E6                           mov     rsi, rsp
0x3472C2: 4C8BBDD8000000                   mov     r15, [rbp+0D8h]
0x03DE12: 4D8B6128                         mov     r12, [r9+28h]
0x347391: 498BAC24D0000000                 mov     rbp, [r12+0D0h]
0x3473F9: 4D8BBC24F0000000                 mov     r15, [r12+0F0h]
0x03DE26: 480FB6ED                         movzx   rbp, bpl
0x03DF07: 498B7128                         mov     rsi, [r9+28h]
0x3474C6: 0FAE96A0000000                   ldmxcsr dword ptr [rsi+0A0h]
0x347534: 49BF8C305B1D01000000             mov     r15, 11D5B308Ch
0x3475A1: 4981C73442AE22                   add     r15, 22AE4234h
0x03DF23: 4D8B7F58                         mov     r15, [r15+58h]
0x347609: 4C03BEA0000000                   add     r15, [rsi+0A0h]
0x03DF2E: 418A2F                           mov     bpl, [r15]
0x03DF31: 480FB6ED                         movzx   rbp, bpl
0x03DF35: 48C1E508                         shl     rbp, 8
0x347671: 4829AEF0000000                   sub     [rsi+0F0h], rbp
0x03DF40: 498B7928                         mov     rdi, [r9+28h]
0x3476DC: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x347741: 49BFF826053401000000             mov     r15, 1340526F8h
0x3477B1: 4981C7C843040C                   add     r15, 0C0443C8h
0x03E04A: 498B4128                         mov     rax, [r9+28h]
0x03E04E: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x34787E: 488BB090000000                   mov     rsi, [rax+90h]
0x3478E5: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x03E14E: 4D8B7928                         mov     r15, [r9+28h]
0x3479BA: 498BAFD8000000                   mov     rbp, [r15+0D8h]
0x03E159: 458B4734                         mov     r8d, [r15+34h]
0x347A26: 4D0387A8000000                   add     r8, [r15+0A8h]
0x03E164: 418A10                           mov     dl, [r8]
0x03E167: 4088D5                           mov     bpl, dl
0x03E23E: 498B6928                         mov     rbp, [r9+28h]
0x347AF3: 4C8B95A0000000                   mov     r10, [rbp+0A0h]
0x03E249: 4152                             push    r10
0x03E24B: 4989E4                           mov     r12, rsp
0x347B5C: 488BB5A0000000                   mov     rsi, [rbp+0A0h]
0x03E33E: 4D8B4928                         mov     r9, [r9+28h]
0x347C27: 498BB9A0000000                   mov     rdi, [r9+0A0h]
0x347C8D: 4D8BB9A8000000                   mov     r15, [r9+0A8h]
0x03E350: 480FB6FF                         movzx   rdi, dil
0x03E429: 498B5128                         mov     rdx, [r9+28h]
0x347D60: 0FAE92B0000000                   ldmxcsr dword ptr [rdx+0B0h]
0x347DC5: 48BF863F221201000000             mov     rdi, 112223F86h
0x347E35: 4881C73A33E72D                   add     rdi, 2DE7333Ah
0x347EA0: 488BBF48050000                   mov     rdi, [rdi+548h]
0x347F0D: 4803BAB0000000                   add     rdi, [rdx+0B0h]
0x03E453: 408A3F                           mov     dil, [rdi]
0x03E456: 480FB6FF                         movzx   rdi, dil
0x03E45A: 48C1E710                         shl     rdi, 10h
0x347F79: 4829BAF0000000                   sub     [rdx+0F0h], rdi
0x03E465: 4D8B6928                         mov     r13, [r9+28h]
0x347FE4: 498BADF0000000                   mov     rbp, [r13+0F0h]
0x34804B: 49BC88FD9C1A01000000             mov     r12, 11A9CFD88h
0x3480BC: 4981C4386D6C25                   add     r12, 256C6D38h
0x03E579: 4D8B7128                         mov     r14, [r9+28h]
0x03E57D: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x348188: 498B9EF0000000                   mov     rbx, [r14+0F0h]
0x3481ED: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x03E66C: 4D8B4128                         mov     r8, [r9+28h]
0x3482B7: 498BB8E8000000                   mov     rdi, [r8+0E8h]
0x03E677: 418B4834                         mov     ecx, [r8+34h]
0x348323: 49038890000000                   add     rcx, [r8+90h]
0x03E682: 448A01                           mov     r8b, [rcx]
0x348389: 49C7C2FF000000                   mov     r10, 0FFh
0x03E68C: 49C1E208                         shl     r10, 8
0x03E690: 49F7D2                           not     r10
0x03E693: 4C21D7                           and     rdi, r10
0x03E696: 4D0FB6D0                         movzx   r10, r8b
0x03E69A: 49C1E208                         shl     r10, 8
0x03E69E: 4C09D7                           or      rdi, r10
0x03E775: 4D8B7928                         mov     r15, [r9+28h]
0x348455: 4D8B97B0000000                   mov     r10, [r15+0B0h]
0x03E780: 4152                             push    r10
0x03E782: 4989E4                           mov     r12, rsp
0x3484C3: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x03E86B: 4D8B4128                         mov     r8, [r9+28h]
0x348592: 498BB0C8000000                   mov     rsi, [r8+0C8h]
0x3485FC: 4D8BA0B0000000                   mov     r12, [r8+0B0h]
0x03E87D: 480FB6F6                         movzx   rsi, sil
0x03E957: 4D8B5128                         mov     r10, [r9+28h]
0x3486C8: 410FAE92A8000000                 ldmxcsr dword ptr [r10+0A8h]
0x34872F: 49BDB83B600901000000             mov     r13, 109603BB8h
0x348798: 4981C50837A936                   add     r13, 36A93708h
0x3487FF: 4D8BAD50070000                   mov     r13, [r13+750h]
0x348865: 4D03AAA8000000                   add     r13, [r10+0A8h]
0x03E982: 418A4D00                         mov     cl, [r13+0]
0x03E986: 480FB6C9                         movzx   rcx, cl
0x03E98A: 48C1E118                         shl     rcx, 18h
0x3488CD: 49298AD8000000                   sub     [r10+0D8h], rcx
0x03E995: 498B4928                         mov     rcx, [r9+28h]
0x348932: 4C8BA9D8000000                   mov     r13, [rcx+0D8h]
0x34899B: 49BF52570F3901000000             mov     r15, 1390F5752h
0x348A0A: 4981C76E13FA06                   add     r15, 6FA136Eh
0x03EA8A: 4D8B7928                         mov     r15, [r9+28h]
0x03EA8E: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x348ADF: 4D8BB788000000                   mov     r14, [r15+88h]
0x348B48: 498BAFE0000000                   mov     rbp, [r15+0E0h]
0x03EB8D: 498B5128                         mov     rdx, [r9+28h]
0x348C1A: 488BBAA0000000                   mov     rdi, [rdx+0A0h]
0x03EB98: 8B4A34                           mov     ecx, [rdx+34h]
0x348C87: 48038AE8000000                   add     rcx, [rdx+0E8h]
0x03EBA2: 448A21                           mov     r12b, [rcx]
0x348CEF: 48C7C5FF000000                   mov     rbp, 0FFh
0x03EBAC: 48C1E510                         shl     rbp, 10h
0x03EBB0: 48F7D5                           not     rbp
0x03EBB3: 4821EF                           and     rdi, rbp
0x03EBB6: 490FB6EC                         movzx   rbp, r12b
0x03EBBA: 48C1E510                         shl     rbp, 10h
0x03EBBE: 4809EF                           or      rdi, rbp
0x03EC92: 498B6928                         mov     rbp, [r9+28h]
0x348DC1: 4C8BBDB0000000                   mov     r15, [rbp+0B0h]
0x03EC9D: 4157                             push    r15
0x03EC9F: 4989E5                           mov     r13, rsp
0x348E2C: 4C8BB5B0000000                   mov     r14, [rbp+0B0h]
0x03ED8F: 498B5928                         mov     rbx, [r9+28h]
0x348EFF: 4C8BABE0000000                   mov     r13, [rbx+0E0h]
0x348F6A: 488BB3E8000000                   mov     rsi, [rbx+0E8h]
0x03EDA1: 4155                             push    r13
0x03EDA3: 682C7E017D                       push    7D017E2Ch
0x03EDA8: 68962C4B57                       push    574B2C96h
0x03EDAD: 68BE31E03D                       push    3DE031BEh
0x03EEAE: 4D8B7928                         mov     r15, [r9+28h]
0x349035: 4D8BA7D8000000                   mov     r12, [r15+0D8h]
0x34909E: 498BB7A8000000                   mov     rsi, [r15+0A8h]
0x03EEC0: 4D0FB6E4                         movzx   r12, r12b
0x03EFA4: 498B7928                         mov     rdi, [r9+28h]
0x349171: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x3491DD: 48BA8E579B0501000000             mov     rdx, 1059B578Eh
0x34924B: 4881C2321B6E3A                   add     rdx, 3A6E1B32h
0x3492B7: 488B9268030000                   mov     rdx, [rdx+368h]
0x349320: 480397D8000000                   add     rdx, [rdi+0D8h]
0x03EFCE: 448A32                           mov     r14b, [rdx]
0x03EFD1: 4D0FB6F6                         movzx   r14, r14b
0x03EFD5: 49C1E620                         shl     r14, 20h
0x34938D: 4C29B7A8000000                   sub     [rdi+0A8h], r14
0x03EFE0: 4D8B4928                         mov     r9, [r9+28h]
0x3493F7: 4D8BB9A8000000                   mov     r15, [r9+0A8h]
0x34945F: 48BEA54411F400000000             mov     rsi, 0F41144A5h
0x3494CB: 4881C61B26F84B                   add     rsi, 4BF8261Bh
0x03F0EB: 4D8B6928                         mov     r13, [r9+28h]
0x03F0EF: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x34959D: 498BBDC0000000                   mov     rdi, [r13+0C0h]
0x34960B: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x03F1EC: 498B7928                         mov     rdi, [r9+28h]
0x3496DD: 4C8BBFE8000000                   mov     r15, [rdi+0E8h]
0x03F1F7: 448B6734                         mov     r12d, [rdi+34h]
0x349748: 4C03A7B0000000                   add     r12, [rdi+0B0h]
0x03F202: 418A3C24                         mov     dil, [r12]
0x3497B5: 48C7C2FF000000                   mov     rdx, 0FFh
0x03F20D: 48C1E218                         shl     rdx, 18h
0x03F211: 48F7D2                           not     rdx
0x03F214: 4921D7                           and     r15, rdx
0x03F217: 480FB6D7                         movzx   rdx, dil
0x03F21B: 48C1E218                         shl     rdx, 18h
0x03F21F: 4909D7                           or      r15, rdx
0x03F304: 498B6928                         mov     rbp, [r9+28h]
0x34988A: 4C8B9DF0000000                   mov     r11, [rbp+0F0h]
0x03F30F: 4153                             push    r11
0x03F311: 4989E4                           mov     r12, rsp
0x3498EF: 488B9DF0000000                   mov     rbx, [rbp+0F0h]
0x03F40A: 498B4128                         mov     rax, [r9+28h]
0x3499C8: 4C8BB8B8000000                   mov     r15, [rax+0B8h]
0x349A36: 488B9890000000                   mov     rbx, [rax+90h]
0x03F41C: 4D0FB6FF                         movzx   r15, r15b
0x03F50F: 498B5928                         mov     rbx, [r9+28h]
0x349B07: 0FAE93F0000000                   ldmxcsr dword ptr [rbx+0F0h]
0x349B75: 49BFDE51E9D100000000             mov     r15, 0D1E951DEh
0x349BDE: 4981C7E220206E                   add     r15, 6E2020E2h
0x03F52B: 4D8B3F                           mov     r15, [r15]
0x349C48: 4C03BBF0000000                   add     r15, [rbx+0F0h]
0x03F535: 418A2F                           mov     bpl, [r15]
0x03F538: 480FB6ED                         movzx   rbp, bpl
0x03F53C: 48C1E528                         shl     rbp, 28h
0x349CB0: 4829AB90000000                   sub     [rbx+90h], rbp
0x349D1A: 48B9C922560B01000000             mov     rcx, 10B5622C9h
0x03F551: 51                               push    rcx
0x03F552: 688657AA2C                       push    2CAA5786h
0x03F557: 68584A3158                       push    58314A58h
0x03F55C: 686D7F1047                       push    47107F6Dh
0x349D8A: 4881442418F747B334               add     [rsp-8+arg_18], 34B347F7h
0x03F56A: 4D8B7928                         mov     r15, [r9+28h]
0x349DF2: 4D8BA790000000                   mov     r12, [r15+90h]
0x03F651: 4D8B4928                         mov     r9, [r9+28h]
0x03F655: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x349EBE: 498BB1A0000000                   mov     rsi, [r9+0A0h]
0x349F23: 4D8BB1D8000000                   mov     r14, [r9+0D8h]
0x03F740: 4D8B7128                         mov     r14, [r9+28h]
0x349FF4: 498BBEE8000000                   mov     rdi, [r14+0E8h]
0x03F74B: 458B4E34                         mov     r9d, [r14+34h]
0x34A061: 4D038EA8000000                   add     r9, [r14+0A8h]
0x03F756: 418A09                           mov     cl, [r9]
0x34A0C8: 49C7C3FF000000                   mov     r11, 0FFh
0x03F760: 49C1E320                         shl     r11, 20h
0x03F764: 49F7D3                           not     r11
0x03F767: 4C21DF                           and     rdi, r11
0x03F76A: 4C0FB6D9                         movzx   r11, cl
0x03F76E: 49C1E320                         shl     r11, 20h
0x03F772: 4C09DF                           or      rdi, r11
0x03F857: 498B5928                         mov     rbx, [r9+28h]
0x34A19E: 488BB3B0000000                   mov     rsi, [rbx+0B0h]
0x03F862: 56                               push    rsi
0x03F863: 4989E6                           mov     r14, rsp
0x34A207: 4C8BABB0000000                   mov     r13, [rbx+0B0h]
0x03F947: 498B7128                         mov     rsi, [r9+28h]
0x34A2D4: 4C8B96E8000000                   mov     r10, [rsi+0E8h]
0x34A33E: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x03F959: 4152                             push    r10
0x03F95B: 68FF52447B                       push    7B4452FFh
0x03F960: 68A9674C40                       push    404C67A9h
0x03F965: 689D34EE15                       push    15EE349Dh
0x03FA52: 498B7928                         mov     rdi, [r9+28h]
0x34A409: 488B9FD0000000                   mov     rbx, [rdi+0D0h]
0x34A477: 4C8BBFF0000000                   mov     r15, [rdi+0F0h]
0x03FA64: 480FB6DB                         movzx   rbx, bl
0x03FB47: 4D8B5128                         mov     r10, [r9+28h]
0x34A546: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x34A5AD: 49BF6D14DEC800000000             mov     r15, 0C8DE146Dh
0x34A61E: 4981C7535E2B77                   add     r15, 772B5E53h
0x03FB64: 4D8B3F                           mov     r15, [r15]
0x34A68B: 4D03BA90000000                   add     r15, [r10+90h]
0x03FB6E: 418A07                           mov     al, [r15]
0x03FB71: 480FB6C0                         movzx   rax, al
0x03FB75: 48C1E030                         shl     rax, 30h
0x34A6F0: 492982F0000000                   sub     [r10+0F0h], rax
0x03FB80: 4D8B7128                         mov     r14, [r9+28h]
0x34A75E: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x34A7C9: 49BD1121F7F000000000             mov     r13, 0F0F72111h
0x34A837: 4981C5AF49124F                   add     r13, 4F1249AFh
0x03FC7C: 4D8B7928                         mov     r15, [r9+28h]
0x03FC80: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x34A902: 498B9F80000000                   mov     rbx, [r15+80h]
0x34A969: 4D8BBFF0000000                   mov     r15, [r15+0F0h]
0x03FD76: 4D8B6128                         mov     r12, [r9+28h]
0x34AA3D: 498BAC24F0000000                 mov     rbp, [r12+0F0h]
0x03FD82: 418B7C2434                       mov     edi, [r12+34h]
0x34AAA3: 4903BC2490000000                 add     rdi, [r12+90h]
0x03FD8F: 408A3F                           mov     dil, [rdi]
0x34AB0B: 49C7C6FF000000                   mov     r14, 0FFh
0x03FD99: 49C1E628                         shl     r14, 28h
0x03FD9D: 49F7D6                           not     r14
0x03FDA0: 4C21F5                           and     rbp, r14
0x03FDA3: 4C0FB6F7                         movzx   r14, dil
0x03FDA7: 49C1E628                         shl     r14, 28h
0x03FDAB: 4C09F5                           or      rbp, r14
0x03FE86: 498B7928                         mov     rdi, [r9+28h]
0x34ABDB: 488BB7A0000000                   mov     rsi, [rdi+0A0h]
0x03FE91: 56                               push    rsi
0x03FE92: 4889E5                           mov     rbp, rsp
0x34AC45: 4C8BA7A0000000                   mov     r12, [rdi+0A0h]
0x03FF8F: 4D8B6128                         mov     r12, [r9+28h]
0x34AD0F: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x34AD78: 498BAC24D8000000                 mov     rbp, [r12+0D8h]
0x03FFA3: 4D0FB6FF                         movzx   r15, r15b
0x04007A: 4D8B5928                         mov     r11, [r9+28h]
0x34AE49: 410FAE93F0000000                 ldmxcsr dword ptr [r11+0F0h]
0x34AEB7: 49BAA8420C2A01000000             mov     r10, 12A0C42A8h
0x34AF27: 4981C21830FD15                   add     r10, 15FD3018h
0x040097: 4D8B12                           mov     r10, [r10]
0x34AF8F: 4D0393F0000000                   add     r10, [r11+0F0h]
0x0400A1: 418A2A                           mov     bpl, [r10]
0x0400A4: 480FB6ED                         movzx   rbp, bpl
0x0400A8: 48C1E538                         shl     rbp, 38h
0x34AFFD: 4929ABA0000000                   sub     [r11+0A0h], rbp
0x34B067: 48BE1229B9E100000000             mov     rsi, 0E1B92912h
0x0400BD: 56                               push    rsi
0x0400BE: 684C6FDD1C                       push    1CDD6F4Ch
0x0400C3: 680B739012                       push    1290730Bh
0x0400C8: 68C151216F                       push    6F2151C1h
0x0400CD: 681518E931                       push    31E91815h
0x34B0D2: 4881442420AE41505E               add     qword ptr [rsp+20h], 5E5041AEh
0x0400DB: 4D8B4128                         mov     r8, [r9+28h]
0x34B13C: 498BB8A0000000                   mov     rdi, [r8+0A0h]
0x0401BF: 4D8B6928                         mov     r13, [r9+28h]
0x0401C3: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x34B212: 4D8BBDD0000000                   mov     r15, [r13+0D0h]
0x34B27E: 4D8BA5B0000000                   mov     r12, [r13+0B0h]
0x0402AD: 498B5128                         mov     rdx, [r9+28h]
0x34B350: 4C8BAAD8000000                   mov     r13, [rdx+0D8h]
0x0402B8: 8B7234                           mov     esi, [rdx+34h]
0x34B3BC: 4803B2F0000000                   add     rsi, [rdx+0F0h]
0x0402C2: 448A3E                           mov     r15b, [rsi]
0x34B427: 49C7C2FF000000                   mov     r10, 0FFh
0x0402CC: 49C1E230                         shl     r10, 30h
0x0402D0: 49F7D2                           not     r10
0x0402D3: 4D21D5                           and     r13, r10
0x0402D6: 4D0FB6D7                         movzx   r10, r15b
0x0402DA: 49C1E230                         shl     r10, 30h
0x0402DE: 4D09D5                           or      r13, r10
0x0403D0: 4D8B5928                         mov     r11, [r9+28h]
0x34B4F8: 4D8BBBE0000000                   mov     r15, [r11+0E0h]
0x0403DB: 4157                             push    r15
0x0403DD: 4989E7                           mov     r15, rsp
0x34B564: 4D8BABE0000000                   mov     r13, [r11+0E0h]
0x0404AE: 4D8B7128                         mov     r14, [r9+28h]
0x34B63C: 4D8B86F0000000                   mov     r8, [r14+0F0h]
0x34B6AA: 4D8BB6E0000000                   mov     r14, [r14+0E0h]
0x0404C0: 4150                             push    r8
0x0404C2: 684B281F4A                       push    4A1F284Bh
0x0404C7: 685B62ED1F                       push    1FED625Bh
0x0404CC: 681916DF21                       push    21DF1619h
0x0404D1: 6858252D36                       push    362D2558h
0x0405D8: 4D8B5928                         mov     r11, [r9+28h]
0x34B782: 4D8BB3D0000000                   mov     r14, [r11+0D0h]
0x34B7E8: 498BABE8000000                   mov     rbp, [r11+0E8h]
0x0405EA: 4D0FB6F6                         movzx   r14, r14b
0x0406CA: 4D8B7128                         mov     r14, [r9+28h]
0x34B8B7: 410FAE96E8000000                 ldmxcsr dword ptr [r14+0E8h]
0x0406D6: 498B7128                         mov     rsi, [r9+28h]
0x34B91F: 488BBEA0000000                   mov     rdi, [rsi+0A0h]
0x34B987: 48BB7369BEC600000000             mov     rbx, 0C6BE6973h
0x34B9F3: 4881C34D014B79                   add     rbx, 794B014Dh
0x0407D1: 4D8B7928                         mov     r15, [r9+28h]
0x0407D5: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x34BAC0: 498B9F88000000                   mov     rbx, [r15+88h]
0x34BB2D: 4D8BBFB0000000                   mov     r15, [r15+0B0h]
0x0408C0: 498B4128                         mov     rax, [r9+28h]
0x34BBF9: 4C8BA0F0000000                   mov     r12, [rax+0F0h]
0x0408CB: 448B6834                         mov     r13d, [rax+34h]
0x34BC5F: 4C03A890000000                   add     r13, [rax+90h]
0x0408D6: 418A7D00                         mov     dil, [r13+0]
0x34BCC8: 48C7C6FF000000                   mov     rsi, 0FFh
0x0408E1: 48C1E638                         shl     rsi, 38h
0x0408E5: 48F7D6                           not     rsi
0x0408E8: 4921F4                           and     r12, rsi
0x0408EB: 480FB6F7                         movzx   rsi, dil
0x0408EF: 48C1E638                         shl     rsi, 38h
0x0408F3: 4909F4                           or      r12, rsi
0x34BD96: 49BC745BEA2301000000             mov     r12, 123EA5B74h
0x0409D8: 4154                             push    r12
0x0409DA: 68D748B776                       push    76B748D7h
0x0409DF: 686F466B38                       push    386B466Fh
0x0409E4: 687D37E411                       push    11E4377Dh
0x0409E9: 681333CA15                       push    15CA3313h
0x34BE00: 4881442420745D9F1C               add     [rsp-8+arg_20], 1C9F5D74h
0x0409F7: 498B6928                         mov     rbp, [r9+28h]
0x34BE6B: 488BADD8000000                   mov     rbp, [rbp+0D8h]
0x040AF2: 4D8B5128                         mov     r10, [r9+28h]
0x34BF37: 498BAAA8000000                   mov     rbp, [r10+0A8h]
0x34BF9F: 498BB2A0000000                   mov     rsi, [r10+0A0h]
0x040B04: 480FB6ED                         movzx   rbp, bpl
0x040BEE: 4D8B6128                         mov     r12, [r9+28h]
0x34C06B: 498B8424A0000000                 mov     rax, [r12+0A0h]
0x34C0D7: 48C7C5407719CB                   mov     rbp, 0FFFFFFFFCB197740h
0x34C13D: 4881C5334E5035                   add     rbp, 35504E33h
0x040C08: 55                               push    rbp
0x34C1A2: 498B9C24A8000000                 mov     rbx, [r12+0A8h]
0x040C11: 48F72424                         mul     qword ptr [rsp]
0x040C15: 4889C7                           mov     rdi, rax
0x040CF0: 498B7928                         mov     rdi, [r9+28h]
0x34C270: 4C8BBF90000000                   mov     r15, [rdi+90h]
0x34C2DD: 4C03BFB0000000                   add     r15, [rdi+0B0h]
0x040DDF: 498B4928                         mov     rcx, [r9+28h]
0x34C3AB: 4C8BA1F0000000                   mov     r12, [rcx+0F0h]
0x040DEA: 4154                             push    r12
0x040DEC: 4989E5                           mov     r13, rsp
0x34C417: 4C8BA1F0000000                   mov     r12, [rcx+0F0h]
0x040ECE: 498B4928                         mov     rcx, [r9+28h]
0x34C4E7: 488B99E0000000                   mov     rbx, [rcx+0E0h]
0x34C550: 4C8BB9D8000000                   mov     r15, [rcx+0D8h]
0x040EE0: 53                               push    rbx
0x040EE1: 689D71E531                       push    31E5719Dh
0x040EE6: 6880450836                       push    36084580h
0x040EEB: 685828E673                       push    73E62858h
0x040FCE: 4D8B4928                         mov     r9, [r9+28h]
0x34C61F: 4D8BB980000000                   mov     r15, [r9+80h]
0x34C687: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x040FE0: 4D0FB6FF                         movzx   r15, r15b
0x0410CE: 498B7928                         mov     rdi, [r9+28h]
0x34C75C: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x34C7C3: 48BB0B6887E200000000             mov     rbx, 0E287680Bh
0x34C82B: 4881C3B50A825D                   add     rbx, 5D820AB5h
0x34C891: 488B9BE8020000                   mov     rbx, [rbx+2E8h]
0x34C8F7: 48039FF0000000                   add     rbx, [rdi+0F0h]
0x0410F8: 448A03                           mov     r8b, [rbx]
0x0410FB: 4D0FB6C0                         movzx   r8, r8b
0x0410FF: 49C1E008                         shl     r8, 8
0x34C95E: 4C298790000000                   sub     [rdi+90h], r8
0x34C9C7: 48BAD41C40D900000000             mov     rdx, 0D9401CD4h
0x041114: 52                               push    rdx
0x041115: 688167A033                       push    33A06781h
0x04111A: 68E213E956                       push    56E913E2h
0x04111F: 685A0DA62A                       push    2AA60D5Ah
0x041124: 683150CE4A                       push    4ACE5031h
0x34CA2F: 4881442420EC4DC966               add     qword ptr [rsp+20h], 66C94DECh
0x041132: 4D8B5928                         mov     r11, [r9+28h]
0x34CA9A: 498BBB90000000                   mov     rdi, [r11+90h]
0x04122B: 4D8B4928                         mov     r9, [r9+28h]
0x04122F: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x34CB6D: 498BB9C8000000                   mov     rdi, [r9+0C8h]
0x34CBD3: 498BB1B0000000                   mov     rsi, [r9+0B0h]
0x04132F: 498B5128                         mov     rdx, [r9+28h]
0x34CCA4: 4C8BB2A8000000                   mov     r14, [rdx+0A8h]
0x04133A: 8B7A34                           mov     edi, [rdx+34h]
0x34CD11: 4803BAB0000000                   add     rdi, [rdx+0B0h]
0x041344: 8A17                             mov     dl, [rdi]
0x041346: 4188D6                           mov     r14b, dl
0x041435: 498B6928                         mov     rbp, [r9+28h]
0x34CDE0: 4C8BA5E8000000                   mov     r12, [rbp+0E8h]
0x041440: 4154                             push    r12
0x041442: 4989E6                           mov     r14, rsp
0x34CE46: 488BBDE8000000                   mov     rdi, [rbp+0E8h]
0x04153D: 4D8B5128                         mov     r10, [r9+28h]
0x34CF12: 498BAAC8000000                   mov     rbp, [r10+0C8h]
0x34CF80: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x04154F: 480FB6ED                         movzx   rbp, bpl
0x041634: 4D8B6928                         mov     r13, [r9+28h]
0x34D054: 410FAE95A0000000                 ldmxcsr dword ptr [r13+0A0h]
0x34D0C1: 49BF5667B01001000000             mov     r15, 110B06756h
0x34D12F: 4981C76A0B592F                   add     r15, 2F590B6Ah
0x34D19C: 4D8BBFE0020000                   mov     r15, [r15+2E0h]
0x34D207: 4D03BDA0000000                   add     r15, [r13+0A0h]
0x04165F: 458A1F                           mov     r11b, [r15]
0x041662: 4D0FB6DB                         movzx   r11, r11b
0x041666: 49C1E310                         shl     r11, 10h
0x34D26C: 4D299DD8000000                   sub     [r13+0D8h], r11
0x041671: 498B6928                         mov     rbp, [r9+28h]
0x34D2D6: 488BBDD8000000                   mov     rdi, [rbp+0D8h]
0x34D33D: 49BE5B40F9FF00000000             mov     r14, 0FFF9405Bh
0x34D3AD: 4981C6652A1040                   add     r14, 40102A65h
0x041768: 4D8B5128                         mov     r10, [r9+28h]
0x04176C: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x34D480: 498BB288000000                   mov     rsi, [r10+88h]
0x34D4E5: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x041863: 498B4928                         mov     rcx, [r9+28h]
0x34D5BB: 4C8BA990000000                   mov     r13, [rcx+90h]
0x04186E: 448B7934                         mov     r15d, [rcx+34h]
0x34D620: 4C03B9A8000000                   add     r15, [rcx+0A8h]
0x041879: 458A27                           mov     r12b, [r15]
0x34D686: 49C7C1FF000000                   mov     r9, 0FFh
0x041883: 49C1E108                         shl     r9, 8
0x041887: 49F7D1                           not     r9
0x04188A: 4D21CD                           and     r13, r9
0x04188D: 4D0FB6CC                         movzx   r9, r12b
0x041891: 49C1E108                         shl     r9, 8
0x041895: 4D09CD                           or      r13, r9
0x04197B: 4D8B7928                         mov     r15, [r9+28h]
0x34D75F: 4D8BA7E0000000                   mov     r12, [r15+0E0h]
0x041986: 4154                             push    r12
0x041988: 4889E7                           mov     rdi, rsp
0x34D7C6: 4D8BBFE0000000                   mov     r15, [r15+0E0h]
0x041A75: 498B7128                         mov     rsi, [r9+28h]
0x34D88E: 4C8B9EB0000000                   mov     r11, [rsi+0B0h]
0x34D8F8: 488B9EF0000000                   mov     rbx, [rsi+0F0h]
0x041A87: 4153                             push    r11
0x041A89: 68C0710073                       push    730071C0h
0x041A8E: 68D80E7800                       push    780ED8h
0x041A93: 6851300756                       push    56073051h
0x041B72: 4D8B7128                         mov     r14, [r9+28h]
0x34D9CA: 498B9EE8000000                   mov     rbx, [r14+0E8h]
0x34DA37: 498BBE90000000                   mov     rdi, [r14+90h]
0x041B84: 480FB6DB                         movzx   rbx, bl
0x041C62: 4D8B7128                         mov     r14, [r9+28h]
0x34DB0A: 410FAE9690000000                 ldmxcsr dword ptr [r14+90h]
0x34DB77: 48BE232B190701000000             mov     rsi, 107192B23h
0x34DBE7: 4881C69D47F038                   add     rsi, 38F0479Dh
0x34DC50: 488BB660050000                   mov     rsi, [rsi+560h]
0x34DCBA: 4903B690000000                   add     rsi, [r14+90h]
0x041C8D: 408A3E                           mov     dil, [rsi]
0x041C90: 480FB6FF                         movzx   rdi, dil
0x041C94: 48C1E718                         shl     rdi, 18h
0x34DD26: 4929BEB0000000                   sub     [r14+0B0h], rdi
0x041C9F: 4D8B7128                         mov     r14, [r9+28h]
0x34DD93: 498B9EB0000000                   mov     rbx, [r14+0B0h]
0x34DDFF: 49BEBCF959E900000000             mov     r14, 0E959F9BCh
0x34DE69: 4981C60471AF56                   add     r14, 56AF7104h
0x041D98: 4D8B6928                         mov     r13, [r9+28h]
0x041D9C: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x34DF3C: 4D8BBDD8000000                   mov     r15, [r13+0D8h]
0x34DFA5: 498BAD90000000                   mov     rbp, [r13+90h]
0x041E97: 4D8B6928                         mov     r13, [r9+28h]
0x34E07C: 4D8BBDA0000000                   mov     r15, [r13+0A0h]
0x041EA2: 458B4534                         mov     r8d, [r13+34h]
0x34E0E7: 4D0385F0000000                   add     r8, [r13+0F0h]
0x041EAD: 458A18                           mov     r11b, [r8]
0x34E153: 48C7C7FF000000                   mov     rdi, 0FFh
0x041EB7: 48C1E710                         shl     rdi, 10h
0x041EBB: 48F7D7                           not     rdi
0x041EBE: 4921FF                           and     r15, rdi
0x041EC1: 490FB6FB                         movzx   rdi, r11b
0x041EC5: 48C1E710                         shl     rdi, 10h
0x041EC9: 4909FF                           or      r15, rdi
0x041FA3: 498B5928                         mov     rbx, [r9+28h]
0x34E224: 488B93F0000000                   mov     rdx, [rbx+0F0h]
0x041FAE: 52                               push    rdx
0x041FAF: 4889E7                           mov     rdi, rsp
0x34E28E: 488BABF0000000                   mov     rbp, [rbx+0F0h]
0x042099: 4D8B6128                         mov     r12, [r9+28h]
0x34E363: 498BBC24D8000000                 mov     rdi, [r12+0D8h]
0x34E3C9: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x0420AD: 480FB6FF                         movzx   rdi, dil
0x04219B: 498B7128                         mov     rsi, [r9+28h]
0x34E49C: 0FAE96B0000000                   ldmxcsr dword ptr [rsi+0B0h]
0x34E506: 48BB355DFB0701000000             mov     rbx, 107FB5D35h
0x34E56E: 4881C38B150E38                   add     rbx, 380E158Bh
0x34E5D5: 488B9B48060000                   mov     rbx, [rbx+648h]
0x34E643: 48039EB0000000                   add     rbx, [rsi+0B0h]
0x0421C5: 448A2B                           mov     r13b, [rbx]
0x0421C8: 4D0FB6ED                         movzx   r13, r13b
0x0421CC: 49C1E520                         shl     r13, 20h
0x34E6AB: 4C29AEE0000000                   sub     [rsi+0E0h], r13
0x0421D7: 498B7128                         mov     rsi, [r9+28h]
0x34E710: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x34E77B: 49BDC8EDB13501000000             mov     r13, 135B1EDC8h
0x34E7EC: 4981C5F87C570A                   add     r13, 0A577CF8h
0x0422D9: 498B7928                         mov     rdi, [r9+28h]
0x0422DD: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x34E8C2: 4C8BA7E0000000                   mov     r12, [rdi+0E0h]
0x34E930: 488BAFF0000000                   mov     rbp, [rdi+0F0h]
0x0423C9: 4D8B5928                         mov     r11, [r9+28h]
0x34EA02: 498BBBA0000000                   mov     rdi, [r11+0A0h]
0x0423D4: 418B6B34                         mov     ebp, [r11+34h]
0x34EA70: 4903ABD8000000                   add     rbp, [r11+0D8h]
0x0423DF: 448A6500                         mov     r12b, [rbp+0]
0x34EADB: 48C7C5FF000000                   mov     rbp, 0FFh
0x0423EA: 48C1E518                         shl     rbp, 18h
0x0423EE: 48F7D5                           not     rbp
0x0423F1: 4821EF                           and     rdi, rbp
0x0423F4: 490FB6EC                         movzx   rbp, r12b
0x0423F8: 48C1E518                         shl     rbp, 18h
0x0423FC: 4809EF                           or      rdi, rbp
0x0424E3: 4D8B5128                         mov     r10, [r9+28h]
0x34EBAD: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x0424EE: 53                               push    rbx
0x0424EF: 4889E5                           mov     rbp, rsp
0x34EC18: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x0425E8: 498B7928                         mov     rdi, [r9+28h]
0x34ECED: 488B9FF0000000                   mov     rbx, [rdi+0F0h]
0x34ED52: 488BB7D8000000                   mov     rsi, [rdi+0D8h]
0x0425FA: 480FB6DB                         movzx   rbx, bl
0x0426C6: 498B5928                         mov     rbx, [r9+28h]
0x34EE23: 0FAE9390000000                   ldmxcsr dword ptr [rbx+90h]
0x34EE8D: 49BF9E70F0C500000000             mov     r15, 0C5F0709Eh
0x34EEF9: 4981C72202197A                   add     r15, 7A190222h
0x0426E2: 4D8B3F                           mov     r15, [r15]
0x34EF66: 4C03BB90000000                   add     r15, [rbx+90h]
0x0426EC: 458A2F                           mov     r13b, [r15]
0x0426EF: 4D0FB6ED                         movzx   r13, r13b
0x0426F3: 49C1E528                         shl     r13, 28h
0x34EFD2: 4C29ABA8000000                   sub     [rbx+0A8h], r13
0x0426FE: 4D8B5928                         mov     r11, [r9+28h]
0x34F03D: 498B9BA8000000                   mov     rbx, [r11+0A8h]
0x34F0AA: 48BD063CDBD200000000             mov     rbp, 0D2DB3C06h
0x34F114: 4881C5BA2E2E6D                   add     rbp, 6D2E2EBAh
0x042800: 498B4128                         mov     rax, [r9+28h]
0x042804: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x042808: 4C8B7078                         mov     r14, [rax+78h]
0x34F1E0: 4C8BB890000000                   mov     r15, [rax+90h]
0x0428F7: 498B4928                         mov     rcx, [r9+28h]
0x34F2AF: 488BB9F0000000                   mov     rdi, [rcx+0F0h]
0x042902: 448B7934                         mov     r15d, [rcx+34h]
0x34F315: 4C03B9E8000000                   add     r15, [rcx+0E8h]
0x04290D: 458A1F                           mov     r11b, [r15]
0x34F37D: 48C7C0FF000000                   mov     rax, 0FFh
0x042917: 48C1E020                         shl     rax, 20h
0x04291B: 48F7D0                           not     rax
0x04291E: 4821C7                           and     rdi, rax
0x042921: 490FB6C3                         movzx   rax, r11b
0x042925: 48C1E020                         shl     rax, 20h
0x042929: 4809C7                           or      rdi, rax
0x042A0D: 4D8B5128                         mov     r10, [r9+28h]
0x34F44B: 4D8B82B0000000                   mov     r8, [r10+0B0h]
0x042A18: 4150                             push    r8
0x042A1A: 4989E7                           mov     r15, rsp
0x34F4B4: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x042B07: 498B7128                         mov     rsi, [r9+28h]
0x042B0B: 4C8B6678                         mov     r12, [rsi+78h]
0x34F589: 488B9E90000000                   mov     rbx, [rsi+90h]
0x042B16: 4D0FB6E4                         movzx   r12, r12b
0x042C03: 4D8B5928                         mov     r11, [r9+28h]
0x34F65E: 410FAE93D8000000                 ldmxcsr dword ptr [r11+0D8h]
0x34F6C5: 49BA806F77D700000000             mov     r10, 0D7776F80h
0x34F72D: 4981C240039268                   add     r10, 68920340h
0x042C20: 4D8B12                           mov     r10, [r10]
0x34F79A: 4D0393D8000000                   add     r10, [r11+0D8h]
0x042C2A: 418A3A                           mov     dil, [r10]
0x042C2D: 480FB6FF                         movzx   rdi, dil
0x042C31: 48C1E730                         shl     rdi, 30h
0x34F7FF: 4929BB90000000                   sub     [r11+90h], rdi
0x042C3C: 4D8B7928                         mov     r15, [r9+28h]
0x34F86A: 4D8BBF90000000                   mov     r15, [r15+90h]
0x34F8D2: 49BD4D47D9E400000000             mov     r13, 0E4D9474Dh
0x34F941: 4981C57323305B                   add     r13, 5B302373h
0x042D40: 498B7928                         mov     rdi, [r9+28h]
0x042D44: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x34FA0F: 4C8BAF90000000                   mov     r13, [rdi+90h]
0x34FA79: 4C8BBFF0000000                   mov     r15, [rdi+0F0h]
0x042E35: 498B6928                         mov     rbp, [r9+28h]
0x34FB4C: 488BBDF0000000                   mov     rdi, [rbp+0F0h]
0x042E40: 448B5534                         mov     r10d, [rbp+34h]
0x34FBB6: 4C0395E0000000                   add     r10, [rbp+0E0h]
0x042E4B: 458A32                           mov     r14b, [r10]
0x34FC1D: 49C7C2FF000000                   mov     r10, 0FFh
0x042E55: 49C1E228                         shl     r10, 28h
0x042E59: 49F7D2                           not     r10
0x042E5C: 4C21D7                           and     rdi, r10
0x042E5F: 4D0FB6D6                         movzx   r10, r14b
0x042E63: 49C1E228                         shl     r10, 28h
0x042E67: 4C09D7                           or      rdi, r10
0x042F56: 498B7928                         mov     rdi, [r9+28h]
0x34FCF0: 488B87B0000000                   mov     rax, [rdi+0B0h]
0x042F61: 50                               push    rax
0x042F62: 4989E4                           mov     r12, rsp
0x34FD59: 488B9FB0000000                   mov     rbx, [rdi+0B0h]
0x043055: 498B4928                         mov     rcx, [r9+28h]
0x34FE25: 488BA9B0000000                   mov     rbp, [rcx+0B0h]
0x34FE92: 4C8BA190000000                   mov     r12, [rcx+90h]
0x043067: 480FB6ED                         movzx   rbp, bpl
0x043147: 4D8B4128                         mov     r8, [r9+28h]
0x34FF64: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x34FFCF: 48BE594F86EB00000000             mov     rsi, 0EB864F59h
0x35003B: 4881C667238354                   add     rsi, 54832367h
0x043164: 488B36                           mov     rsi, [rsi]
0x3500A2: 4903B0A0000000                   add     rsi, [r8+0A0h]
0x04316E: 448A16                           mov     r10b, [rsi]
0x043171: 4D0FB6D2                         movzx   r10, r10b
0x043175: 49C1E238                         shl     r10, 38h
0x35010B: 4D2990D8000000                   sub     [r8+0D8h], r10
0x043180: 4D8B4128                         mov     r8, [r9+28h]
0x350177: 4D8BB0D8000000                   mov     r14, [r8+0D8h]
0x3501DF: 48BD963C201501000000             mov     rbp, 115203C96h
0x350248: 4881C52A2EE92A                   add     rbp, 2AE92E2Ah
0x043284: 4D8B4128                         mov     r8, [r9+28h]
0x043288: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x350319: 498BB890000000                   mov     rdi, [r8+90h]
0x35037E: 498BA8E8000000                   mov     rbp, [r8+0E8h]
0x043376: 498B4128                         mov     rax, [r9+28h]
0x35044F: 488B98A0000000                   mov     rbx, [rax+0A0h]
0x043381: 8B5034                           mov     edx, [rax+34h]
0x3504B8: 480390B0000000                   add     rdx, [rax+0B0h]
0x04338B: 448A12                           mov     r10b, [rdx]
0x350522: 49C7C6FF000000                   mov     r14, 0FFh
0x043395: 49C1E630                         shl     r14, 30h
0x043399: 49F7D6                           not     r14
0x04339C: 4C21F3                           and     rbx, r14
0x04339F: 4D0FB6F2                         movzx   r14, r10b
0x0433A3: 49C1E630                         shl     r14, 30h
0x0433A7: 4C09F3                           or      rbx, r14
0x04348C: 498B7128                         mov     rsi, [r9+28h]
0x3505F1: 4C8BA690000000                   mov     r12, [rsi+90h]
0x043497: 4154                             push    r12
0x043499: 4889E5                           mov     rbp, rsp
0x35065F: 488B9E90000000                   mov     rbx, [rsi+90h]
0x043584: 498B6928                         mov     rbp, [r9+28h]
0x35072D: 4C8BBDA0000000                   mov     r15, [rbp+0A0h]
0x350792: 488BB590000000                   mov     rsi, [rbp+90h]
0x043596: 4157                             push    r15
0x043598: 68162D8251                       push    51822D16h
0x04359D: 68887B8574                       push    74857B88h
0x0435A2: 688D2DEA3A                       push    3AEA2D8Dh
0x043692: 498B4128                         mov     rax, [r9+28h]
0x350869: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x3508D3: 4C8BB0A8000000                   mov     r14, [rax+0A8h]
0x0436A4: 4D0FB6ED                         movzx   r13, r13b
0x043784: 498B5928                         mov     rbx, [r9+28h]
0x3509A8: 0FAE93E0000000                   ldmxcsr dword ptr [rbx+0E0h]
0x350A11: 49BF4A16F0D700000000             mov     r15, 0D7F0164Ah
0x350A79: 4981C7765C1968                   add     r15, 68195C76h
0x0437A0: 4D8B7F68                         mov     r15, [r15+68h]
0x350AE3: 4C03BBE0000000                   add     r15, [rbx+0E0h]
0x0437AB: 418A0F                           mov     cl, [r15]
0x0437AE: 480FB6C9                         movzx   rcx, cl
0x0437B2: 48C1E108                         shl     rcx, 8
0x350B4E: 48298BE8000000                   sub     [rbx+0E8h], rcx
0x350BBC: 49BC5723A4E800000000             mov     r12, 0E8A42357h
0x0437C7: 4154                             push    r12
0x0437C9: 68B20F3919                       push    19390FB2h
0x0437CE: 68CE634413                       push    134463CEh
0x0437D3: 6835499444                       push    44944935h
0x0437D8: 6833132921                       push    21291333h
0x350C27: 488144242069476557               add     qword ptr [rsp+20h], 57654769h
0x0437E6: 4D8B5128                         mov     r10, [r9+28h]
0x350C8E: 4D8BBAE8000000                   mov     r15, [r10+0E8h]
0x0438D6: 498B4128                         mov     rax, [r9+28h]
0x0438DA: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x350D56: 4C8BA8A8000000                   mov     r13, [rax+0A8h]
0x350DBC: 488BB8F0000000                   mov     rdi, [rax+0F0h]
0x0439BC: 4D8B5128                         mov     r10, [r9+28h]
0x350E8A: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x0439C7: 418B6A34                         mov     ebp, [r10+34h]
0x350EF8: 4903AAE0000000                   add     rbp, [r10+0E0h]
0x0439D2: 408A6D00                         mov     bpl, [rbp+0]
0x0439D6: 4188EC                           mov     r12b, bpl
0x043ABB: 4D8B7928                         mov     r15, [r9+28h]
0x350FCB: 4D8BAFD8000000                   mov     r13, [r15+0D8h]
0x043AC6: 4155                             push    r13
0x043AC8: 4889E7                           mov     rdi, rsp
0x351038: 4D8BB7D8000000                   mov     r14, [r15+0D8h]
0x043BB0: 498B4128                         mov     rax, [r9+28h]
0x351105: 488BB0B0000000                   mov     rsi, [rax+0B0h]
0x35116A: 488BA8E8000000                   mov     rbp, [rax+0E8h]
0x043BC2: 56                               push    rsi
0x043BC3: 68881FFF5A                       push    5AFF1F88h
0x043BC8: 68397A1D6E                       push    6E1D7A39h
0x043BCD: 68680A9647                       push    47960A68h
0x043CB6: 498B7128                         mov     rsi, [r9+28h]
0x351239: 4C8BBEE8000000                   mov     r15, [rsi+0E8h]
0x35129E: 488B9EA0000000                   mov     rbx, [rsi+0A0h]
0x043CC8: 4D0FB6FF                         movzx   r15, r15b
0x043DAC: 498B7128                         mov     rsi, [r9+28h]
0x35136B: 0FAE96F0000000                   ldmxcsr dword ptr [rsi+0F0h]
0x3513D6: 49BF8338B62601000000             mov     r15, 126B63883h
0x35143E: 4981C73D3A5319                   add     r15, 19533A3Dh
0x3514A4: 4D8BBFF8010000                   mov     r15, [r15+1F8h]
0x35150D: 4C03BEF0000000                   add     r15, [rsi+0F0h]
0x043DD6: 458A1F                           mov     r11b, [r15]
0x043DD9: 4D0FB6DB                         movzx   r11, r11b
0x043DDD: 49C1E310                         shl     r11, 10h
0x351573: 4C299E90000000                   sub     [rsi+90h], r11
0x043DE8: 498B6928                         mov     rbp, [r9+28h]
0x3515D8: 4C8BAD90000000                   mov     r13, [rbp+90h]
0x351645: 48BD7FF65FCF00000000             mov     rbp, 0CF5FF67Fh
0x3516AE: 4881C54174A970                   add     rbp, 70A97441h
0x043EFB: 498B7128                         mov     rsi, [r9+28h]
0x043EFF: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x351783: 4C8BA680000000                   mov     r12, [rsi+80h]
0x3517EE: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x043FF0: 498B4128                         mov     rax, [r9+28h]
0x3518C6: 4C8BB8F0000000                   mov     r15, [rax+0F0h]
0x043FFB: 448B5034                         mov     r10d, [rax+34h]
0x351930: 4C0390D8000000                   add     r10, [rax+0D8h]
0x044006: 418A32                           mov     sil, [r10]
0x351995: 49C7C3FF000000                   mov     r11, 0FFh
0x044010: 49C1E308                         shl     r11, 8
0x044014: 49F7D3                           not     r11
0x044017: 4D21DF                           and     r15, r11
0x04401A: 4C0FB6DE                         movzx   r11, sil
0x04401E: 49C1E308                         shl     r11, 8
0x044022: 4D09DF                           or      r15, r11
0x044107: 4D8B5128                         mov     r10, [r9+28h]
0x351A66: 4D8B82F0000000                   mov     r8, [r10+0F0h]
0x044112: 4150                             push    r8
0x044114: 4889E6                           mov     rsi, rsp
0x351AD3: 4D8BAAF0000000                   mov     r13, [r10+0F0h]
0x04421D: 4D8B6128                         mov     r12, [r9+28h]
0x351BA4: 4D8BB424F0000000                 mov     r14, [r12+0F0h]
0x351C12: 498BAC24E0000000                 mov     rbp, [r12+0E0h]
0x044231: 4D0FB6F6                         movzx   r14, r14b
0x044315: 498B6928                         mov     rbp, [r9+28h]
0x351CE8: 0FAE95E8000000                   ldmxcsr dword ptr [rbp+0E8h]
0x351D4E: 49BC2C33CBDA00000000             mov     r12, 0DACB332Ch
0x351DBD: 4981C4943F3E65                   add     r12, 653E3F94h
0x351E23: 4D8BA424D0050000                 mov     r12, [r12+5D0h]
0x351E8C: 4C03A5E8000000                   add     r12, [rbp+0E8h]
0x044340: 458A3424                         mov     r14b, [r12]
0x044344: 4D0FB6F6                         movzx   r14, r14b
0x044348: 49C1E618                         shl     r14, 18h
0x351EF8: 4C29B5A0000000                   sub     [rbp+0A0h], r14
0x351F60: 48BD36FC932901000000             mov     rbp, 12993FC36h
0x04435D: 55                               push    rbp
0x04435E: 6842531A32                       push    321A5342h
0x044363: 68027D6B30                       push    306B7D02h
0x044368: 687F3A474D                       push    4D473A7Fh
0x351FCE: 48814424188A6E7516               add     [rsp-8+arg_18], 16756E8Ah
0x044376: 4D8B7928                         mov     r15, [r9+28h]
0x352039: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x044469: 4D8B4128                         mov     r8, [r9+28h]
0x04446D: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x352103: 4D8BA0D8000000                   mov     r12, [r8+0D8h]
0x35216F: 4D8BB0E8000000                   mov     r14, [r8+0E8h]
0x044565: 498B5128                         mov     rdx, [r9+28h]
0x352240: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x044570: 448B7A34                         mov     r15d, [rdx+34h]
0x3522AD: 4C03BAD8000000                   add     r15, [rdx+0D8h]
0x04457B: 458A1F                           mov     r11b, [r15]
0x352319: 48C7C0FF000000                   mov     rax, 0FFh
0x044585: 48C1E010                         shl     rax, 10h
0x044589: 48F7D0                           not     rax
0x04458C: 4921C4                           and     r12, rax
0x04458F: 490FB6C3                         movzx   rax, r11b
0x044593: 48C1E010                         shl     rax, 10h
0x044597: 4909C4                           or      r12, rax
0x044679: 4D8B7928                         mov     r15, [r9+28h]
0x3523E5: 4D8B87D8000000                   mov     r8, [r15+0D8h]
0x044684: 4150                             push    r8
0x044686: 4989E6                           mov     r14, rsp
0x35244C: 4D8BBFD8000000                   mov     r15, [r15+0D8h]
0x044768: 4D8B7128                         mov     r14, [r9+28h]
0x35251F: 498BAEE8000000                   mov     rbp, [r14+0E8h]
0x352584: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x04477A: 55                               push    rbp
0x04477B: 685F09E218                       push    18E2095Fh
0x044780: 68A600A243                       push    43A200A6h
0x044785: 684814387C                       push    7C381448h
0x044885: 498B7928                         mov     rdi, [r9+28h]
0x352657: 488BB788000000                   mov     rsi, [rdi+88h]
0x3526C2: 4C8BA7F0000000                   mov     r12, [rdi+0F0h]
0x044897: 480FB6F6                         movzx   rsi, sil
0x04497F: 498B5928                         mov     rbx, [r9+28h]
0x352794: 0FAE93A8000000                   ldmxcsr dword ptr [rbx+0A8h]
0x3527FC: 49BAD535D33E01000000             mov     r10, 13ED335D5h
0x352868: 4981C2EB3C3601                   add     r10, 1363CEBh
0x3528CE: 4D8B9298070000                   mov     r10, [r10+798h]
0x352939: 4C0393A8000000                   add     r10, [rbx+0A8h]
0x0449A9: 458A12                           mov     r10b, [r10]
0x0449AC: 4D0FB6D2                         movzx   r10, r10b
0x0449B0: 49C1E220                         shl     r10, 20h
0x3529A0: 4C2993D8000000                   sub     [rbx+0D8h], r10
0x0449BB: 498B5128                         mov     rdx, [r9+28h]
0x352A0B: 488B9AD8000000                   mov     rbx, [rdx+0D8h]
0x352A74: 48BF8A270A2601000000             mov     rdi, 1260A278Ah
0x352ADE: 4881C73643FF19                   add     rdi, 19FF4336h
0x044ABD: 4D8B7928                         mov     r15, [r9+28h]
0x044AC1: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x352BB3: 498BAFE8000000                   mov     rbp, [r15+0E8h]
0x352C21: 498BBF90000000                   mov     rdi, [r15+90h]
0x044BAB: 4D8B5928                         mov     r11, [r9+28h]
0x352CF4: 4D8BBBB0000000                   mov     r15, [r11+0B0h]
0x044BB6: 458B6B34                         mov     r13d, [r11+34h]
0x352D60: 4D03ABA0000000                   add     r13, [r11+0A0h]
0x044BC1: 418A4500                         mov     al, [r13+0]
0x352DCA: 48C7C5FF000000                   mov     rbp, 0FFh
0x044BCC: 48C1E518                         shl     rbp, 18h
0x044BD0: 48F7D5                           not     rbp
0x044BD3: 4921EF                           and     r15, rbp
0x044BD6: 480FB6E8                         movzx   rbp, al
0x044BDA: 48C1E518                         shl     rbp, 18h
0x044BDE: 4909EF                           or      r15, rbp
0x044CC5: 4D8B5128                         mov     r10, [r9+28h]
0x352E9D: 498B82F0000000                   mov     rax, [r10+0F0h]
0x044CD0: 50                               push    rax
0x044CD1: 4989E6                           mov     r14, rsp
0x352F08: 498BB2F0000000                   mov     rsi, [r10+0F0h]
0x044DC7: 4D8B5928                         mov     r11, [r9+28h]
0x352FDC: 4D8BAB88000000                   mov     r13, [r11+88h]
0x35304A: 498BABA8000000                   mov     rbp, [r11+0A8h]
0x044DD9: 4D0FB6ED                         movzx   r13, r13b
0x044ED3: 498B4928                         mov     rcx, [r9+28h]
0x353119: 0FAE91E0000000                   ldmxcsr dword ptr [rcx+0E0h]
0x353184: 49BCAA6ED53601000000             mov     r12, 136D56EAAh
0x3531EF: 4981C416043409                   add     r12, 9340416h
0x35325B: 4D8BA424E8070000                 mov     r12, [r12+7E8h]
0x3532C5: 4C03A1E0000000                   add     r12, [rcx+0E0h]
0x044EFE: 418A1C24                         mov     bl, [r12]
0x044F02: 480FB6DB                         movzx   rbx, bl
0x044F06: 48C1E328                         shl     rbx, 28h
0x353330: 482999A0000000                   sub     [rcx+0A0h], rbx
0x35339E: 49BEC14EDC2101000000             mov     r14, 121DC4EC1h
0x044F1B: 4156                             push    r14
0x044F1D: 683E0B695E                       push    5E690B3Eh
0x044F22: 6841766219                       push    19627641h
0x044F27: 68F653844C                       push    4C8453F6h
0x044F2C: 68B120DE63                       push    63DE20B1h
0x35340F: 4881442420FF1B2D1E               add     qword ptr [rsp+20h], 1E2D1BFFh
0x044F3A: 4D8B5928                         mov     r11, [r9+28h]
0x353477: 498BABA0000000                   mov     rbp, [r11+0A0h]
0x04502D: 4D8B5128                         mov     r10, [r9+28h]
0x045031: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x35354C: 4D8BAAF0000000                   mov     r13, [r10+0F0h]
0x3535B5: 4D8BA2A0000000                   mov     r12, [r10+0A0h]
0x04512E: 4D8B5128                         mov     r10, [r9+28h]
0x353684: 498B9AD8000000                   mov     rbx, [r10+0D8h]
0x045139: 458B5A34                         mov     r11d, [r10+34h]
0x3536EF: 4D039AE0000000                   add     r11, [r10+0E0h]
0x045144: 458A1B                           mov     r11b, [r11]
0x35375B: 48C7C6FF000000                   mov     rsi, 0FFh
0x04514E: 48C1E620                         shl     rsi, 20h
0x045152: 48F7D6                           not     rsi
0x045155: 4821F3                           and     rbx, rsi
0x045158: 490FB6F3                         movzx   rsi, r11b
0x04515C: 48C1E620                         shl     rsi, 20h
0x045160: 4809F3                           or      rbx, rsi
0x045251: 498B5928                         mov     rbx, [r9+28h]
0x35382C: 488B8390000000                   mov     rax, [rbx+90h]
0x04525C: 50                               push    rax
0x04525D: 4989E4                           mov     r12, rsp
0x353897: 488BBB90000000                   mov     rdi, [rbx+90h]
0x045349: 498B4128                         mov     rax, [r9+28h]
0x353966: 488BB0D8000000                   mov     rsi, [rax+0D8h]
0x3539D0: 488BB8B0000000                   mov     rdi, [rax+0B0h]
0x04535B: 56                               push    rsi
0x04535C: 68EB42D80F                       push    0FD842EBh
0x045361: 68377CD74D                       push    4DD77C37h
0x045366: 682F242D51                       push    512D242Fh
0x04536B: 68FC17E975                       push    75E917FCh
0x045460: 498B5128                         mov     rdx, [r9+28h]
0x353AA1: 488BB2D0000000                   mov     rsi, [rdx+0D0h]
0x353B07: 488BAAB0000000                   mov     rbp, [rdx+0B0h]
0x045472: 480FB6F6                         movzx   rsi, sil
0x04554B: 498B7128                         mov     rsi, [r9+28h]
0x353BDA: 0FAE96A8000000                   ldmxcsr dword ptr [rsi+0A8h]
0x353C3F: 48BB173A3BDC00000000             mov     rbx, 0DC3B3A17h
0x353CAC: 4881C3A938CE63                   add     rbx, 63CE38A9h
0x353D18: 488B9BF8070000                   mov     rbx, [rbx+7F8h]
0x353D83: 48039EA8000000                   add     rbx, [rsi+0A8h]
0x045575: 8A03                             mov     al, [rbx]
0x045577: 480FB6C0                         movzx   rax, al
0x04557B: 48C1E030                         shl     rax, 30h
0x353DE8: 482986A0000000                   sub     [rsi+0A0h], rax
0x353E53: 49BB904C57FF00000000             mov     r11, 0FF574C90h
0x045590: 4153                             push    r11
0x045592: 684B1DD95C                       push    5CD91D4Bh
0x045597: 681079F542                       push    42F57910h
0x04559C: 68193CE674                       push    74E63C19h
0x353EC4: 4881442418301EB240               add     [rsp-8+arg_18], 40B21E30h
0x0455AA: 4D8B4128                         mov     r8, [r9+28h]
0x353F2C: 498BB0A0000000                   mov     rsi, [r8+0A0h]
0x0456A8: 498B7128                         mov     rsi, [r9+28h]
0x0456AC: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x353FFF: 4C8BAEC8000000                   mov     r13, [rsi+0C8h]
0x35406B: 4C8BBEA8000000                   mov     r15, [rsi+0A8h]
0x0457A0: 4D8B4128                         mov     r8, [r9+28h]
0x354140: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x0457AB: 458B6834                         mov     r13d, [r8+34h]
0x3541AA: 4D03A8E0000000                   add     r13, [r8+0E0h]
0x0457B6: 418A6D00                         mov     bpl, [r13+0]
0x354214: 48C7C7FF000000                   mov     rdi, 0FFh
0x0457C1: 48C1E728                         shl     rdi, 28h
0x0457C5: 48F7D7                           not     rdi
0x0457C8: 4821FE                           and     rsi, rdi
0x0457CB: 480FB6FD                         movzx   rdi, bpl
0x0457CF: 48C1E728                         shl     rdi, 28h
0x0457D3: 4809FE                           or      rsi, rdi
0x0458BF: 498B6928                         mov     rbp, [r9+28h]
0x3542E6: 4C8B9DA8000000                   mov     r11, [rbp+0A8h]
0x0458CA: 4153                             push    r11
0x0458CC: 4989E5                           mov     r13, rsp
0x35434D: 488BADA8000000                   mov     rbp, [rbp+0A8h]
0x0459C0: 4D8B5128                         mov     r10, [r9+28h]
0x354415: 498BBA90000000                   mov     rdi, [r10+90h]
0x35447B: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x0459D2: 480FB6FF                         movzx   rdi, dil
0x045AC9: 4D8B7128                         mov     r14, [r9+28h]
0x354546: 410FAE96B0000000                 ldmxcsr dword ptr [r14+0B0h]
0x3545B3: 48BE1B12CED000000000             mov     rsi, 0D0CE121Bh
0x354624: 4881C6A5603B6F                   add     rsi, 6F3B60A5h
0x354690: 488BB6F8070000                   mov     rsi, [rsi+7F8h]
0x3546FD: 4903B6B0000000                   add     rsi, [r14+0B0h]
0x045AF4: 448A1E                           mov     r11b, [rsi]
0x045AF7: 4D0FB6DB                         movzx   r11, r11b
0x045AFB: 49C1E338                         shl     r11, 38h
0x354766: 4D299EE8000000                   sub     [r14+0E8h], r11
0x3547CF: 49BB3D39843401000000             mov     r11, 13484393Dh
0x045B10: 4153                             push    r11
0x045B12: 68FE318774                       push    748731FEh
0x045B17: 68BD509E3F                       push    3F9E50BDh
0x045B1C: 68A25B1134                       push    34115BA2h
0x35483A: 48814424188331850B               add     qword ptr [rsp+18h], 0B853183h
0x045B2A: 498B6928                         mov     rbp, [r9+28h]
0x3548AA: 4C8BBDE8000000                   mov     r15, [rbp+0E8h]
0x045C1C: 498B4928                         mov     rcx, [r9+28h]
0x045C20: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x35497E: 488BB1D8000000                   mov     rsi, [rcx+0D8h]
0x3549E4: 4C8BA9F0000000                   mov     r13, [rcx+0F0h]
0x045D1F: 498B7928                         mov     rdi, [r9+28h]
0x354AB4: 4C8BAFE0000000                   mov     r13, [rdi+0E0h]
0x045D2A: 448B6734                         mov     r12d, [rdi+34h]
0x354B1A: 4C03A7A8000000                   add     r12, [rdi+0A8h]
0x045D35: 458A1C24                         mov     r11b, [r12]
0x354B88: 49C7C4FF000000                   mov     r12, 0FFh
0x045D40: 49C1E430                         shl     r12, 30h
0x045D44: 49F7D4                           not     r12
0x045D47: 4D21E5                           and     r13, r12
0x045D4A: 4D0FB6E3                         movzx   r12, r11b
0x045D4E: 49C1E430                         shl     r12, 30h
0x045D52: 4D09E5                           or      r13, r12
0x045E3C: 4D8B6928                         mov     r13, [r9+28h]
0x354C5C: 4D8BBDE0000000                   mov     r15, [r13+0E0h]
0x045E47: 4157                             push    r15
0x045E49: 4989E4                           mov     r12, rsp
0x354CCA: 4D8BADE0000000                   mov     r13, [r13+0E0h]
0x045F51: 4D8B4128                         mov     r8, [r9+28h]
0x354D95: 498BB890000000                   mov     rdi, [r8+90h]
0x354E03: 4D8BB8E0000000                   mov     r15, [r8+0E0h]
0x045F63: 480FB6FF                         movzx   rdi, dil
0x046051: 498B5928                         mov     rbx, [r9+28h]
0x354ED6: 0FAE93B0000000                   ldmxcsr dword ptr [rbx+0B0h]
0x04605C: 498B4928                         mov     rcx, [r9+28h]
0x354F3F: 488BA9F0000000                   mov     rbp, [rcx+0F0h]
0x354FAC: 49BEC72668CB00000000             mov     r14, 0CB6826C7h
0x355018: 4981C6F943A174                   add     r14, 74A143F9h
0x04616B: 4D8B6928                         mov     r13, [r9+28h]
0x04616F: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x3550EB: 4D8BB5D0000000                   mov     r14, [r13+0D0h]
0x355151: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x04625B: 498B7928                         mov     rdi, [r9+28h]
0x355226: 4C8BBFA8000000                   mov     r15, [rdi+0A8h]
0x046266: 448B7734                         mov     r14d, [rdi+34h]
0x355291: 4C03B7E8000000                   add     r14, [rdi+0E8h]
0x046271: 418A0E                           mov     cl, [r14]
0x3552FF: 48C7C3FF000000                   mov     rbx, 0FFh
0x04627B: 48C1E338                         shl     rbx, 38h
0x04627F: 48F7D3                           not     rbx
0x046282: 4921DF                           and     r15, rbx
0x046285: 480FB6D9                         movzx   rbx, cl
0x046289: 48C1E338                         shl     rbx, 38h
0x04628D: 4909DF                           or      r15, rbx
0x046379: 4D8B7928                         mov     r15, [r9+28h]
0x3553C7: 4D8BAFF0000000                   mov     r13, [r15+0F0h]
0x046384: 4155                             push    r13
0x046386: 4989E6                           mov     r14, rsp
0x35542C: 4D8BBFF0000000                   mov     r15, [r15+0F0h]
0x04647B: 498B5928                         mov     rbx, [r9+28h]
0x3554FC: 4C8BB390000000                   mov     r14, [rbx+90h]
0x355565: 488BABF0000000                   mov     rbp, [rbx+0F0h]
0x04648D: 4D0FB6F6                         movzx   r14, r14b
0x04656A: 498B6928                         mov     rbp, [r9+28h]
0x35563B: 0FAE95E8000000                   ldmxcsr dword ptr [rbp+0E8h]
0x3556A2: 49B8A02B68F300000000             mov     r8, 0F3682BA0h
0x04657F: 4150                             push    r8
0x046581: 68F36A6C2E                       push    2E6C6AF3h
0x046586: 68E7673252                       push    523267E7h
0x04658B: 68C7279B1F                       push    1F9B27C7h
0x046590: 68A04D3B62                       push    623B4DA0h
0x35570F: 48814424202027A14C               add     qword ptr [rsp+20h], 4CA12720h
0x04659E: 4D8B5928                         mov     r11, [r9+28h]
0x355778: 4D8BABA0000000                   mov     r13, [r11+0A0h]
0x04668A: 4D8B6928                         mov     r13, [r9+28h]
0x04668E: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x355844: 498B9DD0000000                   mov     rbx, [r13+0D0h]
0x3558AD: 4D8BB5E0000000                   mov     r14, [r13+0E0h]
0x04678E: 498B4128                         mov     rax, [r9+28h]
0x355982: 488BB0E8000000                   mov     rsi, [rax+0E8h]
0x046799: 448B7834                         mov     r15d, [rax+34h]
0x3559E9: 4C03B890000000                   add     r15, [rax+90h]
0x0467A4: 458A3F                           mov     r15b, [r15]
0x355A50: 48C7C5FF000000                   mov     rbp, 0FFh
0x0467AE: 48C1E520                         shl     rbp, 20h
0x0467B2: 48F7D5                           not     rbp
0x0467B5: 4821EE                           and     rsi, rbp
0x0467B8: 490FB6EF                         movzx   rbp, r15b
0x0467BC: 48C1E520                         shl     rbp, 20h
0x0467C0: 4809EE                           or      rsi, rbp
0x0468A3: 498B4928                         mov     rcx, [r9+28h]
0x355B1C: 4C8BB9A8000000                   mov     r15, [rcx+0A8h]
0x0468AE: 4157                             push    r15
0x0468B0: 4989E6                           mov     r14, rsp
0x355B85: 4C8BA1A8000000                   mov     r12, [rcx+0A8h]
0x0469A9: 498B6928                         mov     rbp, [r9+28h]
0x355C56: 488BBDE8000000                   mov     rdi, [rbp+0E8h]
0x355CC3: 4C8BB5D8000000                   mov     r14, [rbp+0D8h]
0x0469BB: 57                               push    rdi
0x0469BC: 6856065D53                       push    535D0656h
0x0469C1: 688625BB5E                       push    5EBB2586h
0x0469C6: 68BD51C353                       push    53C351BDh
0x0469CB: 682A1C8C52                       push    528C1C2Ah
0x046AC2: 498B4928                         mov     rcx, [r9+28h]
0x355D97: 4C8BA9D0000000                   mov     r13, [rcx+0D0h]
0x355DFD: 488BA9E8000000                   mov     rbp, [rcx+0E8h]
0x046AD4: 4D0FB6ED                         movzx   r13, r13b
0x046BC3: 498B5928                         mov     rbx, [r9+28h]
0x355ED1: 0FAE93E0000000                   ldmxcsr dword ptr [rbx+0E0h]
0x046BCE: 4D8B5128                         mov     r10, [r9+28h]
0x355F38: 498BB2A0000000                   db  49h ; I
0x355F9D: 48BD0128272601000000             mov     rbp, 126272801h
0x35600A: 4881C5BF2AE219                   add     rbp, 19E22ABFh
0x046CD2: 4D8B4928                         mov     r9, [r9+28h]
0x046CD6: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x3560D9: 498BB1C8000000                   mov     rsi, [r9+0C8h]
0x356141: 498B99A8000000                   mov     rbx, [r9+0A8h]
0x046DCA: 498B4928                         mov     rcx, [r9+28h]
0x356215: 4C8BB190000000                   mov     r14, [rcx+90h]
0x046DD5: 448B5134                         mov     r10d, [rcx+34h]
0x35627D: 4C0391A8000000                   add     r10, [rcx+0A8h]
0x046DE0: 458A0A                           mov     r9b, [r10]
0x3562EB: 48C7C1FF000000                   mov     rcx, 0FFh
0x046DEA: 48C1E128                         shl     rcx, 28h
0x046DEE: 48F7D1                           not     rcx
0x046DF1: 4921CE                           and     r14, rcx
0x046DF4: 490FB6C9                         movzx   rcx, r9b
0x046DF8: 48C1E128                         shl     rcx, 28h
0x046DFC: 4909CE                           or      r14, rcx
0x046EE8: 4D8B7128                         mov     r14, [r9+28h]
0x3563BC: 498B86E8000000                   mov     rax, [r14+0E8h]
0x046EF3: 50                               push    rax
0x046EF4: 4889E7                           mov     rdi, rsp
0x356424: 4D8BAEE8000000                   mov     r13, [r14+0E8h]
0x046FD7: 498B5928                         mov     rbx, [r9+28h]
0x3564F4: 4C8BBBB0000000                   mov     r15, [rbx+0B0h]
0x35655D: 4C8BABE0000000                   mov     r13, [rbx+0E0h]
0x046FE9: 4157                             push    r15
0x046FEB: 687F2D5B63                       push    635B2D7Fh
0x046FF0: 6822092A0D                       push    0D2A0922h
0x046FF5: 68AE7E3C58                       push    583C7EAEh
0x046FFA: 68860BC35F                       push    5FC30B86h
0x0470EC: 4D8B6128                         mov     r12, [r9+28h]
0x35662B: 498BAC24D8000000                 mov     rbp, [r12+0D8h]
0x356694: 498B9C24E0000000                 mov     rbx, [r12+0E0h]
0x047100: 480FB6ED                         movzx   rbp, bpl
0x0471E4: 498B5928                         mov     rbx, [r9+28h]
0x356763: 0FAE93A0000000                   ldmxcsr dword ptr [rbx+0A0h]
0x0471EF: 4D8B5128                         mov     r10, [r9+28h]
0x3567CC: 4D8BBA90000000                   mov     r15, [r10+90h]
0x356839: 49BCAC000F2701000000             mov     r12, 1270F00ACh
0x3568A9: 4981C41452FA18                   add     r12, 18FA5214h
0x0472E6: 498B7128                         mov     rsi, [r9+28h]
0x0472EA: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x356979: 488BBED8000000                   mov     rdi, [rsi+0D8h]
0x3569E7: 488BB6F0000000                   mov     rsi, [rsi+0F0h]
0x0473E3: 498B5128                         mov     rdx, [r9+28h]
0x356AB6: 488B9AA8000000                   mov     rbx, [rdx+0A8h]
0x0473EE: 8B7A34                           mov     edi, [rdx+34h]
0x356B1B: 4803BAB0000000                   add     rdi, [rdx+0B0h]
0x0473F8: 448A0F                           mov     r9b, [rdi]
0x356B87: 48C7C6FF000000                   mov     rsi, 0FFh
0x047402: 48C1E630                         shl     rsi, 30h
0x047406: 48F7D6                           not     rsi
0x047409: 4821F3                           and     rbx, rsi
0x04740C: 490FB6F1                         movzx   rsi, r9b
0x047410: 48C1E630                         shl     rsi, 30h
0x047414: 4809F3                           or      rbx, rsi
0x0474FE: 498B7128                         mov     rsi, [r9+28h]
0x356C53: 4C8BA690000000                   mov     r12, [rsi+90h]
0x356CC1: 48BE18EF98C900000000             mov     rsi, 0C998EF18h
0x356D2E: 4881C6D8226776                   add     rsi, 766722D8h
0x04751A: 4D85E4                           test    r12, r12
0x356D96: 4C8D2D8E07CFFF                   lea     r13, unk_6A6752B
0x047524: 4C0F45EE                         cmovnz  r13, rsi
0x047528: 41FFE5                           jmp     r13
