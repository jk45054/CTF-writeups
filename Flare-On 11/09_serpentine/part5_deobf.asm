0x37981C: 48BA607874DA00000000             mov     rdx, 0DA747860h
0x05D3BF: 52                               push    rdx
0x05D3C0: 681406155D                       push    5D150614h
0x05D3C5: 6845388F36                       push    368F3845h
0x05D3CA: 68CD3AB064                       push    64B03ACDh
0x05D3CF: 689B31A921                       push    21A9319Bh
0x37988B: 488144242088401566               add     qword ptr [rsp+20h], 66154088h
0x05D4C5: 4D8B5928                         mov     r11, [r9+28h]
0x37995D: 4D8BB390000000                   mov     r14, [r11+90h]
0x05D4D0: 4D0FB6F6                         movzx   r14, r14b
0x05D5BE: 498B5128                         mov     rdx, [r9+28h]
0x379A33: 488B82E8000000                   mov     rax, [rdx+0E8h]
0x379AA1: 49C7C26400019B                   mov     r10, 0FFFFFFFF9B010064h
0x379B0A: 4981C2450B6365                   add     r10, 65630B45h
0x05D5D7: 4152                             push    r10
0x05D5D9: 48F72424                         mul     qword ptr [rsp]
0x05D5DD: 4989C6                           mov     r14, rax
0x05D6CA: 4D8B6128                         mov     r12, [r9+28h]
0x379BD8: 498BB424E8000000                 mov     rsi, [r12+0E8h]
0x05D6D6: 56                               push    rsi
0x05D6D7: 4889E5                           mov     rbp, rsp
0x379C47: 4D8BB424E8000000                 mov     r14, [r12+0E8h]
0x05D7B8: 4D8B7928                         mov     r15, [r9+28h]
0x379D18: 4D8BB7D8000000                   mov     r14, [r15+0D8h]
0x379D80: 4D8BBFE8000000                   mov     r15, [r15+0E8h]
0x05D7CA: 4D0FB6F6                         movzx   r14, r14b
0x05D8B8: 498B6928                         mov     rbp, [r9+28h]
0x379E4C: 0FAE95E8000000                   ldmxcsr dword ptr [rbp+0E8h]
0x379EB4: 48BFB834221201000000             mov     rdi, 1122234B8h
0x379F1D: 4881C7082EE72D                   add     rdi, 2DE72E08h
0x379F85: 488BBFE0020000                   mov     rdi, [rdi+2E0h]
0x379FEC: 4803BDE8000000                   add     rdi, [rbp+0E8h]
0x05D8E2: 448A27                           mov     r12b, [rdi]
0x05D8E5: 4D0FB6E4                         movzx   r12, r12b
0x05D8E9: 49C1E408                         shl     r12, 8
0x37A055: 4C01A5F0000000                   add     [rbp+0F0h], r12
0x37A0BF: 48B9DAE4ADCC00000000             mov     rcx, 0CCADE4DAh
0x05D8FE: 51                               push    rcx
0x05D8FF: 68EE431169                       push    691143EEh
0x05D904: 68FF1F6307                       push    7631FFFh
0x05D909: 681E6FE856                       push    56E86F1Eh
0x05D90E: 68F0265807                       push    75826F0h
0x37A127: 4881442420E6755B73               add     qword ptr [rsp+20h], 735B75E6h
0x05D91C: 498B7128                         mov     rsi, [r9+28h]
0x37A194: 4C8BB6F0000000                   mov     r14, [rsi+0F0h]
0x05DA12: 498B5928                         mov     rbx, [r9+28h]
0x05DA16: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x37A25E: 4C8BA3C0000000                   mov     r12, [rbx+0C0h]
0x37A2C7: 488B9BE8000000                   mov     rbx, [rbx+0E8h]
0x05DB09: 4D8B7128                         mov     r14, [r9+28h]
0x37A398: 4D8BBE90000000                   mov     r15, [r14+90h]
0x05DB14: 458B5E34                         mov     r11d, [r14+34h]
0x37A404: 4D039ED8000000                   add     r11, [r14+0D8h]
0x05DB1F: 458A0B                           mov     r9b, [r11]
0x05DB22: 4588CF                           mov     r15b, r9b
0x05DC13: 4D8B6128                         mov     r12, [r9+28h]
0x37A4DA: 498BBC24F0000000                 mov     rdi, [r12+0F0h]
0x05DC1F: 57                               push    rdi
0x05DC20: 4989E6                           mov     r14, rsp
0x37A541: 4D8BA424F0000000                 mov     r12, [r12+0F0h]
0x05DD18: 498B5928                         mov     rbx, [r9+28h]
0x37A614: 4C8BB380000000                   mov     r14, [rbx+80h]
0x37A682: 4C8BA3D8000000                   mov     r12, [rbx+0D8h]
0x05DD2A: 4D0FB6F6                         movzx   r14, r14b
0x05DE01: 4D8B6128                         mov     r12, [r9+28h]
0x37A757: 410FAE9424E8000000               ldmxcsr dword ptr [r12+0E8h]
0x37A7C4: 48BD5F16BBF000000000             mov     rbp, 0F0BB165Fh
0x37A82C: 4881C5614C4E4F                   add     rbp, 4F4E4C61h
0x37A897: 488BADD0030000                   mov     rbp, [rbp+3D0h]
0x37A905: 4903AC24E8000000                 add     rbp, [r12+0E8h]
0x05DE2E: 448A6D00                         mov     r13b, [rbp+0]
0x05DE32: 4D0FB6ED                         movzx   r13, r13b
0x05DE36: 49C1E510                         shl     r13, 10h
0x37A970: 4D01AC24D8000000                 add     [r12+0D8h], r13
0x05DE42: 4D8B5128                         mov     r10, [r9+28h]
0x37A9DD: 498BB2D8000000                   mov     rsi, [r10+0D8h]
0x37AA42: 49BDAC4ED33601000000             mov     r13, 136D34EACh
0x37AAB3: 4981C5140C3609                   add     r13, 9360C14h
0x05DF4B: 498B7128                         mov     rsi, [r9+28h]
0x05DF4F: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x37AB8A: 4C8BA680000000                   mov     r12, [rsi+80h]
0x37ABF0: 4C8BB6A8000000                   mov     r14, [rsi+0A8h]
0x05E04B: 498B7128                         mov     rsi, [r9+28h]
0x37ACC1: 4C8BA6E8000000                   mov     r12, [rsi+0E8h]
0x05E056: 8B7E34                           mov     edi, [rsi+34h]
0x37AD29: 4803BED8000000                   add     rdi, [rsi+0D8h]
0x05E060: 8A17                             mov     dl, [rdi]
0x37AD92: 49C7C6FF000000                   mov     r14, 0FFh
0x05E069: 49C1E608                         shl     r14, 8
0x05E06D: 49F7D6                           not     r14
0x05E070: 4D21F4                           and     r12, r14
0x05E073: 4C0FB6F2                         movzx   r14, dl
0x05E077: 49C1E608                         shl     r14, 8
0x05E07B: 4D09F4                           or      r12, r14
0x05E158: 498B5928                         mov     rbx, [r9+28h]
0x37AE5E: 488BBBD8000000                   mov     rdi, [rbx+0D8h]
0x05E163: 57                               push    rdi
0x05E164: 4889E5                           mov     rbp, rsp
0x37AEC6: 4C8BB3D8000000                   mov     r14, [rbx+0D8h]
0x05E254: 4D8B4128                         mov     r8, [r9+28h]
0x37AF95: 4D8BB8D8000000                   mov     r15, [r8+0D8h]
0x37B001: 4D8BA8E8000000                   mov     r13, [r8+0E8h]
0x05E266: 4D0FB6FF                         movzx   r15, r15b
0x05E354: 498B5928                         mov     rbx, [r9+28h]
0x37B0D7: 0FAE93F0000000                   ldmxcsr dword ptr [rbx+0F0h]
0x37B145: 48B93F0CF6F200000000             mov     rcx, 0F2F60C3Fh
0x37B1AD: 4881C18156134D                   add     rcx, 4D135681h
0x37B219: 488B8960030000                   mov     rcx, [rcx+360h]
0x37B286: 48038BF0000000                   add     rcx, [rbx+0F0h]
0x05E37E: 448A11                           mov     r10b, [rcx]
0x05E381: 4D0FB6D2                         movzx   r10, r10b
0x05E385: 49C1E218                         shl     r10, 18h
0x37B2EC: 4C0193E0000000                   add     [rbx+0E0h], r10
0x05E390: 4D8B6928                         mov     r13, [r9+28h]
0x37B357: 498BBDE0000000                   mov     rdi, [r13+0E0h]
0x37B3BD: 48BD331A2F3A01000000             mov     rbp, 13A2F1A33h
0x37B427: 4881C58D40DA05                   add     rbp, 5DA408Dh
0x05E496: 498B7928                         mov     rdi, [r9+28h]
0x05E49A: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x37B4FA: 488BB7C0000000                   mov     rsi, [rdi+0C0h]
0x37B562: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x05E588: 4D8B4128                         mov     r8, [r9+28h]
0x37B631: 498BB8A0000000                   mov     rdi, [r8+0A0h]
0x05E593: 418B4834                         mov     ecx, [r8+34h]
0x37B69B: 490388A8000000                   add     rcx, [r8+0A8h]
0x05E59E: 448A39                           mov     r15b, [rcx]
0x37B702: 48C7C3FF000000                   mov     rbx, 0FFh
0x05E5A8: 48C1E310                         shl     rbx, 10h
0x05E5AC: 48F7D3                           not     rbx
0x05E5AF: 4821DF                           and     rdi, rbx
0x05E5B2: 490FB6DF                         movzx   rbx, r15b
0x05E5B6: 48C1E310                         shl     rbx, 10h
0x05E5BA: 4809DF                           or      rdi, rbx
0x05E699: 4D8B4128                         mov     r8, [r9+28h]
0x37B7D9: 4D8BB0B0000000                   mov     r14, [r8+0B0h]
0x05E6A4: 4156                             push    r14
0x05E6A6: 4989E7                           mov     r15, rsp
0x37B842: 4D8BA0B0000000                   mov     r12, [r8+0B0h]
0x05E78B: 4D8B7928                         mov     r15, [r9+28h]
0x37B90E: 4D8B87F0000000                   mov     r8, [r15+0F0h]
0x37B979: 4D8BB7D8000000                   mov     r14, [r15+0D8h]
0x05E79D: 4150                             push    r8
0x05E79F: 684D52C01B                       push    1BC0524Dh
0x05E7A4: 689467C226                       push    26C26794h
0x05E7A9: 68AC6F3D76                       push    763D6FACh
0x05E7AE: 68D001E82E                       push    2EE801D0h
0x05E895: 4D8B4128                         mov     r8, [r9+28h]
0x37BA4D: 498BB8E0000000                   mov     rdi, [r8+0E0h]
0x37BAB7: 4D8BA8E8000000                   mov     r13, [r8+0E8h]
0x05E8A7: 480FB6FF                         movzx   rdi, dil
0x05E985: 498B6928                         mov     rbp, [r9+28h]
0x37BB87: 0FAE95B0000000                   ldmxcsr dword ptr [rbp+0B0h]
0x37BBF3: 48BF5D4CABFB00000000             mov     rdi, 0FBAB4C5Dh
0x37BC64: 4881C763165E44                   add     rdi, 445E1663h
0x37BCCF: 488BBF88020000                   mov     rdi, [rdi+288h]
0x37BD38: 4803BDB0000000                   add     rdi, [rbp+0B0h]
0x05E9AF: 448A1F                           mov     r11b, [rdi]
0x05E9B2: 4D0FB6DB                         movzx   r11, r11b
0x05E9B6: 49C1E320                         shl     r11, 20h
0x37BD9F: 4C019DE0000000                   add     [rbp+0E0h], r11
0x05E9C1: 4D8B6928                         mov     r13, [r9+28h]
0x37BE0B: 498BB5E0000000                   mov     rsi, [r13+0E0h]
0x37BE77: 48BBE93E6C1001000000             mov     rbx, 1106C3EE9h
0x37BEE8: 4881C3D71B9D2F                   add     rbx, 2F9D1BD7h
0x05EABE: 4D8B6928                         mov     r13, [r9+28h]
0x05EAC2: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x37BFBC: 498BB5B8000000                   mov     rsi, [r13+0B8h]
0x37C022: 498BBDA8000000                   mov     rdi, [r13+0A8h]
0x05EBA5: 4D8B5128                         mov     r10, [r9+28h]
0x37C0F4: 4D8BBAB0000000                   mov     r15, [r10+0B0h]
0x05EBB0: 418B6A34                         mov     ebp, [r10+34h]
0x37C160: 4903AAA8000000                   add     rbp, [r10+0A8h]
0x05EBBB: 408A7500                         mov     sil, [rbp+0]
0x37C1C6: 48C7C2FF000000                   mov     rdx, 0FFh
0x05EBC6: 48C1E218                         shl     rdx, 18h
0x05EBCA: 48F7D2                           not     rdx
0x05EBCD: 4921D7                           and     r15, rdx
0x05EBD0: 480FB6D6                         movzx   rdx, sil
0x05EBD4: 48C1E218                         shl     rdx, 18h
0x05EBD8: 4909D7                           or      r15, rdx
0x05ECC4: 498B4128                         mov     rax, [r9+28h]
0x37C29E: 488BA8F0000000                   mov     rbp, [rax+0F0h]
0x05ECCF: 55                               push    rbp
0x05ECD0: 4889E3                           mov     rbx, rsp
0x37C303: 4C8BA8F0000000                   mov     r13, [rax+0F0h]
0x05EDC2: 4D8B6128                         mov     r12, [r9+28h]
0x37C3CD: 498BAC2488000000                 mov     rbp, [r12+88h]
0x37C435: 4D8BAC24E0000000                 mov     r13, [r12+0E0h]
0x05EDD6: 480FB6ED                         movzx   rbp, bpl
0x05EEB4: 498B7928                         mov     rdi, [r9+28h]
0x37C503: 0FAE97A0000000                   ldmxcsr dword ptr [rdi+0A0h]
0x37C570: 48B85222B0D900000000             mov     rax, 0D9B02252h
0x37C5D8: 48056E405966                     add     rax, 6659406Eh
0x05EECF: 488B00                           mov     rax, [rax]
0x37C63E: 480387A0000000                   add     rax, [rdi+0A0h]
0x05EED9: 408A28                           mov     bpl, [rax]
0x05EEDC: 480FB6ED                         movzx   rbp, bpl
0x05EEE0: 48C1E528                         shl     rbp, 28h
0x37C6AB: 4801AFE0000000                   add     [rdi+0E0h], rbp
0x37C717: 49B88E4CA6C200000000             mov     r8, 0C2A64C8Eh
0x05EEF5: 4150                             push    r8
0x05EEF7: 68E313993A                       push    3A9913E3h
0x05EEFC: 6881049D36                       push    369D0481h
0x05EF01: 68FF52247F                       push    7F2452FFh
0x37C783: 4881442418320E637D               add     [rsp-8+arg_18], 7D630E32h
0x05EF0F: 4D8B4928                         mov     r9, [r9+28h]
0x37C7F1: 4D8BB1E0000000                   mov     r14, [r9+0E0h]
0x05EFFF: 498B5128                         mov     rdx, [r9+28h]
0x05F003: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x37C8C4: 4C8BAA88000000                   mov     r13, [rdx+88h]
0x37C932: 4C8BBAE8000000                   mov     r15, [rdx+0E8h]
0x05F0ED: 4D8B7928                         mov     r15, [r9+28h]
0x37CA01: 4D8BB7F0000000                   mov     r14, [r15+0F0h]
0x05F0F8: 458B6734                         mov     r12d, [r15+34h]
0x37CA6B: 4D03A7E0000000                   add     r12, [r15+0E0h]
0x05F103: 418A3424                         mov     sil, [r12]
0x37CAD3: 48C7C3FF000000                   mov     rbx, 0FFh
0x05F10E: 48C1E320                         shl     rbx, 20h
0x05F112: 48F7D3                           not     rbx
0x05F115: 4921DE                           and     r14, rbx
0x05F118: 480FB6DE                         movzx   rbx, sil
0x05F11C: 48C1E320                         shl     rbx, 20h
0x05F120: 4909DE                           or      r14, rbx
0x05F206: 498B5128                         mov     rdx, [r9+28h]
0x37CBA5: 4C8BB2E8000000                   mov     r14, [rdx+0E8h]
0x05F211: 4156                             push    r14
0x05F213: 4989E4                           mov     r12, rsp
0x37CC0C: 4C8BB2E8000000                   mov     r14, [rdx+0E8h]
0x05F2F8: 4D8B5928                         mov     r11, [r9+28h]
0x37CCDC: 4D8BA3D8000000                   mov     r12, [r11+0D8h]
0x37CD45: 498BABE8000000                   mov     rbp, [r11+0E8h]
0x05F30A: 4154                             push    r12
0x05F30C: 687332547D                       push    7D543273h
0x05F311: 68611BDA65                       push    65DA1B61h
0x05F316: 688476791A                       push    1A797684h
0x05F31B: 6810506528                       push    28655010h
0x05F412: 498B7928                         mov     rdi, [r9+28h]
0x37CE0E: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x37CE7C: 488BBFA0000000                   mov     rdi, [rdi+0A0h]
0x05F424: 480FB6ED                         movzx   rbp, bpl
0x05F506: 4D8B5928                         mov     r11, [r9+28h]
0x37CF4A: 410FAE93A0000000                 ldmxcsr dword ptr [r11+0A0h]
0x37CFB7: 49BAFEDC31CA00000000             mov     r10, 0CA31DCFEh
0x05F51C: 4152                             push    r10
0x05F51E: 68CF5FF056                       push    56F05FCFh
0x05F523: 685D0FD515                       push    15D50F5Dh
0x05F528: 68A2174D25                       push    254D17A2h
0x37D01F: 4881442418C27DD775               add     qword ptr [rsp+18h], 75D77DC2h
0x05F536: 498B5128                         mov     rdx, [r9+28h]
0x37D08D: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x05F617: 4D8B7128                         mov     r14, [r9+28h]
0x05F61B: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x37D15E: 4D8BAED0000000                   mov     r13, [r14+0D0h]
0x37D1CB: 498B9ED8000000                   mov     rbx, [r14+0D8h]
0x05F709: 4D8B6128                         mov     r12, [r9+28h]
0x37D29F: 498BB42490000000                 mov     rsi, [r12+90h]
0x05F715: 458B7C2434                       mov     r15d, [r12+34h]
0x37D30D: 4D03BC24E0000000                 add     r15, [r12+0E0h]
0x05F722: 458A3F                           mov     r15b, [r15]
0x37D37A: 48C7C7FF000000                   mov     rdi, 0FFh
0x05F72C: 48C1E738                         shl     rdi, 38h
0x05F730: 48F7D7                           not     rdi
0x05F733: 4821FE                           and     rsi, rdi
0x05F736: 490FB6FF                         movzx   rdi, r15b
0x05F73A: 48C1E738                         shl     rdi, 38h
0x05F73E: 4809FE                           or      rsi, rdi
0x37D44B: 48BB8E3BE72701000000             mov     rbx, 127E73B8Eh
0x05F81E: 53                               push    rbx
0x05F81F: 68226D8A7E                       push    7E8A6D22h
0x05F824: 68C7572035                       push    352057C7h
0x05F829: 68986D996F                       push    6F996D98h
0x37D4BC: 48814424185A7DA218               add     qword ptr [rsp+18h], 18A27D5Ah
0x05F837: 498B4128                         mov     rax, [r9+28h]
0x37D523: 4C8BA0A8000000                   mov     r12, [rax+0A8h]
0x05F91D: 498B7128                         mov     rsi, [r9+28h]
0x37D5F5: 488BAEA8000000                   mov     rbp, [rsi+0A8h]
0x37D65F: 488B9ED8000000                   mov     rbx, [rsi+0D8h]
0x05F92F: 480FB6ED                         movzx   rbp, bpl
0x05FA18: 4D8B7128                         mov     r14, [r9+28h]
0x37D733: 498B86A0000000                   mov     rax, [r14+0A0h]
0x37D7A1: 49C7C23EA0098C                   mov     r10, 0FFFFFFFF8C09A03Eh
0x37D80D: 4981C2A739E874                   add     r10, 74E839A7h
0x05FA31: 4152                             push    r10
0x37D877: 4D8BBE90000000                   mov     r15, [r14+90h]
0x05FA3A: 48F72424                         mul     qword ptr [rsp]
0x05FA3E: 4989C4                           mov     r12, rax
0x05FB34: 4D8B6128                         mov     r12, [r9+28h]
0x37D94A: 498BAC24F0000000                 mov     rbp, [r12+0F0h]
0x37D9B2: 492BAC24D8000000                 sub     rbp, [r12+0D8h]
0x05FC32: 4D8B7928                         mov     r15, [r9+28h]
0x37DA83: 4D8B97A0000000                   mov     r10, [r15+0A0h]
0x05FC3D: 4152                             push    r10
0x05FC3F: 4889E6                           mov     rsi, rsp
0x37DAEA: 4D8BBFA0000000                   mov     r15, [r15+0A0h]
0x05FD26: 498B4928                         mov     rcx, [r9+28h]
0x37DBC1: 4C8BB9B8000000                   mov     r15, [rcx+0B8h]
0x37DC2C: 4C8BB1F0000000                   mov     r14, [rcx+0F0h]
0x05FD38: 4D0FB6FF                         movzx   r15, r15b
0x05FE16: 498B7928                         mov     rdi, [r9+28h]
0x37DCF9: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x37DD62: 49BB0B1730D400000000             mov     r11, 0D430170Bh
0x37DDCF: 4981C3B54BD96B                   add     r11, 6BD94BB5h
0x37DE39: 4D8B9B58030000                   mov     r11, [r11+358h]
0x37DEA6: 4C039FF0000000                   add     r11, [rdi+0F0h]
0x05FE40: 418A1B                           mov     bl, [r11]
0x05FE43: 480FB6DB                         movzx   rbx, bl
0x05FE47: 48C1E308                         shl     rbx, 8
0x37DF12: 48019FE8000000                   add     [rdi+0E8h], rbx
0x05FE52: 4D8B4128                         mov     r8, [r9+28h]
0x37DF7F: 4D8BB0E8000000                   mov     r14, [r8+0E8h]
0x37DFE5: 48BD5642ACF200000000             mov     rbp, 0F2AC4256h
0x37E050: 4881C56A185D4D                   add     rbp, 4D5D186Ah
0x05FF67: 4D8B4928                         mov     r9, [r9+28h]
0x05FF6B: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x37E11F: 4D8BA9A8000000                   mov     r13, [r9+0A8h]
0x37E18A: 4D8BB1E8000000                   mov     r14, [r9+0E8h]
0x060067: 4D8B6928                         mov     r13, [r9+28h]
0x37E25B: 498BB5E8000000                   mov     rsi, [r13+0E8h]
0x060072: 418B4D34                         mov     ecx, [r13+34h]
0x37E2C3: 49038DE0000000                   add     rcx, [r13+0E0h]
0x06007D: 408A29                           mov     bpl, [rcx]
0x060080: 4088EE                           mov     sil, bpl
0x06016D: 498B7128                         mov     rsi, [r9+28h]
0x37E395: 4C8B96A8000000                   mov     r10, [rsi+0A8h]
0x060178: 4152                             push    r10
0x06017A: 4989E4                           mov     r12, rsp
0x37E403: 4C8BB6A8000000                   mov     r14, [rsi+0A8h]
0x060269: 498B7928                         mov     rdi, [r9+28h]
0x37E4CB: 4C8B8FD8000000                   mov     r9, [rdi+0D8h]
0x37E531: 4C8BBFE8000000                   mov     r15, [rdi+0E8h]
0x06027B: 4151                             push    r9
0x06027D: 688A6A5167                       push    67516A8Ah
0x060282: 6831176333                       push    33631731h
0x060287: 680B405008                       push    850400Bh
0x06037B: 4D8B4928                         mov     r9, [r9+28h]
0x37E608: 4D8BB9E8000000                   mov     r15, [r9+0E8h]
0x37E670: 498BA9F0000000                   mov     rbp, [r9+0F0h]
0x06038D: 4D0FB6FF                         movzx   r15, r15b
0x060474: 498B7928                         mov     rdi, [r9+28h]
0x37E747: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x37E7B0: 49BEC7FD40E200000000             mov     r14, 0E240FDC7h
0x37E821: 4981C6F964C85D                   add     r14, 5DC864F9h
0x37E887: 4D8BB668020000                   mov     r14, [r14+268h]
0x37E8ED: 4C03B7F0000000                   add     r14, [rdi+0F0h]
0x06049E: 418A2E                           mov     bpl, [r14]
0x0604A1: 480FB6ED                         movzx   rbp, bpl
0x0604A5: 48C1E510                         shl     rbp, 10h
0x37E954: 4801AFA0000000                   add     [rdi+0A0h], rbp
0x0604B0: 498B4128                         mov     rax, [r9+28h]
0x37E9BE: 4C8BA8A0000000                   mov     r13, [rax+0A0h]
0x37EA2A: 48BFF8282DFC00000000             mov     rdi, 0FC2D28F8h
0x37EA98: 4881C7C831DC43                   add     rdi, 43DC31C8h
0x0605AE: 498B5128                         mov     rdx, [r9+28h]
0x0605B2: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x37EB6C: 4C8BBAC0000000                   mov     r15, [rdx+0C0h]
0x37EBDA: 488BBAE0000000                   mov     rdi, [rdx+0E0h]
0x0606A3: 4D8B4928                         mov     r9, [r9+28h]
0x37ECAC: 498BA9B0000000                   mov     rbp, [r9+0B0h]
0x0606AE: 418B4934                         mov     ecx, [r9+34h]
0x37ED17: 490389F0000000                   add     rcx, [r9+0F0h]
0x0606B9: 448A19                           mov     r11b, [rcx]
0x37ED81: 48C7C0FF000000                   mov     rax, 0FFh
0x0606C3: 48C1E008                         shl     rax, 8
0x0606C7: 48F7D0                           not     rax
0x0606CA: 4821C5                           and     rbp, rax
0x0606CD: 490FB6C3                         movzx   rax, r11b
0x0606D1: 48C1E008                         shl     rax, 8
0x0606D5: 4809C5                           or      rbp, rax
0x0607B0: 4D8B5928                         mov     r11, [r9+28h]
0x37EE50: 498BB3A0000000                   mov     rsi, [r11+0A0h]
0x0607BB: 56                               push    rsi
0x0607BC: 4989E6                           mov     r14, rsp
0x37EEBB: 498BB3A0000000                   mov     rsi, [r11+0A0h]
0x0608A4: 498B7928                         mov     rdi, [r9+28h]
0x37EF8C: 488B8FE8000000                   mov     rcx, [rdi+0E8h]
0x37EFF3: 488BBFA8000000                   mov     rdi, [rdi+0A8h]
0x0608B6: 51                               push    rcx
0x0608B7: 68AF542225                       push    252254AFh
0x0608BC: 68C72C4F3A                       push    3A4F2CC7h
0x0608C1: 68FD351161                       push    611135FDh
0x0608C6: 68CD6D4B6F                       push    6F4B6DCDh
0x0609B0: 4D8B5128                         mov     r10, [r9+28h]
0x37F0C9: 4D8BBA88000000                   mov     r15, [r10+88h]
0x37F136: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x0609C2: 4D0FB6FF                         movzx   r15, r15b
0x060AA5: 498B7128                         mov     rsi, [r9+28h]
0x37F207: 0FAE96F0000000                   ldmxcsr dword ptr [rsi+0F0h]
0x37F275: 48BF875F5B2101000000             mov     rdi, 1215B5F87h
0x37F2DD: 4881C73903AE1E                   add     rdi, 1EAE0339h
0x37F349: 488BBF10020000                   mov     rdi, [rdi+210h]
0x37F3B1: 4803BEF0000000                   add     rdi, [rsi+0F0h]
0x060ACF: 8A17                             mov     dl, [rdi]
0x060AD1: 480FB6D2                         movzx   rdx, dl
0x060AD5: 48C1E218                         shl     rdx, 18h
0x37F41D: 480196D8000000                   add     [rsi+0D8h], rdx
0x37F48A: 49BCE14E7CD200000000             mov     r12, 0D27C4EE1h
0x060AEA: 4154                             push    r12
0x060AEC: 680204DA73                       push    73DA0402h
0x060AF1: 689D19A25B                       push    5BA2199Dh
0x060AF6: 681702DC75                       push    75DC0217h
0x060AFB: 682E282108                       push    821282Eh
0x37F4F3: 4881442420DF0B8D6D               add     qword ptr [rsp+20h], 6D8D0BDFh
0x060B09: 498B7928                         mov     rdi, [r9+28h]
0x37F55E: 488BBFD8000000                   mov     rdi, [rdi+0D8h]
0x060BFD: 498B7128                         mov     rsi, [r9+28h]
0x060C01: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x37F62E: 4C8BB6D0000000                   mov     r14, [rsi+0D0h]
0x37F69C: 488BAEB0000000                   mov     rbp, [rsi+0B0h]
0x060CEB: 4D8B6128                         mov     r12, [r9+28h]
0x37F767: 4D8BBC24A0000000                 mov     r15, [r12+0A0h]
0x060CF7: 458B4C2434                       mov     r9d, [r12+34h]
0x37F7D4: 4D038C24E8000000                 add     r9, [r12+0E8h]
0x060D04: 458A01                           mov     r8b, [r9]
0x37F843: 48C7C5FF000000                   mov     rbp, 0FFh
0x060D0E: 48C1E510                         shl     rbp, 10h
0x060D12: 48F7D5                           not     rbp
0x060D15: 4921EF                           and     r15, rbp
0x060D18: 490FB6E8                         movzx   rbp, r8b
0x060D1C: 48C1E510                         shl     rbp, 10h
0x060D20: 4909EF                           or      r15, rbp
0x060DFE: 4D8B7928                         mov     r15, [r9+28h]
0x37F917: 4D8BB7F0000000                   mov     r14, [r15+0F0h]
0x060E09: 4156                             push    r14
0x060E0B: 4889E6                           mov     rsi, rsp
0x37F981: 498BAFF0000000                   mov     rbp, [r15+0F0h]
0x060EFA: 4D8B5128                         mov     r10, [r9+28h]
0x37FA52: 498BBA88000000                   mov     rdi, [r10+88h]
0x37FAC0: 4D8BA2A0000000                   mov     r12, [r10+0A0h]
0x060F0C: 480FB6FF                         movzx   rdi, dil
0x060FEC: 4D8B5928                         mov     r11, [r9+28h]
0x37FB88: 410FAE93B0000000                 ldmxcsr dword ptr [r11+0B0h]
0x37FBF2: 48BB1BE4EA1001000000             mov     rbx, 110EAE41Bh
0x37FC5A: 4881C3A57E1E2F                   add     rbx, 2F1E7EA5h
0x37FCC5: 488B9B58040000                   mov     rbx, [rbx+458h]
0x37FD30: 49039BB0000000                   add     rbx, [r11+0B0h]
0x061017: 8A1B                             mov     bl, [rbx]
0x061019: 480FB6DB                         movzx   rbx, bl
0x06101D: 48C1E320                         shl     rbx, 20h
0x37FD9C: 49019BD8000000                   add     [r11+0D8h], rbx
0x37FE07: 48B9E2383C1301000000             mov     rcx, 1133C38E2h
0x061032: 51                               push    rcx
0x061033: 681106BD63                       push    63BD0611h
0x061038: 683E475F3C                       push    3C5F473Eh
0x06103D: 687D7E5312                       push    12537E7Dh
0x37FE71: 4881442418DE21CD2C               add     [rsp-8+arg_18], 2CCD21DEh
0x06104B: 4D8B6928                         mov     r13, [r9+28h]
0x37FEDD: 4D8BBDD8000000                   mov     r15, [r13+0D8h]
0x06113F: 498B5128                         mov     rdx, [r9+28h]
0x061143: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x37FFA6: 488BB2E0000000                   mov     rsi, [rdx+0E0h]
0x380011: 4C8BA2F0000000                   mov     r12, [rdx+0F0h]
0x061241: 498B4928                         mov     rcx, [r9+28h]
0x3800E1: 488BB1D8000000                   mov     rsi, [rcx+0D8h]
0x06124C: 448B7134                         mov     r14d, [rcx+34h]
0x380146: 4C03B1A8000000                   add     r14, [rcx+0A8h]
0x061257: 458A16                           mov     r10b, [r14]
0x3801AF: 48C7C0FF000000                   mov     rax, 0FFh
0x061261: 48C1E018                         shl     rax, 18h
0x061265: 48F7D0                           not     rax
0x061268: 4821C6                           and     rsi, rax
0x06126B: 490FB6C2                         movzx   rax, r10b
0x06126F: 48C1E018                         shl     rax, 18h
0x061273: 4809C6                           or      rsi, rax
0x061355: 4D8B6928                         mov     r13, [r9+28h]
0x380281: 4D8B9DA8000000                   mov     r11, [r13+0A8h]
0x061360: 4153                             push    r11
0x061362: 4889E5                           mov     rbp, rsp
0x3802EE: 498BBDA8000000                   mov     rdi, [r13+0A8h]
0x061455: 4D8B6928                         mov     r13, [r9+28h]
0x3803C3: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x38042D: 4D8BBDB0000000                   mov     r15, [r13+0B0h]
0x061467: 56                               push    rsi
0x061468: 68221F2856                       push    56281F22h
0x06146D: 686F638248                       push    4882636Fh
0x061472: 68C2460507                       push    70546C2h
0x061477: 682F10BB70                       push    70BB102Fh
0x06156D: 498B5128                         mov     rdx, [r9+28h]
0x3804FB: 488BAAD8000000                   mov     rbp, [rdx+0D8h]
0x380569: 4C8BB2F0000000                   mov     r14, [rdx+0F0h]
0x06157F: 480FB6ED                         movzx   rbp, bpl
0x061663: 4D8B7928                         mov     r15, [r9+28h]
0x380635: 410FAE97A0000000                 ldmxcsr dword ptr [r15+0A0h]
0x38069D: 49BA470E1BE600000000             mov     r10, 0E61B0E47h
0x38070D: 4981C27954EE59                   add     r10, 59EE5479h
0x061680: 4D8B12                           mov     r10, [r10]
0x380776: 4D0397A0000000                   add     r10, [r15+0A0h]
0x06168A: 418A0A                           mov     cl, [r10]
0x06168D: 480FB6C9                         movzx   rcx, cl
0x061691: 48C1E128                         shl     rcx, 28h
0x3807E1: 49018FE8000000                   add     [r15+0E8h], rcx
0x06169C: 4D8B6128                         mov     r12, [r9+28h]
0x380848: 4D8BAC24E8000000                 mov     r13, [r12+0E8h]
0x3808B3: 48BEBFF615D600000000             mov     rsi, 0D615F6BFh
0x380921: 4881C60164F369                   add     rsi, 69F36401h
0x061792: 4D8B6128                         mov     r12, [r9+28h]
0x3809F2: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x380A5B: 498BAC2480000000                 mov     rbp, [r12+80h]
0x380ACA: 498BB424E0000000                 mov     rsi, [r12+0E0h]
0x061881: 4D8B4128                         mov     r8, [r9+28h]
0x380B96: 498B98A8000000                   mov     rbx, [r8+0A8h]
0x06188C: 418B5034                         mov     edx, [r8+34h]
0x380BFC: 490390A0000000                   add     rdx, [r8+0A0h]
0x061897: 448A32                           mov     r14b, [rdx]
0x380C66: 48C7C6FF000000                   mov     rsi, 0FFh
0x0618A1: 48C1E620                         shl     rsi, 20h
0x0618A5: 48F7D6                           not     rsi
0x0618A8: 4821F3                           and     rbx, rsi
0x0618AB: 490FB6F6                         movzx   rsi, r14b
0x0618AF: 48C1E620                         shl     rsi, 20h
0x0618B3: 4809F3                           or      rbx, rsi
0x061988: 4D8B6928                         mov     r13, [r9+28h]
0x380D37: 498BB590000000                   mov     rsi, [r13+90h]
0x061993: 56                               push    rsi
0x061994: 4989E6                           mov     r14, rsp
0x380DA1: 4D8BA590000000                   mov     r12, [r13+90h]
0x061A72: 4D8B7928                         mov     r15, [r9+28h]
0x380E70: 4D8B9FE8000000                   mov     r11, [r15+0E8h]
0x380EDE: 4D8BB7D8000000                   mov     r14, [r15+0D8h]
0x061A84: 4153                             push    r11
0x061A86: 68DC719E3B                       push    3B9E71DCh
0x061A8B: 681737A02A                       push    2AA03717h
0x061A90: 68960DB21D                       push    1DB20D96h
0x061A95: 68C03D0011                       push    11003DC0h
0x061B87: 498B7928                         mov     rdi, [r9+28h]
0x380FAE: 4C8BAFB0000000                   mov     r13, [rdi+0B0h]
0x381018: 4C8BB7E8000000                   mov     r14, [rdi+0E8h]
0x061B99: 4D0FB6ED                         movzx   r13, r13b
0x061C8C: 498B6928                         mov     rbp, [r9+28h]
0x3810EC: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x38115A: 48BA580D20CB00000000             mov     rdx, 0CB200D58h
0x3811C2: 4881C26855E974                   add     rdx, 74E95568h
0x061CA8: 488B12                           mov     rdx, [rdx]
0x381230: 480395E0000000                   add     rdx, [rbp+0E0h]
0x061CB2: 448A22                           mov     r12b, [rdx]
0x061CB5: 4D0FB6E4                         movzx   r12, r12b
0x061CB9: 49C1E430                         shl     r12, 30h
0x38129A: 4C01A5E8000000                   add     [rbp+0E8h], r12
0x381302: 48BEE2074A3101000000             mov     rsi, 1314A07E2h
0x061CCE: 56                               push    rsi
0x061CCF: 68CD7D826E                       push    6E827DCDh
0x061CD4: 68F8304301                       push    14330F8h
0x061CD9: 680E099B08                       push    89B090Eh
0x061CDE: 6853346F67                       push    676F3453h
0x38136B: 4881442420DE52BF0E               add     qword ptr [rsp+20h], 0EBF52DEh
0x061CEC: 498B6928                         mov     rbp, [r9+28h]
0x3813DB: 4C8BB5E8000000                   mov     r14, [rbp+0E8h]
0x061DDC: 498B5928                         mov     rbx, [r9+28h]
0x061DE0: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x3814AE: 4C8BAB80000000                   mov     r13, [rbx+80h]
0x38151C: 488BABE8000000                   mov     rbp, [rbx+0E8h]
0x061EE3: 4D8B7928                         mov     r15, [r9+28h]
0x3815EF: 4D8BA7A0000000                   mov     r12, [r15+0A0h]
0x061EEE: 458B4F34                         mov     r9d, [r15+34h]
0x381659: 4D038FE0000000                   add     r9, [r15+0E0h]
0x061EF9: 458A19                           mov     r11b, [r9]
0x3816C5: 48C7C6FF000000                   mov     rsi, 0FFh
0x061F03: 48C1E628                         shl     rsi, 28h
0x061F07: 48F7D6                           not     rsi
0x061F0A: 4921F4                           and     r12, rsi
0x061F0D: 490FB6F3                         movzx   rsi, r11b
0x061F11: 48C1E628                         shl     rsi, 28h
0x061F15: 4909F4                           or      r12, rsi
0x381796: 48BA0B9C08F700000000             mov     rdx, 0F7089C0Bh
0x061FFC: 52                               push    rdx
0x061FFD: 68D856BC0C                       push    0CBC56D8h
0x062002: 68434A4449                       push    49444A43h
0x062007: 68F1658A41                       push    418A65F1h
0x06200C: 680470CE67                       push    67CE7004h
0x3817FF: 4881442420DD1C8149               add     qword ptr [rsp+20h], 49811CDDh
0x06201A: 4D8B4928                         mov     r9, [r9+28h]
0x381869: 4D8BA1D8000000                   mov     r12, [r9+0D8h]
0x06211E: 498B7928                         mov     rdi, [r9+28h]
0x38193A: 4C8BBFE0000000                   mov     r15, [rdi+0E0h]
0x38199F: 488BAFD8000000                   mov     rbp, [rdi+0D8h]
0x062130: 4D0FB6FF                         movzx   r15, r15b
0x06221C: 498B4928                         mov     rcx, [r9+28h]
0x381A6C: 488B81F0000000                   mov     rax, [rcx+0F0h]
0x381AD3: 49C7C49A9BE6B7                   mov     r12, 0FFFFFFFFB7E69B9Ah
0x381B3C: 4981C45E47ED48                   add     r12, 48ED475Eh
0x062235: 4154                             push    r12
0x381BA6: 488BA9A0000000                   mov     rbp, [rcx+0A0h]
0x06223E: 48F72424                         mul     qword ptr [rsp]
0x062242: 4889C3                           mov     rbx, rax
0x062332: 4D8B5928                         mov     r11, [r9+28h]
0x381C77: 4D8BABA0000000                   mov     r13, [r11+0A0h]
0x381CDF: 4D03AB90000000                   add     r13, [r11+90h]
0x062428: 4D8B6928                         mov     r13, [r9+28h]
0x381DAE: 4D8BB5E0000000                   mov     r14, [r13+0E0h]
0x062433: 4156                             push    r14
0x062435: 4889E6                           mov     rsi, rsp
0x381E19: 498B9DE0000000                   mov     rbx, [r13+0E0h]
0x062523: 498B7928                         mov     rdi, [r9+28h]
0x381EEF: 4C8BBFE0000000                   mov     r15, [rdi+0E0h]
0x381F5A: 488B9F90000000                   mov     rbx, [rdi+90h]
0x062535: 4D0FB6FF                         movzx   r15, r15b
0x06261B: 498B6928                         mov     rbp, [r9+28h]
0x38202D: 0FAE95F0000000                   ldmxcsr dword ptr [rbp+0F0h]
0x382092: 48BB1C2F07D600000000             mov     rbx, 0D6072F1Ch
0x382100: 4881C3A433026A                   add     rbx, 6A0233A4h
0x382167: 488B9BC0030000                   mov     rbx, [rbx+3C0h]
0x3821D4: 48039DF0000000                   add     rbx, [rbp+0F0h]
0x062645: 8A03                             mov     al, [rbx]
0x062647: 480FB6C0                         movzx   rax, al
0x06264B: 48C1E008                         shl     rax, 8
0x382240: 48018590000000                   add     [rbp+90h], rax
0x062656: 498B6928                         mov     rbp, [r9+28h]
0x3822AB: 488BBD90000000                   mov     rdi, [rbp+90h]
0x382313: 49BCBB30C7E900000000             mov     r12, 0E9C730BBh
0x382384: 4981C4052A4256                   add     r12, 56422A05h
0x06275C: 4D8B7128                         mov     r14, [r9+28h]
0x062760: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x382453: 4D8BBE80000000                   mov     r15, [r14+80h]
0x3824BB: 4D8BB6B0000000                   mov     r14, [r14+0B0h]
0x062854: 4D8B6928                         mov     r13, [r9+28h]
0x38258E: 498BBDE8000000                   mov     rdi, [r13+0E8h]
0x06285F: 458B5D34                         mov     r11d, [r13+34h]
0x3825F7: 4D039DF0000000                   add     r11, [r13+0F0h]
0x06286A: 458A1B                           mov     r11b, [r11]
0x06286D: 4488DF                           mov     dil, r11b
0x06294B: 4D8B5128                         mov     r10, [r9+28h]
0x3826C9: 498BBAB0000000                   mov     rdi, [r10+0B0h]
0x062956: 57                               push    rdi
0x062957: 4989E5                           mov     r13, rsp
0x382736: 498BBAB0000000                   mov     rdi, [r10+0B0h]
0x062A3C: 498B4128                         mov     rax, [r9+28h]
0x38280A: 4C8BA8E0000000                   mov     r13, [rax+0E0h]
0x382877: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x062A4E: 4155                             push    r13
0x062A50: 68D645D94D                       push    4DD945D6h
0x062A55: 6807188C7A                       push    7A8C1807h
0x062A5A: 68C518F311                       push    11F318C5h
0x062B53: 498B6928                         mov     rbp, [r9+28h]
0x382947: 4C8BBDA0000000                   mov     r15, [rbp+0A0h]
0x3829AD: 488B9DD8000000                   mov     rbx, [rbp+0D8h]
0x062B65: 4D0FB6FF                         movzx   r15, r15b
0x062C3A: 498B7928                         mov     rdi, [r9+28h]
0x382A84: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x382AF2: 49BC5111723701000000             mov     r12, 137721151h
0x382B5A: 4981C46F519708                   add     r12, 897516Fh
0x382BC5: 4D8BA424F0050000                 mov     r12, [r12+5F0h]
0x382C2B: 4C03A7F0000000                   add     r12, [rdi+0F0h]
0x062C65: 458A3C24                         mov     r15b, [r12]
0x062C69: 4D0FB6FF                         movzx   r15, r15b
0x062C6D: 49C1E710                         shl     r15, 10h
0x382C90: 4C01BF90000000                   add     [rdi+90h], r15
0x062C78: 4D8B7928                         mov     r15, [r9+28h]
0x382CFC: 498BAF90000000                   mov     rbp, [r15+90h]
0x382D68: 49BFC80B542A01000000             mov     r15, 12A540BC8h
0x382DD5: 4981C7F84EB515                   add     r15, 15B54EF8h
0x062D80: 498B4128                         mov     rax, [r9+28h]
0x062D84: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x382EAD: 488BB8F0000000                   mov     rdi, [rax+0F0h]
0x382F17: 4C8BB0A0000000                   mov     r14, [rax+0A0h]
0x062E7B: 4D8B4928                         mov     r9, [r9+28h]
0x382FE8: 498BB1E8000000                   mov     rsi, [r9+0E8h]
0x062E86: 458B5934                         mov     r11d, [r9+34h]
0x383056: 4D0399B0000000                   add     r11, [r9+0B0h]
0x062E91: 458A2B                           mov     r13b, [r11]
0x3830C1: 49C7C2FF000000                   mov     r10, 0FFh
0x062E9B: 49C1E208                         shl     r10, 8
0x062E9F: 49F7D2                           not     r10
0x062EA2: 4C21D6                           and     rsi, r10
0x062EA5: 4D0FB6D5                         movzx   r10, r13b
0x062EA9: 49C1E208                         shl     r10, 8
0x062EAD: 4C09D6                           or      rsi, r10
0x062F8E: 4D8B5928                         mov     r11, [r9+28h]
0x383191: 4D8B83A8000000                   mov     r8, [r11+0A8h]
0x062F99: 4150                             push    r8
0x062F9B: 4889E3                           mov     rbx, rsp
0x3831FB: 4D8BABA8000000                   mov     r13, [r11+0A8h]
0x063094: 498B6928                         mov     rbp, [r9+28h]
0x3832C5: 488BB5F0000000                   mov     rsi, [rbp+0F0h]
0x383333: 488BBDE0000000                   mov     rdi, [rbp+0E0h]
0x0630A6: 480FB6F6                         movzx   rsi, sil
0x06318B: 498B7928                         mov     rdi, [r9+28h]
0x3833FF: 0FAE97A8000000                   ldmxcsr dword ptr [rdi+0A8h]
0x383466: 49BFFA31A21D01000000             mov     r15, 11DA231FAh
0x3834D4: 4981C7C6306722                   add     r15, 226730C6h
0x0631A7: 4D8B7F10                         mov     r15, [r15+10h]
0x383540: 4C03BFA8000000                   add     r15, [rdi+0A8h]
0x0631B2: 458A27                           mov     r12b, [r15]
0x0631B5: 4D0FB6E4                         movzx   r12, r12b
0x0631B9: 49C1E418                         shl     r12, 18h
0x3835A5: 4C01A7B0000000                   add     [rdi+0B0h], r12
0x0631C4: 498B6928                         mov     rbp, [r9+28h]
0x383612: 4C8BBDB0000000                   mov     r15, [rbp+0B0h]
0x38367C: 49BE6326AEF700000000             mov     r14, 0F7AE2663h
0x3836E7: 4981C65D345B48                   add     r14, 485B345Dh
0x0632C0: 498B5128                         mov     rdx, [r9+28h]
0x0632C4: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x0632C8: 488B5A78                         mov     rbx, [rdx+78h]
0x3837BB: 4C8BB2F0000000                   mov     r14, [rdx+0F0h]
0x0633B0: 498B4928                         mov     rcx, [r9+28h]
0x38388F: 488BA9E8000000                   mov     rbp, [rcx+0E8h]
0x0633BB: 448B5934                         mov     r11d, [rcx+34h]
0x3838FD: 4C039990000000                   add     r11, [rcx+90h]
0x0633C6: 458A0B                           mov     r9b, [r11]
0x383964: 49C7C3FF000000                   mov     r11, 0FFh
0x0633D0: 49C1E310                         shl     r11, 10h
0x0633D4: 49F7D3                           not     r11
0x0633D7: 4C21DD                           and     rbp, r11
0x0633DA: 4D0FB6D9                         movzx   r11, r9b
0x0633DE: 49C1E310                         shl     r11, 10h
0x0633E2: 4C09DD                           or      rbp, r11
0x0634AE: 4D8B5128                         mov     r10, [r9+28h]
0x383A31: 498BBAA0000000                   mov     rdi, [r10+0A0h]
0x0634B9: 57                               push    rdi
0x0634BA: 4989E7                           mov     r15, rsp
0x383A9C: 4D8BA2A0000000                   mov     r12, [r10+0A0h]
0x0635A6: 498B5928                         mov     rbx, [r9+28h]
0x383B6C: 4C8BBBA8000000                   mov     r15, [rbx+0A8h]
0x383BD8: 4C8BB3D8000000                   mov     r14, [rbx+0D8h]
0x0635B8: 4D0FB6FF                         movzx   r15, r15b
0x063692: 498B4928                         mov     rcx, [r9+28h]
0x383CA5: 0FAE91F0000000                   ldmxcsr dword ptr [rcx+0F0h]
0x383D13: 49BE2918B5D600000000             mov     r14, 0D6B51829h
0x383D80: 4981C6974A5469                   add     r14, 69544A97h
0x383DEC: 4D8BB6C0010000                   mov     r14, [r14+1C0h]
0x383E55: 4C03B1F0000000                   add     r14, [rcx+0F0h]
0x0636BC: 418A16                           mov     dl, [r14]
0x0636BF: 480FB6D2                         movzx   rdx, dl
0x0636C3: 48C1E220                         shl     rdx, 20h
0x383EBB: 480191E8000000                   add     [rcx+0E8h], rdx
0x0636CE: 4D8B4128                         mov     r8, [r9+28h]
0x383F25: 4D8BA0E8000000                   mov     r12, [r8+0E8h]
0x383F8B: 49BF8BE4F51C01000000             mov     r15, 11CF5E48Bh
0x383FFA: 4981C735761323                   add     r15, 23137635h
0x0637D0: 498B6928                         mov     rbp, [r9+28h]
0x0637D4: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x3840CC: 4C8BADB8000000                   mov     r13, [rbp+0B8h]
0x384138: 4C8BA5D8000000                   mov     r12, [rbp+0D8h]
0x0638CB: 4D8B7928                         mov     r15, [r9+28h]
0x38420E: 4D8BA7D8000000                   mov     r12, [r15+0D8h]
0x0638D6: 418B4F34                         mov     ecx, [r15+34h]
0x384278: 49038FE0000000                   add     rcx, [r15+0E0h]
0x0638E1: 448A31                           mov     r14b, [rcx]
0x3842E4: 49C7C0FF000000                   mov     r8, 0FFh
0x0638EB: 49C1E018                         shl     r8, 18h
0x0638EF: 49F7D0                           not     r8
0x0638F2: 4D21C4                           and     r12, r8
0x0638F5: 4D0FB6C6                         movzx   r8, r14b
0x0638F9: 49C1E018                         shl     r8, 18h
0x0638FD: 4D09C4                           or      r12, r8
0x0639E7: 498B4128                         mov     rax, [r9+28h]
0x3843B5: 488BB0D8000000                   mov     rsi, [rax+0D8h]
0x0639F2: 56                               push    rsi
0x0639F3: 4989E6                           mov     r14, rsp
0x38441B: 488BA8D8000000                   mov     rbp, [rax+0D8h]
0x063AE4: 4D8B4128                         mov     r8, [r9+28h]
0x3844EA: 498B98E8000000                   mov     rbx, [r8+0E8h]
0x384553: 498BA8A0000000                   mov     rbp, [r8+0A0h]
0x063AF6: 480FB6DB                         movzx   rbx, bl
0x063BC9: 4D8B7128                         mov     r14, [r9+28h]
0x384628: 410FAE9690000000                 ldmxcsr dword ptr [r14+90h]
0x063BD5: 498B6928                         mov     rbp, [r9+28h]
0x384694: 488B9DA0000000                   mov     rbx, [rbp+0A0h]
0x3846FB: 48BD4A0928FE00000000             mov     rbp, 0FE28094Ah
0x384764: 4881C57651E141                   add     rbp, 41E15176h
0x063CDD: 498B4928                         mov     rcx, [r9+28h]
0x063CE1: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x38483B: 4C8BA9A8000000                   mov     r13, [rcx+0A8h]
0x3848A2: 488BB990000000                   mov     rdi, [rcx+90h]
0x063DC0: 498B5928                         mov     rbx, [r9+28h]
0x38496E: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x063DCB: 448B7B34                         mov     r15d, [rbx+34h]
0x3849DA: 4C03BBE0000000                   add     r15, [rbx+0E0h]
0x063DD6: 418A2F                           mov     bpl, [r15]
0x384A3F: 48C7C3FF000000                   mov     rbx, 0FFh
0x063DE0: 48C1E338                         shl     rbx, 38h
0x063DE4: 48F7D3                           not     rbx
0x063DE7: 4821DF                           and     rdi, rbx
0x063DEA: 480FB6DD                         movzx   rbx, bpl
0x063DEE: 48C1E338                         shl     rbx, 38h
0x063DF2: 4809DF                           or      rdi, rbx
0x063EE5: 4D8B6128                         mov     r12, [r9+28h]
0x384B0E: 4D8BAC24B0000000                 mov     r13, [r12+0B0h]
0x384B7A: 48BDFA78FAF700000000             mov     rbp, 0F7FA78FAh
0x384BEA: 4881C5EE3F8F48                   add     rbp, 488F3FEEh
0x063FE8: 498B4128                         mov     rax, [r9+28h]
0x384CBA: 4C8BA8D0000000                   mov     r13, [rax+0D0h]
0x384D22: 4C8BA0E0000000                   mov     r12, [rax+0E0h]
0x063FFA: 4D0FB6ED                         movzx   r13, r13b
0x0640EF: 4D8B5928                         mov     r11, [r9+28h]
0x384DF2: 498B83E0000000                   mov     rax, [r11+0E0h]
0x384E60: 49C7C5000CCCCF                   mov     r13, 0FFFFFFFFCFCC0C00h
0x384ECB: 4981C5CE4CE930                   add     r13, 30E94CCEh
0x064108: 4155                             push    r13
0x384F31: 498BABD8000000                   mov     rbp, [r11+0D8h]
0x064111: 48F72424                         mul     qword ptr [rsp]
0x064115: 4889C7                           mov     rdi, rax
0x0641EA: 4D8B7928                         mov     r15, [r9+28h]
0x384FFF: 498BBFA0000000                   mov     rdi, [r15+0A0h]
0x385064: 4903BFB0000000                   add     rdi, [r15+0B0h]
0x0642EE: 4D8B6928                         mov     r13, [r9+28h]
0x385139: 498B8DB0000000                   mov     rcx, [r13+0B0h]
0x0642F9: 51                               push    rcx
0x0642FA: 4989E4                           mov     r12, rsp
0x3851A3: 498B9DB0000000                   mov     rbx, [r13+0B0h]
0x0643D4: 498B5928                         mov     rbx, [r9+28h]
0x385273: 4C8B9BD8000000                   mov     r11, [rbx+0D8h]
0x3852DB: 4C8BB390000000                   mov     r14, [rbx+90h]
0x0643E6: 4153                             push    r11
0x0643E8: 68604F6354                       push    54634F60h
0x0643ED: 681104147C                       push    7C140411h
0x0643F2: 6859754B42                       push    424B7559h
0x0643F7: 68CE53AA19                       push    19AA53CEh
0x0644E9: 498B5128                         mov     rdx, [r9+28h]
0x3853AC: 4C8BB2A8000000                   mov     r14, [rdx+0A8h]
0x385414: 4C8BBAE8000000                   mov     r15, [rdx+0E8h]
0x0644FB: 4D0FB6F6                         movzx   r14, r14b
0x0645E5: 4D8B4128                         mov     r8, [r9+28h]
0x3854E6: 410FAE90E8000000                 ldmxcsr dword ptr [r8+0E8h]
0x385554: 49BDE36BE3F200000000             mov     r13, 0F2E36BE3h
0x3855C3: 4981C5DD06264D                   add     r13, 4D2606DDh
0x385628: 4D8BAD70040000                   mov     r13, [r13+470h]
0x385696: 4D03A8E8000000                   add     r13, [r8+0E8h]
0x064610: 418A4500                         mov     al, [r13+0]
0x064614: 480FB6C0                         movzx   rax, al
0x064618: 48C1E008                         shl     rax, 8
0x3856FB: 492980F0000000                   sub     [r8+0F0h], rax
0x064623: 4D8B7928                         mov     r15, [r9+28h]
0x385763: 498B9FF0000000                   mov     rbx, [r15+0F0h]
0x3857D0: 48BF6C54B02A01000000             mov     rdi, 12AB0546Ch
0x385841: 4881C754165915                   add     rdi, 15591654h
0x06472E: 4D8B4128                         mov     r8, [r9+28h]
0x064732: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x385913: 498BB088000000                   mov     rsi, [r8+88h]
0x38597E: 498B9890000000                   mov     rbx, [r8+90h]
0x06481F: 4D8B4928                         mov     r9, [r9+28h]
0x385A4F: 4D8BA990000000                   mov     r13, [r9+90h]
0x06482A: 458B5134                         mov     r10d, [r9+34h]
0x385ABB: 4D0391A8000000                   add     r10, [r9+0A8h]
0x064835: 458A32                           mov     r14b, [r10]
0x064838: 4588F5                           mov     r13b, r14b
0x064914: 4D8B5128                         mov     r10, [r9+28h]
0x385B86: 4D8BAAE0000000                   mov     r13, [r10+0E0h]
0x06491F: 4155                             push    r13
0x064921: 4889E5                           mov     rbp, rsp
0x385BF4: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x064A21: 4D8B4928                         mov     r9, [r9+28h]
0x385CC0: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x385D27: 4D8BB190000000                   mov     r14, [r9+90h]
0x064A33: 480FB6DB                         movzx   rbx, bl
0x064B30: 4D8B5128                         mov     r10, [r9+28h]
0x385DFF: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x385E6E: 48BFE15AABCE00000000             mov     rdi, 0CEAB5AE1h
0x385EDD: 4881C7DF175E71                   add     rdi, 715E17DFh
0x385F46: 488BBF60040000                   mov     rdi, [rdi+460h]
0x385FB2: 4903BA90000000                   add     rdi, [r10+90h]
0x064B5B: 408A3F                           mov     dil, [rdi]
0x064B5E: 480FB6FF                         movzx   rdi, dil
0x064B62: 48C1E710                         shl     rdi, 10h
0x38601A: 4929BAE8000000                   sub     [r10+0E8h], rdi
0x064B6D: 4D8B7928                         mov     r15, [r9+28h]
0x386085: 498B9FE8000000                   mov     rbx, [r15+0E8h]
0x3860EE: 49BE1D528BF600000000             mov     r14, 0F68B521Dh
0x386159: 4981C6A3187E49                   add     r14, 497E18A3h
0x064C71: 498B7128                         mov     rsi, [r9+28h]
0x064C75: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x38622E: 4C8BBED8000000                   mov     r15, [rsi+0D8h]
0x386294: 488B9E90000000                   mov     rbx, [rsi+90h]
0x064D66: 498B7128                         mov     rsi, [r9+28h]
0x386368: 4C8BBE90000000                   mov     r15, [rsi+90h]
0x064D71: 448B5634                         mov     r10d, [rsi+34h]
0x3863D1: 4C0396F0000000                   add     r10, [rsi+0F0h]
0x064D7C: 418A12                           mov     dl, [r10]
0x38643D: 48C7C5FF000000                   mov     rbp, 0FFh
0x064D86: 48C1E508                         shl     rbp, 8
0x064D8A: 48F7D5                           not     rbp
0x064D8D: 4921EF                           and     r15, rbp
0x064D90: 480FB6EA                         movzx   rbp, dl
0x064D94: 48C1E508                         shl     rbp, 8
0x064D98: 4909EF                           or      r15, rbp
0x064E6F: 4D8B7128                         mov     r14, [r9+28h]
0x38650F: 498BB6F0000000                   mov     rsi, [r14+0F0h]
0x064E7A: 56                               push    rsi
0x064E7B: 4989E7                           mov     r15, rsp
0x386574: 498BAEF0000000                   mov     rbp, [r14+0F0h]
0x064F74: 4D8B5128                         mov     r10, [r9+28h]
0x386644: 498B82F0000000                   mov     rax, [r10+0F0h]
0x3866A9: 498BB2A0000000                   mov     rsi, [r10+0A0h]
0x064F86: 50                               push    rax
0x064F87: 6827729306                       push    6937227h
0x064F8C: 68D6422651                       push    512642D6h
0x064F91: 68E00DE54D                       push    4DE50DE0h
0x065097: 4D8B7128                         mov     r14, [r9+28h]
0x386779: 498BB6F0000000                   mov     rsi, [r14+0F0h]
0x3867E5: 4D8BAEA8000000                   mov     r13, [r14+0A8h]
0x0650A9: 480FB6F6                         movzx   rsi, sil
0x065194: 4D8B5128                         mov     r10, [r9+28h]
0x3868B5: 410FAE92A8000000                 ldmxcsr dword ptr [r10+0A8h]
0x38691C: 49BFB241243E01000000             mov     r15, 13E2441B2h
0x38698D: 4981C70E31E501                   add     r15, 1E5310Eh
0x3869FB: 4D8BBF08020000                   mov     r15, [r15+208h]
0x386A64: 4D03BAA8000000                   add     r15, [r10+0A8h]
0x0651BF: 418A07                           mov     al, [r15]
0x0651C2: 480FB6C0                         movzx   rax, al
0x0651C6: 48C1E018                         shl     rax, 18h
0x386AD2: 492982E0000000                   sub     [r10+0E0h], rax
0x386B3F: 48BFED14B31701000000             mov     rdi, 117B314EDh
0x0651DB: 57                               push    rdi
0x0651DC: 68A4432677                       push    772643A4h
0x0651E1: 688D52030C                       push    0C03528Dh
0x0651E6: 6852344056                       push    56403452h
0x386BB0: 4881442418D3555628               add     qword ptr [rsp+18h], 285655D3h
0x0651F4: 498B7928                         mov     rdi, [r9+28h]
0x386C19: 4C8BB7E0000000                   mov     r14, [rdi+0E0h]
0x0652F3: 4D8B5128                         mov     r10, [r9+28h]
0x0652F7: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x386CF1: 4D8BAA88000000                   mov     r13, [r10+88h]
0x386D5F: 498BB2E8000000                   mov     rsi, [r10+0E8h]
0x0653FD: 4D8B4128                         mov     r8, [r9+28h]
0x386E2D: 4D8BB0A8000000                   mov     r14, [r8+0A8h]
0x065408: 458B7834                         mov     r15d, [r8+34h]
0x386E9A: 4D03B8E0000000                   add     r15, [r8+0E0h]
0x065413: 458A3F                           mov     r15b, [r15]
0x386F02: 49C7C1FF000000                   mov     r9, 0FFh
0x06541D: 49C1E110                         shl     r9, 10h
0x065421: 49F7D1                           not     r9
0x065424: 4D21CE                           and     r14, r9
0x065427: 4D0FB6CF                         movzx   r9, r15b
0x06542B: 49C1E110                         shl     r9, 10h
0x06542F: 4D09CE                           or      r14, r9
0x065517: 498B4128                         mov     rax, [r9+28h]
0x386FD2: 4C8B80E8000000                   mov     r8, [rax+0E8h]
0x065522: 4150                             push    r8
0x065524: 4889E6                           mov     rsi, rsp
0x387037: 488B98E8000000                   mov     rbx, [rax+0E8h]
0x065606: 4D8B6928                         mov     r13, [r9+28h]
0x387107: 498B85A8000000                   mov     rax, [r13+0A8h]
0x38716E: 4D8BB590000000                   mov     r14, [r13+90h]
0x065618: 50                               push    rax
0x065619: 68D2032D72                       push    722D03D2h
0x06561E: 686257E121                       push    21E15762h
0x065623: 683A731F4F                       push    4F1F733Ah
0x06570D: 498B7928                         mov     rdi, [r9+28h]
0x065711: 4C8B6F78                         mov     r13, [rdi+78h]
0x38723B: 4C8BB7E8000000                   mov     r14, [rdi+0E8h]
0x06571C: 4D0FB6ED                         movzx   r13, r13b
0x0657F2: 498B4128                         mov     rax, [r9+28h]
0x38730B: 0FAE90E0000000                   ldmxcsr dword ptr [rax+0E0h]
0x387374: 48B9C708FF2001000000             mov     rcx, 120FF08C7h
0x3873E5: 4881C1F9690A1F                   add     rcx, 1F0A69F9h
0x38744E: 488B8998010000                   mov     rcx, [rcx+198h]
0x3874B4: 480388E0000000                   add     rcx, [rax+0E0h]
0x06581C: 8A09                             mov     cl, [rcx]
0x06581E: 480FB6C9                         movzx   rcx, cl
0x065822: 48C1E120                         shl     rcx, 20h
0x38751E: 482988E8000000                   sub     [rax+0E8h], rcx
0x06582D: 4D8B7928                         mov     r15, [r9+28h]
0x38758A: 498BAFE8000000                   mov     rbp, [r15+0E8h]
0x3875F7: 49BE1AF41C0A01000000             mov     r14, 10A1CF41Ah
0x387663: 4981C6A676EC35                   add     r14, 35EC76A6h
0x065945: 4D8B6128                         mov     r12, [r9+28h]
0x387734: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x38779D: 498BBC24D0000000                 mov     rdi, [r12+0D0h]
0x387806: 4D8BB424A0000000                 mov     r14, [r12+0A0h]
0x065A3A: 498B5128                         mov     rdx, [r9+28h]
0x3878DB: 4C8BB2E8000000                   mov     r14, [rdx+0E8h]
0x065A45: 448B6234                         mov     r12d, [rdx+34h]
0x387942: 4C03A2B0000000                   add     r12, [rdx+0B0h]
0x065A50: 458A2C24                         mov     r13b, [r12]
0x3879AE: 49C7C1FF000000                   mov     r9, 0FFh
0x065A5B: 49C1E118                         shl     r9, 18h
0x065A5F: 49F7D1                           not     r9
0x065A62: 4D21CE                           and     r14, r9
0x065A65: 4D0FB6CD                         movzx   r9, r13b
0x065A69: 49C1E118                         shl     r9, 18h
0x065A6D: 4D09CE                           or      r14, r9
0x065B4A: 498B5928                         mov     rbx, [r9+28h]
0x387A79: 488BBBE8000000                   mov     rdi, [rbx+0E8h]
0x065B55: 57                               push    rdi
0x065B56: 4989E5                           mov     r13, rsp
0x387AE3: 488BB3E8000000                   mov     rsi, [rbx+0E8h]
0x065C43: 4D8B7128                         mov     r14, [r9+28h]
0x387BB2: 498B96E0000000                   mov     rdx, [r14+0E0h]
0x387C19: 4D8BB6A8000000                   mov     r14, [r14+0A8h]
0x065C55: 52                               push    rdx
0x065C56: 68275F6522                       push    22655F27h
0x065C5B: 68CE305505                       push    55530CEh
0x065C60: 68E82F6B01                       push    16B2FE8h
0x065C65: 6885554867                       push    67485585h
0x065D53: 498B5128                         mov     rdx, [r9+28h]
0x387CE8: 488B9AB0000000                   mov     rbx, [rdx+0B0h]
0x387D53: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x065D65: 480FB6DB                         movzx   rbx, bl
0x065E43: 498B5928                         mov     rbx, [r9+28h]
0x387E27: 0FAE9390000000                   ldmxcsr dword ptr [rbx+90h]
0x387E92: 48BE4A52173901000000             mov     rsi, 13917524Ah
0x387F02: 4881C67620F206                   add     rsi, 6F22076h
0x065E5F: 488B36                           mov     rsi, [rsi]
0x387F67: 4803B390000000                   add     rsi, [rbx+90h]
0x065E69: 408A3E                           mov     dil, [rsi]
0x065E6C: 480FB6FF                         movzx   rdi, dil
0x065E70: 48C1E728                         shl     rdi, 28h
0x387FD1: 4829BBD8000000                   sub     [rbx+0D8h], rdi
0x38803B: 49B8CB25A82C01000000             mov     r8, 12CA825CBh
0x065E85: 4150                             push    r8
0x065E87: 686411BB78                       push    78BB1164h
0x065E8C: 680707DC15                       push    15DC0707h
0x065E91: 681E684631                       push    3146681Eh
0x3880A3: 4881442418F5446113               add     [rsp-8+arg_18], 136144F5h
0x065E9F: 4D8B5128                         mov     r10, [r9+28h]
0x38810B: 4D8BA2D8000000                   mov     r12, [r10+0D8h]
0x065F96: 498B6928                         mov     rbp, [r9+28h]
0x065F9A: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x3881D6: 488BB580000000                   mov     rsi, [rbp+80h]
0x38823B: 4C8BADD8000000                   mov     r13, [rbp+0D8h]
0x066093: 498B6928                         mov     rbp, [r9+28h]
0x388312: 4C8BBDE0000000                   mov     r15, [rbp+0E0h]
0x06609E: 448B6D34                         mov     r13d, [rbp+34h]
0x388377: 4C03ADA8000000                   add     r13, [rbp+0A8h]
0x0660A9: 418A7500                         mov     sil, [r13+0]
0x3883DC: 49C7C3FF000000                   mov     r11, 0FFh
0x0660B4: 49C1E320                         shl     r11, 20h
0x0660B8: 49F7D3                           not     r11
0x0660BB: 4D21DF                           and     r15, r11
0x0660BE: 4C0FB6DE                         movzx   r11, sil
0x0660C2: 49C1E320                         shl     r11, 20h
0x0660C6: 4D09DF                           or      r15, r11
0x0661A1: 4D8B6928                         mov     r13, [r9+28h]
0x3884B1: 498BB5F0000000                   mov     rsi, [r13+0F0h]
0x0661AC: 56                               push    rsi
0x0661AD: 4989E7                           mov     r15, rsp
0x38851E: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x066296: 4D8B6928                         mov     r13, [r9+28h]
0x3885F4: 498BBD90000000                   mov     rdi, [r13+90h]
0x38865F: 4D8BBDE8000000                   mov     r15, [r13+0E8h]
0x0662A8: 480FB6FF                         movzx   rdi, dil
0x066389: 4D8B5928                         mov     r11, [r9+28h]
0x388732: 410FAE93B0000000                 ldmxcsr dword ptr [r11+0B0h]
0x38879E: 48B8DB20E00F01000000             mov     rax, 10FE020DBh
0x06639F: 50                               push    rax
0x0663A0: 68242D9070                       push    70902D24h
0x0663A5: 68275AFE18                       push    18FE5A27h
0x0663AA: 681664A73C                       push    3CA76416h
0x38880C: 4881442418E5492930               add     [rsp-8+arg_18], 302949E5h
0x0663B8: 4D8B4128                         mov     r8, [r9+28h]
0x38887C: 498B98F0000000                   mov     rbx, [r8+0F0h]
0x0664AC: 498B6928                         mov     rbp, [r9+28h]
0x0664B0: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x388948: 488B9DB0000000                   mov     rbx, [rbp+0B0h]
0x3889B0: 4C8BAD90000000                   mov     r13, [rbp+90h]
0x0665AF: 498B7128                         mov     rsi, [r9+28h]
0x388A7D: 488BAEE0000000                   mov     rbp, [rsi+0E0h]
0x0665BA: 448B7E34                         mov     r15d, [rsi+34h]
0x388AE8: 4C03BE90000000                   add     r15, [rsi+90h]
0x0665C5: 458A27                           mov     r12b, [r15]
0x388B52: 48C7C6FF000000                   mov     rsi, 0FFh
0x0665CF: 48C1E638                         shl     rsi, 38h
0x0665D3: 48F7D6                           not     rsi
0x0665D6: 4821F5                           and     rbp, rsi
0x0665D9: 490FB6F4                         movzx   rsi, r12b
0x0665DD: 48C1E638                         shl     rsi, 38h
0x0665E1: 4809F5                           or      rbp, rsi
0x0666C2: 498B6928                         mov     rbp, [r9+28h]
0x388C1F: 4C8BB5A0000000                   mov     r14, [rbp+0A0h]
0x388C8B: 48BD4049F0EB00000000             mov     rbp, 0EBF04940h
0x388CF4: 4881C5A86F9954                   add     rbp, 54996FA8h
0x0667CC: 498B5928                         mov     rbx, [r9+28h]
0x388DCD: 488BABE0000000                   mov     rbp, [rbx+0E0h]
0x388E39: 4C8BA3E8000000                   mov     r12, [rbx+0E8h]
0x0667DE: 480FB6ED                         movzx   rbp, bpl
0x0668D6: 4D8B7928                         mov     r15, [r9+28h]
0x388F0A: 498B87A0000000                   mov     rax, [r15+0A0h]
0x388F73: 49C7C04DE2A486                   mov     r8, 0FFFFFFFF86A4E24Dh
0x388FDD: 4981C05A218A79                   add     r8, 798A215Ah
0x0668EF: 4150                             push    r8
0x389047: 498B9FD8000000                   mov     rbx, [r15+0D8h]
0x0668F8: 48F72424                         mul     qword ptr [rsp]
0x0668FC: 4989C4                           mov     r12, rax
0x0669D0: 498B4128                         mov     rax, [r9+28h]
0x389112: 4C8BB090000000                   mov     r14, [rax+90h]
0x38917C: 4C2BB0D8000000                   sub     r14, [rax+0D8h]
0x066AC3: 4D8B5128                         mov     r10, [r9+28h]
0x389250: 498B9AE8000000                   mov     rbx, [r10+0E8h]
0x066ACE: 53                               push    rbx
0x066ACF: 4989E7                           mov     r15, rsp
0x3892B6: 498B9AE8000000                   mov     rbx, [r10+0E8h]
0x066BBA: 4D8B7928                         mov     r15, [r9+28h]
0x389381: 4D8BA7D8000000                   mov     r12, [r15+0D8h]
0x3893EC: 498BB790000000                   mov     rsi, [r15+90h]
0x066BCC: 4D0FB6E4                         movzx   r12, r12b
0x066CB8: 498B5128                         mov     rdx, [r9+28h]
0x3894BF: 0FAE92D8000000                   ldmxcsr dword ptr [rdx+0D8h]
0x38952A: 49BC9E2A551F01000000             mov     r12, 11F552A9Eh
0x066CCD: 4154                             push    r12
0x066CCF: 683E2E8A6F                       push    6F8A2E3Eh
0x066CD4: 68DB667B24                       push    247B66DBh
0x066CD9: 684B417C68                       push    687C414Bh
0x066CDE: 687F505C43                       push    435C507Fh
0x38959B: 48814424202220B420               add     qword ptr [rsp+20h], 20B42022h
0x066CEC: 4D8B4928                         mov     r9, [r9+28h]
0x389604: 498BA9A8000000                   mov     rbp, [r9+0A8h]
0x066DDF: 4D8B7128                         mov     r14, [r9+28h]
0x066DE3: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x3896D7: 498BAEE8000000                   mov     rbp, [r14+0E8h]
0x38973D: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x066ED1: 4D8B5928                         mov     r11, [r9+28h]
0x389808: 498B9BE8000000                   mov     rbx, [r11+0E8h]
0x066EDC: 458B6334                         mov     r12d, [r11+34h]
0x389872: 4D03A3A0000000                   add     r12, [r11+0A0h]
0x066EE7: 458A0C24                         mov     r9b, [r12]
0x066EEB: 4488CB                           mov     bl, r9b
0x066FD9: 498B5928                         mov     rbx, [r9+28h]
0x389945: 4C8B8390000000                   mov     r8, [rbx+90h]
0x066FE4: 4150                             push    r8
0x066FE6: 4989E7                           mov     r15, rsp
0x3899AA: 488BB390000000                   mov     rsi, [rbx+90h]
0x0670E1: 498B5128                         mov     rdx, [r9+28h]
0x389A82: 488BB280000000                   mov     rsi, [rdx+80h]
0x389AEA: 488B9AA8000000                   mov     rbx, [rdx+0A8h]
0x0670F3: 480FB6F6                         movzx   rsi, sil
0x0671D1: 4D8B6128                         mov     r12, [r9+28h]
0x389BBC: 410FAE9424A8000000               ldmxcsr dword ptr [r12+0A8h]
0x389C25: 49BB6E23AFDB00000000             mov     r11, 0DBAF236Eh
0x0671E8: 4153                             push    r11
0x0671EA: 68797BE613                       push    13E67B79h
0x0671EF: 68F317C42F                       push    2FC417F3h
0x0671F4: 689418CA38                       push    38CA1894h
0x389C96: 488144241852275A64               add     qword ptr [rsp+18h], 645A2752h
0x067202: 498B7928                         mov     rdi, [r9+28h]
0x389CFE: 488BBF90000000                   mov     rdi, [rdi+90h]
0x067300: 4D8B5928                         mov     r11, [r9+28h]
0x067304: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x067309: 4D8B7378                         mov     r14, [r11+78h]
0x389DCF: 498BB3B0000000                   mov     rsi, [r11+0B0h]
0x0673EC: 4D8B7128                         mov     r14, [r9+28h]
0x389E9F: 4D8BAEA8000000                   mov     r13, [r14+0A8h]
0x0673F7: 458B5E34                         mov     r11d, [r14+34h]
0x389F0C: 4D039EE8000000                   add     r11, [r14+0E8h]
0x067402: 418A13                           mov     dl, [r11]
0x389F73: 49C7C2FF000000                   mov     r10, 0FFh
0x06740C: 49C1E208                         shl     r10, 8
0x067410: 49F7D2                           not     r10
0x067413: 4D21D5                           and     r13, r10
0x067416: 4C0FB6D2                         movzx   r10, dl
0x06741A: 49C1E208                         shl     r10, 8
0x06741E: 4D09D5                           or      r13, r10
0x0674F9: 4D8B5928                         mov     r11, [r9+28h]
0x38A043: 498B9BE0000000                   mov     rbx, [r11+0E0h]
0x067504: 53                               push    rbx
0x067505: 4889E6                           mov     rsi, rsp
0x38A0AB: 498BBBE0000000                   mov     rdi, [r11+0E0h]
0x067602: 4D8B4928                         mov     r9, [r9+28h]
0x38A17F: 4D8BB1E8000000                   mov     r14, [r9+0E8h]
0x38A1EB: 4D8BA9B0000000                   mov     r13, [r9+0B0h]
0x067614: 4D0FB6F6                         movzx   r14, r14b
0x0676EE: 4D8B4128                         mov     r8, [r9+28h]
0x38A2BE: 410FAE90E8000000                 ldmxcsr dword ptr [r8+0E8h]
0x0676FA: 498B5128                         mov     rdx, [r9+28h]
0x38A324: 4C8BBAE0000000                   mov     r15, [rdx+0E0h]
0x38A392: 49BE9901BD2001000000             mov     r14, 120BD0199h
0x38A3FD: 4981C627494C1F                   add     r14, 1F4C4927h
0x0677FF: 4D8B4928                         mov     r9, [r9+28h]
0x067803: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x38A4D1: 4D8BA9B0000000                   mov     r13, [r9+0B0h]
0x38A536: 4D8BB1F0000000                   mov     r14, [r9+0F0h]
0x0678F4: 498B4928                         mov     rcx, [r9+28h]
0x38A60C: 4C8BA1E8000000                   mov     r12, [rcx+0E8h]
0x0678FF: 8B5134                           mov     edx, [rcx+34h]
0x38A675: 480391E0000000                   add     rdx, [rcx+0E0h]
0x067909: 408A3A                           mov     dil, [rdx]
0x38A6E2: 48C7C2FF000000                   mov     rdx, 0FFh
0x067913: 48C1E210                         shl     rdx, 10h
0x067917: 48F7D2                           not     rdx
0x06791A: 4921D4                           and     r12, rdx
0x06791D: 480FB6D7                         movzx   rdx, dil
0x067921: 48C1E210                         shl     rdx, 10h
0x067925: 4909D4                           or      r12, rdx
0x0679F8: 498B4928                         mov     rcx, [r9+28h]
0x38A7AD: 488B99D8000000                   mov     rbx, [rcx+0D8h]
0x067A03: 53                               push    rbx
0x067A04: 4989E5                           mov     r13, rsp
0x38A815: 4C8BB9D8000000                   mov     r15, [rcx+0D8h]
0x067AEA: 4D8B5928                         mov     r11, [r9+28h]
0x38A8E1: 498BB3E0000000                   mov     rsi, [r11+0E0h]
0x38A94A: 4D8BABF0000000                   mov     r13, [r11+0F0h]
0x067AFC: 56                               push    rsi
0x067AFD: 68111CC04F                       push    4FC01C11h
0x067B02: 68C1617E57                       push    577E61C1h
0x067B07: 68371AAE30                       push    30AE1A37h
0x067B0C: 685E7D2E13                       push    132E7D5Eh
0x067C02: 4D8B5128                         mov     r10, [r9+28h]
0x38AA23: 4D8BA2D8000000                   mov     r12, [r10+0D8h]
0x38AA8E: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x067C14: 4D0FB6E4                         movzx   r12, r12b
0x067CFD: 4D8B4128                         mov     r8, [r9+28h]
0x38AB5F: 410FAE90D8000000                 ldmxcsr dword ptr [r8+0D8h]
0x38ABCE: 49BB4F11182001000000             mov     r11, 12018114Fh
0x067D13: 4153                             push    r11
0x067D15: 68551EEE27                       push    27EE1E55h
0x067D1A: 68856D8963                       push    63896D85h
0x067D1F: 685523D65B                       push    5BD62355h
0x38AC3E: 48814424187139F11F               add     qword ptr [rsp+18h], 1FF13971h
0x067D2D: 498B7128                         mov     rsi, [r9+28h]
0x38ACAD: 488BBE90000000                   mov     rdi, [rsi+90h]
0x067E1C: 498B4928                         mov     rcx, [r9+28h]
0x067E20: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x38AD79: 488BA9C8000000                   mov     rbp, [rcx+0C8h]
0x38ADE2: 4C8BB9B0000000                   mov     r15, [rcx+0B0h]
0x067F1F: 4D8B5128                         mov     r10, [r9+28h]
0x38AEBB: 4D8BB2F0000000                   mov     r14, [r10+0F0h]
0x067F2A: 418B7234                         mov     esi, [r10+34h]
0x38AF26: 4903B2A0000000                   add     rsi, [r10+0A0h]
0x067F35: 448A2E                           mov     r13b, [rsi]
0x38AF90: 49C7C7FF000000                   mov     r15, 0FFh
0x067F3F: 49C1E718                         shl     r15, 18h
0x067F43: 49F7D7                           not     r15
0x067F46: 4D21FE                           and     r14, r15
0x067F49: 4D0FB6FD                         movzx   r15, r13b
0x067F4D: 49C1E718                         shl     r15, 18h
0x067F51: 4D09FE                           or      r14, r15
0x06801C: 4D8B4128                         mov     r8, [r9+28h]
0x38B05B: 4D8BA8E8000000                   mov     r13, [r8+0E8h]
0x068027: 4155                             push    r13
0x068029: 4889E5                           mov     rbp, rsp
0x38B0C0: 498B98E8000000                   mov     rbx, [r8+0E8h]
0x06810A: 4D8B5928                         mov     r11, [r9+28h]
0x38B190: 498BBBD0000000                   mov     rdi, [r11+0D0h]
0x38B1FD: 4D8BAB90000000                   mov     r13, [r11+90h]
0x06811C: 480FB6FF                         movzx   rdi, dil
0x068206: 4D8B5128                         mov     r10, [r9+28h]
0x38B2D5: 410FAE92B0000000                 ldmxcsr dword ptr [r10+0B0h]
0x38B343: 48B8C216B3F300000000             mov     rax, 0F3B316C2h
0x06821C: 50                               push    rax
0x06821D: 68A6409857                       push    579840A6h
0x068222: 685073F209                       push    9F27350h
0x068227: 685B262917                       push    1729265Bh
0x06822C: 68053D8A0A                       push    0A8A3D05h
0x38B3B0: 4881442420FE33564C               add     qword ptr [rsp+20h], 4C5633FEh
0x06823A: 4D8B4128                         mov     r8, [r9+28h]
0x38B420: 498BA8E0000000                   mov     rbp, [r8+0E0h]
0x068321: 4D8B5928                         mov     r11, [r9+28h]
0x068325: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x38B4F0: 498BABD8000000                   mov     rbp, [r11+0D8h]
0x38B556: 4D8BA3A0000000                   mov     r12, [r11+0A0h]
0x06841F: 498B6928                         mov     rbp, [r9+28h]
0x38B62D: 4C8BADD8000000                   mov     r13, [rbp+0D8h]
0x06842A: 448B5534                         mov     r10d, [rbp+34h]
0x38B695: 4C0395A0000000                   add     r10, [rbp+0A0h]
0x068435: 458A22                           mov     r12b, [r10]
0x38B703: 48C7C5FF000000                   mov     rbp, 0FFh
0x06843F: 48C1E528                         shl     rbp, 28h
0x068443: 48F7D5                           not     rbp
0x068446: 4921ED                           and     r13, rbp
0x068449: 490FB6EC                         movzx   rbp, r12b
0x06844D: 48C1E528                         shl     rbp, 28h
0x068451: 4909ED                           or      r13, rbp
0x38B7CE: 48BEB7816D1E01000000             mov     rsi, 11E6D81B7h
0x068541: 56                               push    rsi
0x068542: 68D730A003                       push    3A030D7h
0x068547: 6808067B67                       push    677B0608h
0x06854C: 68503EB968                       push    68B93E50h
0x068551: 684771EB19                       push    19EB7147h
0x38B83B: 488144242031371C22               add     qword ptr [rsp+20h], 221C3731h
0x06855F: 498B5128                         mov     rdx, [r9+28h]
0x38B8AB: 488BAAE0000000                   mov     rbp, [rdx+0E0h]
0x068655: 498B7128                         mov     rsi, [r9+28h]
0x38B97B: 4C8BAEA8000000                   mov     r13, [rsi+0A8h]
0x38B9E9: 4C8BB6A0000000                   mov     r14, [rsi+0A0h]
0x068667: 4D0FB6ED                         movzx   r13, r13b
0x068758: 4D8B7928                         mov     r15, [r9+28h]
0x38BAB4: 498B87E0000000                   mov     rax, [r15+0E0h]
0x38BB1F: 49C7C4E5BCE7B5                   mov     r12, 0FFFFFFFFB5E7BCE5h
0x38BB86: 4981C47C3DD14A                   add     r12, 4AD13D7Ch
0x068771: 4154                             push    r12
0x38BBEE: 498BBFE8000000                   mov     rdi, [r15+0E8h]
0x06877A: 48F72424                         mul     qword ptr [rsp]
0x06877E: 4889C6                           mov     rsi, rax
0x06884B: 498B6928                         mov     rbp, [r9+28h]
0x38BCBF: 4C8BA5B0000000                   mov     r12, [rbp+0B0h]
0x38BD29: 4C03A5A8000000                   add     r12, [rbp+0A8h]
0x06894A: 498B4928                         mov     rcx, [r9+28h]
0x38BDF9: 4C8BB1D8000000                   mov     r14, [rcx+0D8h]
0x068955: 4156                             push    r14
0x068957: 4989E5                           mov     r13, rsp
0x38BE60: 4C8BA1D8000000                   mov     r12, [rcx+0D8h]
0x068A37: 498B7928                         mov     rdi, [r9+28h]
0x38BF35: 4C8BAFE0000000                   mov     r13, [rdi+0E0h]
0x38BF9C: 4C8BA7D8000000                   mov     r12, [rdi+0D8h]
0x068A49: 4D0FB6ED                         movzx   r13, r13b
0x068B42: 498B6928                         mov     rbp, [r9+28h]
0x38C072: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x068B4D: 498B5128                         mov     rdx, [r9+28h]
0x38C0DB: 4C8BAAD8000000                   mov     r13, [rdx+0D8h]
0x38C147: 48BE8A2E1FEF00000000             mov     rsi, 0EF1F2E8Ah
0x38C1B2: 4881C6361CEA50                   add     rsi, 50EA1C36h
0x068C51: 498B5128                         mov     rdx, [r9+28h]
0x068C55: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x38C283: 4C8BAAE8000000                   mov     r13, [rdx+0E8h]
0x38C2EE: 4C8BA2E0000000                   mov     r12, [rdx+0E0h]
0x068D43: 498B4128                         mov     rax, [r9+28h]
0x38C3C4: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x068D4E: 8B5034                           mov     edx, [rax+34h]
0x38C42B: 480390E0000000                   add     rdx, [rax+0E0h]
0x068D58: 8A02                             mov     al, [rdx]
0x068D5A: 4188C7                           mov     r15b, al
0x068E4F: 498B4928                         mov     rcx, [r9+28h]
0x38C4F5: 488BB1F0000000                   mov     rsi, [rcx+0F0h]
0x068E5A: 56                               push    rsi
0x068E5B: 4989E7                           mov     r15, rsp
0x38C55D: 488BB1F0000000                   mov     rsi, [rcx+0F0h]
0x068F46: 4D8B4128                         mov     r8, [r9+28h]
0x38C62F: 498B88F0000000                   mov     rcx, [r8+0F0h]
0x38C69A: 4D8BA0A8000000                   mov     r12, [r8+0A8h]
0x068F58: 51                               push    rcx
0x068F59: 688532CE78                       push    78CE3285h
0x068F5E: 68227B4A00                       push    4A7B22h
0x068F63: 685969C32D                       push    2DC36959h
0x068F68: 688D5E7138                       push    38715E8Dh
0x06904D: 4D8B6128                         mov     r12, [r9+28h]
0x38C76E: 4D8BB42490000000                 mov     r14, [r12+90h]
0x38C7D4: 498BAC24D8000000                 mov     rbp, [r12+0D8h]
0x069061: 4D0FB6F6                         movzx   r14, r14b
0x069151: 4D8B5928                         mov     r11, [r9+28h]
0x38C8AA: 410FAE93E8000000                 ldmxcsr dword ptr [r11+0E8h]
0x38C910: 48B95C0C322501000000             mov     rcx, 125320C5Ch
0x069167: 51                               push    rcx
0x069168: 6836541F07                       push    71F5436h
0x06916D: 68C72F5916                       push    16592FC7h
0x069172: 68F2127056                       push    567012F2h
0x069177: 68347B3E4A                       push    4A3E7B34h
0x38C978: 4881442420643ED71A               add     qword ptr [rsp+20h], 1AD73E64h
0x069185: 4D8B5928                         mov     r11, [r9+28h]
0x38C9DF: 4D8BA3A0000000                   mov     r12, [r11+0A0h]
0x069282: 4D8B7128                         mov     r14, [r9+28h]
0x069286: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x38CAB5: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x38CB1F: 4D8BA6D8000000                   mov     r12, [r14+0D8h]
0x06937A: 4D8B5928                         mov     r11, [r9+28h]
0x38CBEC: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x069385: 418B7B34                         mov     edi, [r11+34h]
0x38CC55: 4903BBB0000000                   add     rdi, [r11+0B0h]
0x069390: 8A07                             mov     al, [rdi]
0x38CCBD: 49C7C0FF000000                   mov     r8, 0FFh
0x069399: 49C1E008                         shl     r8, 8
0x06939D: 49F7D0                           not     r8
0x0693A0: 4D21C6                           and     r14, r8
0x0693A3: 4C0FB6C0                         movzx   r8, al
0x0693A7: 49C1E008                         shl     r8, 8
0x0693AB: 4D09C6                           or      r14, r8
0x069497: 498B7928                         mov     rdi, [r9+28h]
0x38CD8F: 4C8B97E8000000                   mov     r10, [rdi+0E8h]
0x0694A2: 4152                             push    r10
0x0694A4: 4889E3                           mov     rbx, rsp
0x38CDFD: 488BAFE8000000                   mov     rbp, [rdi+0E8h]
0x069594: 4D8B7928                         mov     r15, [r9+28h]
0x38CED0: 4D8BA7F0000000                   mov     r12, [r15+0F0h]
0x38CF3A: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x0695A6: 4D0FB6E4                         movzx   r12, r12b
0x06967E: 498B6928                         mov     rbp, [r9+28h]
0x38D007: 0FAE95D8000000                   ldmxcsr dword ptr [rbp+0D8h]
0x069689: 4D8B6128                         mov     r12, [r9+28h]
0x38D075: 498B9C24E8000000                 mov     rbx, [r12+0E8h]
0x38D0DE: 49BFA3213DD700000000             mov     r15, 0D73D21A3h
0x38D14B: 4981C71D29CC68                   add     r15, 68CC291Dh
0x069791: 4D8B5128                         mov     r10, [r9+28h]
0x069795: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x38D21D: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x38D285: 498BB290000000                   mov     rsi, [r10+90h]
0x06988C: 4D8B6928                         mov     r13, [r9+28h]
0x38D354: 4D8BA5A8000000                   mov     r12, [r13+0A8h]
0x069897: 418B7D34                         mov     edi, [r13+34h]
0x38D3BE: 4903BD90000000                   add     rdi, [r13+90h]
0x0698A2: 408A37                           mov     sil, [rdi]
0x38D42B: 48C7C3FF000000                   mov     rbx, 0FFh
0x0698AC: 48C1E310                         shl     rbx, 10h
0x0698B0: 48F7D3                           not     rbx
0x0698B3: 4921DC                           and     r12, rbx
0x0698B6: 480FB6DE                         movzx   rbx, sil
0x0698BA: 48C1E310                         shl     rbx, 10h
0x0698BE: 4909DC                           or      r12, rbx
0x06999F: 498B7928                         mov     rdi, [r9+28h]
0x38D501: 4C8BBFD8000000                   mov     r15, [rdi+0D8h]
0x0699AA: 4157                             push    r15
0x0699AC: 4889E3                           mov     rbx, rsp
0x38D566: 4C8BBFD8000000                   mov     r15, [rdi+0D8h]
0x069A9E: 4D8B5128                         mov     r10, [r9+28h]
0x38D632: 4D8BAAA8000000                   mov     r13, [r10+0A8h]
0x38D69C: 4D8BB2F0000000                   mov     r14, [r10+0F0h]
0x069AB0: 4D0FB6ED                         movzx   r13, r13b
0x069B98: 4D8B6928                         mov     r13, [r9+28h]
0x38D768: 410FAE95E0000000                 ldmxcsr dword ptr [r13+0E0h]
0x069BA4: 4D8B4128                         mov     r8, [r9+28h]
0x38D7D4: 498B98E8000000                   mov     rbx, [r8+0E8h]
0x38D842: 48BE6E1BC6C200000000             mov     rsi, 0C2C61B6Eh
0x38D8AC: 4881C6522F437D                   add     rsi, 7D432F52h
0x069C9C: 498B4128                         mov     rax, [r9+28h]
0x069CA0: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x38D980: 488BB8F0000000                   mov     rdi, [rax+0F0h]
0x38D9EC: 4C8BB890000000                   mov     r15, [rax+90h]
0x069D92: 498B4128                         mov     rax, [r9+28h]
0x38DAC0: 488BB0F0000000                   mov     rsi, [rax+0F0h]
0x069D9D: 448B4034                         mov     r8d, [rax+34h]
0x38DB29: 4C0380B0000000                   add     r8, [rax+0B0h]
0x069DA8: 418A18                           mov     bl, [r8]
0x38DB90: 49C7C6FF000000                   mov     r14, 0FFh
0x069DB2: 49C1E618                         shl     r14, 18h
0x069DB6: 49F7D6                           not     r14
0x069DB9: 4C21F6                           and     rsi, r14
0x069DBC: 4C0FB6F3                         movzx   r14, bl
0x069DC0: 49C1E618                         shl     r14, 18h
0x069DC4: 4C09F6                           or      rsi, r14
0x069EA1: 498B5928                         mov     rbx, [r9+28h]
0x38DC65: 488BABA8000000                   mov     rbp, [rbx+0A8h]
0x069EAC: 55                               push    rbp
0x069EAD: 4889E6                           mov     rsi, rsp
0x38DCD0: 488B9BA8000000                   mov     rbx, [rbx+0A8h]
0x069F96: 498B5128                         mov     rdx, [r9+28h]
0x38DDA0: 488B9AC0000000                   mov     rbx, [rdx+0C0h]
0x38DE0E: 488BB290000000                   mov     rsi, [rdx+90h]
0x069FA8: 480FB6DB                         movzx   rbx, bl
0x06A08B: 4D8B5128                         mov     r10, [r9+28h]
0x38DEE5: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x38DF4D: 49BF130EEB0501000000             mov     r15, 105EB0E13h
0x06A0A1: 4157                             push    r15
0x06A0A3: 685A20AC3B                       push    3BAC205Ah
0x06A0A8: 689A02531A                       push    1A53029Ah
0x06A0AD: 680C28E470                       push    70E4280Ch
0x06A0B2: 68A0249013                       push    139024A0h
0x38DFBB: 4881442420AD3C1E3A               add     qword ptr [rsp+20h], 3A1E3CADh
0x06A0C0: 4D8B6128                         mov     r12, [r9+28h]
0x38E02A: 4D8BBC24A8000000                 mov     r15, [r12+0A8h]
0x06A1B5: 498B4928                         mov     rcx, [r9+28h]
0x06A1B9: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x38E0FE: 4C8BA180000000                   mov     r12, [rcx+80h]
0x38E169: 4C8BA9F0000000                   mov     r13, [rcx+0F0h]
0x06A2A2: 4D8B5128                         mov     r10, [r9+28h]
0x38E23A: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x06A2AD: 458B7A34                         mov     r15d, [r10+34h]
0x38E2A7: 4D03BAD8000000                   add     r15, [r10+0D8h]
0x06A2B8: 458A17                           mov     r10b, [r15]
0x38E30C: 48C7C2FF000000                   mov     rdx, 0FFh
0x06A2C2: 48C1E220                         shl     rdx, 20h
0x06A2C6: 48F7D2                           not     rdx
0x06A2C9: 4821D3                           and     rbx, rdx
0x06A2CC: 490FB6D2                         movzx   rdx, r10b
0x06A2D0: 48C1E220                         shl     rdx, 20h
0x06A2D4: 4809D3                           or      rbx, rdx
0x06A3B8: 4D8B6128                         mov     r12, [r9+28h]
0x38E3DA: 4D8BAC2490000000                 mov     r13, [r12+90h]
0x38E447: 48BEB5834CF100000000             mov     rsi, 0F14C83B5h
0x38E4B8: 4881C633353D4F                   add     rsi, 4F3D3533h
0x06A4C0: 498B4128                         mov     rax, [r9+28h]
0x38E58A: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x38E5F5: 488BB8E0000000                   mov     rdi, [rax+0E0h]
0x06A4D2: 4D0FB6FF                         movzx   r15, r15b
0x06A5A9: 498B6928                         mov     rbp, [r9+28h]
0x38E6C1: 488B85F0000000                   mov     rax, [rbp+0F0h]
0x38E72D: 48C7C184B3588B                   mov     rcx, 0FFFFFFFF8B58B384h
0x38E794: 4881C183118875                   add     rcx, 75881183h
0x06A5C2: 51                               push    rcx
0x38E800: 488BADB0000000                   mov     rbp, [rbp+0B0h]
0x06A5CA: 48F72424                         mul     qword ptr [rsp]
0x06A5CE: 4989C5                           mov     r13, rax
0x06A6C5: 4D8B5128                         mov     r10, [r9+28h]
0x38E8CF: 498BBAA0000000                   mov     rdi, [r10+0A0h]
0x38E939: 492BBAE0000000                   sub     rdi, [r10+0E0h]
0x06A7AC: 4D8B6128                         mov     r12, [r9+28h]
0x38EA0B: 4D8BAC24B0000000                 mov     r13, [r12+0B0h]
0x06A7B8: 4155                             push    r13
0x06A7BA: 4889E3                           mov     rbx, rsp
0x38EA73: 498BB424B0000000                 mov     rsi, [r12+0B0h]
0x06A8AE: 498B7928                         mov     rdi, [r9+28h]
0x38EB41: 488BAFA0000000                   mov     rbp, [rdi+0A0h]
0x38EBAA: 488BBFA8000000                   mov     rdi, [rdi+0A8h]
0x06A8C0: 480FB6ED                         movzx   rbp, bpl
0x06A993: 4D8B6128                         mov     r12, [r9+28h]
0x38EC79: 410FAE9424A0000000               ldmxcsr dword ptr [r12+0A0h]
0x06A9A0: 498B4128                         mov     rax, [r9+28h]
0x38ECE4: 488BB0B0000000                   mov     rsi, [rax+0B0h]
0x38ED4C: 48BF8A472D2C01000000             mov     rdi, 12C2D478Ah
0x38EDB5: 4881C73603DC13                   add     rdi, 13DC0336h
0x06AAA5: 498B7928                         mov     rdi, [r9+28h]
0x06AAA9: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x38EE7F: 488B9F90000000                   mov     rbx, [rdi+90h]
0x38EEE5: 488BB7A8000000                   mov     rsi, [rdi+0A8h]
0x06AB99: 4D8B4128                         mov     r8, [r9+28h]
0x38EFB1: 4D8BB8A8000000                   mov     r15, [r8+0A8h]
0x06ABA4: 458B4834                         mov     r9d, [r8+34h]
0x38F01C: 4D038890000000                   add     r9, [r8+90h]
0x06ABAF: 418A01                           mov     al, [r9]
0x06ABB2: 4188C7                           mov     r15b, al
0x06ACAA: 498B7928                         mov     rdi, [r9+28h]
0x38F0ED: 488BB7F0000000                   mov     rsi, [rdi+0F0h]
0x06ACB5: 56                               push    rsi
0x06ACB6: 4889E3                           mov     rbx, rsp
0x38F153: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x06AD9A: 4D8B4128                         mov     r8, [r9+28h]
0x38F225: 4D8BB8D0000000                   mov     r15, [r8+0D0h]
0x38F28E: 4D8BB0B0000000                   mov     r14, [r8+0B0h]
0x06ADAC: 4D0FB6FF                         movzx   r15, r15b
0x06AEA1: 498B4928                         mov     rcx, [r9+28h]
0x38F35B: 0FAE91F0000000                   ldmxcsr dword ptr [rcx+0F0h]
0x38F3C9: 48BF01CE9BF000000000             mov     rdi, 0F09BCE01h
0x06AEB6: 57                               push    rdi
0x06AEB7: 68D311427D                       push    7D4211D3h
0x06AEBC: 68413DCC67                       push    67CC3D41h
0x06AEC1: 6846147907                       push    7791446h
0x06AEC6: 6896427D61                       push    617D4296h
0x38F435: 4881442420BF7C6D4F               add     qword ptr [rsp+20h], 4F6D7CBFh
0x06AED4: 498B5928                         mov     rbx, [r9+28h]
0x38F49D: 4C8BB3E8000000                   mov     r14, [rbx+0E8h]
0x06AFCD: 498B4128                         mov     rax, [r9+28h]
0x06AFD1: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x38F56E: 4C8BB0A8000000                   mov     r14, [rax+0A8h]
0x38F5DC: 488BB8E8000000                   mov     rdi, [rax+0E8h]
0x06B0C4: 4D8B4928                         mov     r9, [r9+28h]
0x38F6A6: 498BB9B0000000                   mov     rdi, [r9+0B0h]
0x06B0CF: 418B5934                         mov     ebx, [r9+34h]
0x38F70D: 490399E8000000                   add     rbx, [r9+0E8h]
0x06B0DA: 448A3B                           mov     r15b, [rbx]
0x38F775: 48C7C3FF000000                   mov     rbx, 0FFh
0x06B0E4: 48C1E308                         shl     rbx, 8
0x06B0E8: 48F7D3                           not     rbx
0x06B0EB: 4821DF                           and     rdi, rbx
0x06B0EE: 490FB6DF                         movzx   rbx, r15b
0x06B0F2: 48C1E308                         shl     rbx, 8
0x06B0F6: 4809DF                           or      rdi, rbx
0x06B1C7: 498B4128                         mov     rax, [r9+28h]
0x38F844: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x06B1D2: 4155                             push    r13
0x06B1D4: 4989E6                           mov     r14, rsp
0x38F8AA: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x06B2CF: 498B5928                         mov     rbx, [r9+28h]
0x38F97F: 488BBBE8000000                   mov     rdi, [rbx+0E8h]
0x38F9EB: 488B9BE0000000                   mov     rbx, [rbx+0E0h]
0x06B2E1: 57                               push    rdi
0x06B2E2: 68F9501639                       push    391650F9h
0x06B2E7: 681D65A048                       push    48A0651Dh
0x06B2EC: 6842691160                       push    60116942h
0x06B3D3: 4D8B4928                         mov     r9, [r9+28h]
0x38FABC: 498BA980000000                   mov     rbp, [r9+80h]
0x38FB25: 498BB990000000                   mov     rdi, [r9+90h]
0x06B3E5: 480FB6ED                         movzx   rbp, bpl
0x06B4CD: 4D8B6928                         mov     r13, [r9+28h]
0x38FBF4: 410FAE95A0000000                 ldmxcsr dword ptr [r13+0A0h]
0x38FC61: 48B81DE2392001000000             mov     rax, 12039E21Dh
0x06B4E3: 50                               push    rax
0x06B4E4: 68CD43FE1F                       push    1FFE43CDh
0x06B4E9: 68D8043434                       push    343404D8h
0x06B4EE: 68D36D8D05                       push    58D6DD3h
0x38FCCA: 4881442418A368CF1F               add     qword ptr [rsp+18h], 1FCF68A3h
0x06B4FC: 4D8B5128                         mov     r10, [r9+28h]
0x38FD39: 498BAAB0000000                   mov     rbp, [r10+0B0h]
0x06B5F9: 498B4928                         mov     rcx, [r9+28h]
0x06B5FD: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x38FE08: 488BB9B0000000                   mov     rdi, [rcx+0B0h]
0x38FE73: 4C8BB9A0000000                   mov     r15, [rcx+0A0h]
0x06B6F9: 4D8B5128                         mov     r10, [r9+28h]
0x38FF4C: 4D8BAAF0000000                   mov     r13, [r10+0F0h]
0x06B704: 418B4234                         mov     eax, [r10+34h]
0x38FFB2: 490382B0000000                   add     rax, [r10+0B0h]
0x06B70F: 8A18                             mov     bl, [rax]
0x390019: 48C7C7FF000000                   mov     rdi, 0FFh
0x06B718: 48C1E710                         shl     rdi, 10h
0x06B71C: 48F7D7                           not     rdi
0x06B71F: 4921FD                           and     r13, rdi
0x06B722: 480FB6FB                         movzx   rdi, bl
0x06B726: 48C1E710                         shl     rdi, 10h
0x06B72A: 4909FD                           or      r13, rdi
0x06B81B: 498B5928                         mov     rbx, [r9+28h]
0x3900F0: 4C8B83E0000000                   mov     r8, [rbx+0E0h]
0x06B826: 4150                             push    r8
0x06B828: 4989E7                           mov     r15, rsp
0x390156: 488B9BE0000000                   mov     rbx, [rbx+0E0h]
0x06B91B: 4D8B7128                         mov     r14, [r9+28h]
0x390227: 4D8BAEF0000000                   mov     r13, [r14+0F0h]
0x39028C: 498BBE90000000                   mov     rdi, [r14+90h]
0x06B92D: 4155                             push    r13
0x06B92F: 68FE249F5F                       push    5F9F24FEh
0x06B934: 68F3153E64                       push    643E15F3h
0x06B939: 68B879AC7B                       push    7BAC79B8h
0x06B93E: 689C7D1D1B                       push    1B1D7D9Ch
0x06BA29: 498B5928                         mov     rbx, [r9+28h]
0x390361: 488BBBD0000000                   mov     rdi, [rbx+0D0h]
0x3903CA: 4C8BB3B0000000                   mov     r14, [rbx+0B0h]
0x06BA3B: 480FB6FF                         movzx   rdi, dil
0x06BB23: 4D8B7128                         mov     r14, [r9+28h]
0x39049E: 410FAE96B0000000                 ldmxcsr dword ptr [r14+0B0h]
0x390508: 49BEE50352C100000000             mov     r14, 0C15203E5h
0x06BB39: 4156                             push    r14
0x06BB3B: 68EF679368                       push    689367EFh
0x06BB40: 68B0256815                       push    156825B0h
0x06BB45: 6887640922                       push    22096487h
0x06BB4A: 68A95EF837                       push    37F85EA9h
0x390573: 4881442420DB46B77E               add     qword ptr [rsp+20h], 7EB746DBh
0x06BB58: 4D8B4928                         mov     r9, [r9+28h]
0x3905DA: 498BB9E8000000                   mov     rdi, [r9+0E8h]
0x06BC5F: 4D8B4128                         mov     r8, [r9+28h]
0x06BC63: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x3906AB: 4D8BA888000000                   mov     r13, [r8+88h]
0x390710: 498BA8B0000000                   mov     rbp, [r8+0B0h]
0x06BD54: 4D8B5128                         mov     r10, [r9+28h]
0x3907E0: 4D8BAAA0000000                   mov     r13, [r10+0A0h]
0x06BD5F: 418B5A34                         mov     ebx, [r10+34h]
0x39084E: 49039AE0000000                   add     rbx, [r10+0E0h]
0x06BD6A: 448A0B                           mov     r9b, [rbx]
0x3908BC: 48C7C7FF000000                   mov     rdi, 0FFh
0x06BD74: 48C1E718                         shl     rdi, 18h
0x06BD78: 48F7D7                           not     rdi
0x06BD7B: 4921FD                           and     r13, rdi
0x06BD7E: 490FB6F9                         movzx   rdi, r9b
0x06BD82: 48C1E718                         shl     rdi, 18h
0x06BD86: 4909FD                           or      r13, rdi
0x06BE68: 498B5928                         mov     rbx, [r9+28h]
0x390990: 488B93E0000000                   mov     rdx, [rbx+0E0h]
0x06BE73: 52                               push    rdx
0x06BE74: 4889E6                           mov     rsi, rsp
0x3909F7: 4C8BB3E0000000                   mov     r14, [rbx+0E0h]
0x06BF61: 498B5928                         mov     rbx, [r9+28h]
0x390AC3: 4C8BB3A8000000                   mov     r14, [rbx+0A8h]
0x390B2F: 488BB3E8000000                   mov     rsi, [rbx+0E8h]
0x06BF73: 4156                             push    r14
0x06BF75: 68B9154D09                       push    94D15B9h
0x06BF7A: 68EA567752                       push    527756EAh
0x06BF7F: 684D5A431C                       push    1C435A4Dh
0x06C074: 498B5128                         mov     rdx, [r9+28h]
0x390BFF: 4C8BBAD0000000                   mov     r15, [rdx+0D0h]
0x390C6A: 488BBAA8000000                   mov     rdi, [rdx+0A8h]
0x06C086: 4D0FB6FF                         movzx   r15, r15b
0x06C17C: 4D8B5928                         mov     r11, [r9+28h]
0x390D40: 410FAE93F0000000                 ldmxcsr dword ptr [r11+0F0h]
0x06C188: 4D8B5128                         mov     r10, [r9+28h]
0x390DAB: 498BAAB0000000                   mov     rbp, [r10+0B0h]
0x390E18: 49BC571D62D000000000             mov     r12, 0D0621D57h
0x390E86: 4981C4692DA76F                   add     r12, 6FA72D69h
0x06C286: 4D8B6128                         mov     r12, [r9+28h]
0x390F5A: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x390FBF: 4D8BAC24B8000000                 mov     r13, [r12+0B8h]
0x391027: 498B9C24A0000000                 mov     rbx, [r12+0A0h]
0x06C384: 498B7928                         mov     rdi, [r9+28h]
0x3910FB: 488BB790000000                   mov     rsi, [rdi+90h]
0x06C38F: 448B7734                         mov     r14d, [rdi+34h]
0x391161: 4C03B7E0000000                   add     r14, [rdi+0E0h]
0x06C39A: 458A3E                           mov     r15b, [r14]
0x3911C7: 49C7C3FF000000                   mov     r11, 0FFh
0x06C3A4: 49C1E320                         shl     r11, 20h
0x06C3A8: 49F7D3                           not     r11
0x06C3AB: 4C21DE                           and     rsi, r11
0x06C3AE: 4D0FB6DF                         movzx   r11, r15b
0x06C3B2: 49C1E320                         shl     r11, 20h
0x06C3B6: 4C09DE                           or      rsi, r11
0x06C494: 498B4128                         mov     rax, [r9+28h]
0x39129A: 4C8BB8A8000000                   mov     r15, [rax+0A8h]
0x06C49F: 4157                             push    r15
0x06C4A1: 4989E7                           mov     r15, rsp
0x391303: 4C8BB0A8000000                   mov     r14, [rax+0A8h]
0x06C5A2: 4D8B7928                         mov     r15, [r9+28h]
0x3913D5: 4D8BAFC0000000                   mov     r13, [r15+0C0h]
0x391441: 4D8BB7E8000000                   mov     r14, [r15+0E8h]
0x06C5B4: 4D0FB6ED                         movzx   r13, r13b
0x06C6A9: 4D8B6928                         mov     r13, [r9+28h]
0x391513: 410FAE95E0000000                 ldmxcsr dword ptr [r13+0E0h]
0x391582: 49BF1F08922101000000             mov     r15, 12192081Fh
0x06C6BF: 4157                             push    r15
0x06C6C1: 68750AA84A                       push    4AA80A75h
0x06C6C6: 687935FC0A                       push    0AFC3579h
0x06C6CB: 68FE3F065A                       push    5A063FFEh
0x06C6D0: 68A6766068                       push    686076A6h
0x3915EF: 4881442420A142771E               add     [rsp-8+arg_20], 1E7742A1h
0x06C6DE: 498B4928                         mov     rcx, [r9+28h]
0x391659: 488BB9E8000000                   mov     rdi, [rcx+0E8h]
0x06C7B7: 4D8B5128                         mov     r10, [r9+28h]
0x06C7BB: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x391727: 4D8BBAB8000000                   mov     r15, [r10+0B8h]
0x39178C: 4D8BAAB0000000                   mov     r13, [r10+0B0h]
0x06C89B: 498B7128                         mov     rsi, [r9+28h]
0x39185D: 4C8BA6E0000000                   mov     r12, [rsi+0E0h]
0x06C8A6: 448B6E34                         mov     r13d, [rsi+34h]
0x3918C5: 4C03AEF0000000                   add     r13, [rsi+0F0h]
0x06C8B1: 418A4D00                         mov     cl, [r13+0]
0x39192A: 49C7C5FF000000                   mov     r13, 0FFh
0x06C8BC: 49C1E530                         shl     r13, 30h
0x06C8C0: 49F7D5                           not     r13
0x06C8C3: 4D21EC                           and     r12, r13
0x06C8C6: 4C0FB6E9                         movzx   r13, cl
0x06C8CA: 49C1E530                         shl     r13, 30h
0x06C8CE: 4D09EC                           or      r12, r13
0x06C9AD: 4D8B6128                         mov     r12, [r9+28h]
0x391A00: 498BB424D8000000                 mov     rsi, [r12+0D8h]
0x06C9B9: 56                               push    rsi
0x06C9BA: 4989E5                           mov     r13, rsp
0x391A6D: 498B9C24D8000000                 mov     rbx, [r12+0D8h]
0x06CAA1: 4D8B5128                         mov     r10, [r9+28h]
0x391B38: 4D8B8AE0000000                   mov     r9, [r10+0E0h]
0x391BA2: 4D8BA290000000                   mov     r12, [r10+90h]
0x06CAB3: 4151                             push    r9
0x06CAB5: 68935C4C5D                       push    5D4C5C93h
0x06CABA: 68671E357A                       push    7A351E67h
0x06CABF: 689D0E600A                       push    0A600E9Dh
0x06CAC4: 6834121056                       push    56101234h
0x06CBB3: 4D8B5128                         mov     r10, [r9+28h]
0x06CBB7: 498B7278                         mov     rsi, [r10+78h]
0x391C72: 498BBAD8000000                   mov     rdi, [r10+0D8h]
0x06CBC2: 480FB6F6                         movzx   rsi, sil
0x06CC9C: 498B5128                         mov     rdx, [r9+28h]
0x391D3F: 0FAE92A8000000                   ldmxcsr dword ptr [rdx+0A8h]
0x06CCA7: 498B7928                         mov     rdi, [r9+28h]
0x391DAD: 488BB7B0000000                   mov     rsi, [rdi+0B0h]
0x391E12: 49BE28030FC700000000             mov     r14, 0C70F0328h
0x391E7E: 4981C69847FA78                   add     r14, 78FA4798h
0x06CDA0: 4D8B5128                         mov     r10, [r9+28h]
0x06CDA4: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x391F4F: 4D8BB2F0000000                   mov     r14, [r10+0F0h]
0x391FBC: 4D8BBAA8000000                   mov     r15, [r10+0A8h]
0x06CE95: 4D8B7128                         mov     r14, [r9+28h]
0x392089: 4D8BA6F0000000                   mov     r12, [r14+0F0h]
0x06CEA0: 418B6E34                         mov     ebp, [r14+34h]
0x3920EE: 4903AEE8000000                   add     rbp, [r14+0E8h]
0x06CEAB: 408A6D00                         mov     bpl, [rbp+0]
0x39215C: 49C7C6FF000000                   mov     r14, 0FFh
0x06CEB6: 49C1E638                         shl     r14, 38h
0x06CEBA: 49F7D6                           not     r14
0x06CEBD: 4D21F4                           and     r12, r14
0x06CEC0: 4C0FB6F5                         movzx   r14, bpl
0x06CEC4: 49C1E638                         shl     r14, 38h
0x06CEC8: 4D09F4                           or      r12, r14
0x39222B: 49BEC09D8FE500000000             mov     r14, 0E58F9DC0h
0x06CFAC: 4156                             push    r14
0x06CFAE: 68076D831B                       push    1B836D07h
0x06CFB3: 6897167134                       push    34711697h
0x06CFB8: 689405484A                       push    4A480594h
0x392294: 4881442418281BFA5A               add     qword ptr [rsp+18h], 5AFA1B28h
0x06CFC6: 4D8B7928                         mov     r15, [r9+28h]
0x392301: 498BBFD8000000                   mov     rdi, [r15+0D8h]
0x06D0BF: 498B5128                         mov     rdx, [r9+28h]
0x3923D8: 488BAAB8000000                   mov     rbp, [rdx+0B8h]
0x392441: 4C8BBAB0000000                   mov     r15, [rdx+0B0h]
0x06D0D1: 480FB6ED                         movzx   rbp, bpl
0x06D1BA: 498B5928                         mov     rbx, [r9+28h]
0x392514: 488B83A0000000                   mov     rax, [rbx+0A0h]
0x392579: 49C7C7AB2F39F4                   mov     r15, 0FFFFFFFFF4392FABh
0x3925E0: 4981C7A305550C                   add     r15, 0C5505A3h
0x06D1D3: 4157                             push    r15
0x392645: 4C8BABF0000000                   mov     r13, [rbx+0F0h]
0x06D1DC: 48F72424                         mul     qword ptr [rsp]
0x06D1E0: 4889C6                           mov     rsi, rax
0x06D2CE: 498B5928                         mov     rbx, [r9+28h]
0x392714: 4C8BB3E0000000                   mov     r14, [rbx+0E0h]
0x39277B: 4C03B3A8000000                   add     r14, [rbx+0A8h]
0x06D3CF: 498B7928                         mov     rdi, [r9+28h]
0x39284B: 4C8BBFE8000000                   mov     r15, [rdi+0E8h]
0x06D3DA: 4157                             push    r15
0x06D3DC: 4989E4                           mov     r12, rsp
0x3928B1: 488BB7E8000000                   mov     rsi, [rdi+0E8h]
0x06D4B9: 4D8B7128                         mov     r14, [r9+28h]
0x392983: 498B9EF0000000                   mov     rbx, [r14+0F0h]
0x3929F1: 4D8BBEA8000000                   mov     r15, [r14+0A8h]
0x06D4CB: 480FB6DB                         movzx   rbx, bl
0x06D5A4: 498B4928                         mov     rcx, [r9+28h]
0x392AC2: 0FAE9190000000                   ldmxcsr dword ptr [rcx+90h]
0x392B27: 49BB5321D9F000000000             mov     r11, 0F0D92153h
0x392B93: 4981C36D51304F                   add     r11, 4F30516Dh
0x06D5C0: 4D8B5B40                         mov     r11, [r11+40h]
0x392BFD: 4C039990000000                   add     r11, [rcx+90h]
0x06D5CB: 458A23                           mov     r12b, [r11]
0x06D5CE: 4D0FB6E4                         movzx   r12, r12b
0x06D5D2: 49C1E408                         shl     r12, 8
0x392C6B: 4C29A1F0000000                   sub     [rcx+0F0h], r12
0x392CD5: 48BB1C5160E700000000             mov     rbx, 0E760511Ch
0x06D5E7: 53                               push    rbx
0x06D5E8: 689E25A345                       push    45A3259Eh
0x06D5ED: 681B228A23                       push    238A221Bh
0x06D5F2: 6869353A6D                       push    6D3A3569h
0x392D41: 4881442418A419A958               add     qword ptr [rsp+18h], 58A919A4h
0x06D600: 498B7928                         mov     rdi, [r9+28h]
0x392DAD: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x06D6F7: 4D8B6128                         mov     r12, [r9+28h]
0x392E7F: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x392EE4: 4D8BB424D0000000                 mov     r14, [r12+0D0h]
0x392F4D: 4D8BBC24B0000000                 mov     r15, [r12+0B0h]
0x06D7F3: 498B7128                         mov     rsi, [r9+28h]
0x39301E: 488BAEF0000000                   mov     rbp, [rsi+0F0h]
0x06D7FE: 8B7E34                           mov     edi, [rsi+34h]
0x39308C: 4803BEE8000000                   add     rdi, [rsi+0E8h]
0x06D808: 448A0F                           mov     r9b, [rdi]
0x06D80B: 4488CD                           mov     bpl, r9b
0x06D8F7: 4D8B5128                         mov     r10, [r9+28h]
0x393160: 4D8BAAA0000000                   mov     r13, [r10+0A0h]
0x06D902: 4155                             push    r13
0x06D904: 4889E3                           mov     rbx, rsp
0x3931CD: 498BBAA0000000                   mov     rdi, [r10+0A0h]
0x06DA01: 498B5928                         mov     rbx, [r9+28h]
0x39329F: 4C8BBBC8000000                   mov     r15, [rbx+0C8h]
0x39330D: 488B9BB0000000                   mov     rbx, [rbx+0B0h]
0x06DA13: 4D0FB6FF                         movzx   r15, r15b
0x06DB01: 498B6928                         mov     rbp, [r9+28h]
0x3933DC: 0FAE95F0000000                   ldmxcsr dword ptr [rbp+0F0h]
0x393449: 49BB47619B2B01000000             mov     r11, 12B9B6147h
0x3934B2: 4981C379116E14                   add     r11, 146E1179h
0x393517: 4D8B9B88010000                   mov     r11, [r11+188h]
0x393580: 4C039DF0000000                   add     r11, [rbp+0F0h]
0x06DB2B: 458A2B                           mov     r13b, [r11]
0x06DB2E: 4D0FB6ED                         movzx   r13, r13b
0x06DB32: 49C1E510                         shl     r13, 10h
0x3935EC: 4C29AD90000000                   sub     [rbp+90h], r13
0x06DB3D: 4D8B5128                         mov     r10, [r9+28h]
0x393654: 4D8BAA90000000                   mov     r13, [r10+90h]
0x3936BF: 49BCBC4224C700000000             mov     r12, 0C72442BCh
0x393729: 4981C40428E578                   add     r12, 78E52804h
0x06DC57: 4D8B6128                         mov     r12, [r9+28h]
0x3937FE: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x06DC61: 498B742478                       mov     rsi, [r12+78h]
0x393864: 4D8BA424E0000000                 mov     r12, [r12+0E0h]
0x06DD43: 4D8B5928                         mov     r11, [r9+28h]
0x393935: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x06DD4E: 458B5334                         mov     r10d, [r11+34h]
0x3939A2: 4D0393A8000000                   add     r10, [r11+0A8h]
0x06DD59: 458A0A                           mov     r9b, [r10]
0x393A0F: 48C7C0FF000000                   mov     rax, 0FFh
0x06DD63: 48C1E008                         shl     rax, 8
0x06DD67: 48F7D0                           not     rax
0x06DD6A: 4921C6                           and     r14, rax
0x06DD6D: 490FB6C1                         movzx   rax, r9b
0x06DD71: 48C1E008                         shl     rax, 8
0x06DD75: 4909C6                           or      r14, rax
0x06DE42: 4D8B6928                         mov     r13, [r9+28h]
0x393AE0: 4D8BB5E8000000                   mov     r14, [r13+0E8h]
0x06DE4D: 4156                             push    r14
0x06DE4F: 4989E6                           mov     r14, rsp
0x393B45: 4D8BADE8000000                   mov     r13, [r13+0E8h]
0x06DF44: 498B5928                         mov     rbx, [r9+28h]
0x06DF48: 4C8B7B78                         mov     r15, [rbx+78h]
0x393C1A: 488BBBE0000000                   mov     rdi, [rbx+0E0h]
0x06DF53: 4D0FB6FF                         movzx   r15, r15b
0x06E03D: 4D8B5128                         mov     r10, [r9+28h]
0x393CE2: 410FAE92F0000000                 ldmxcsr dword ptr [r10+0F0h]
0x393D49: 48BB953E90F600000000             mov     rbx, 0F6903E95h
0x393DB4: 4881C32B347949                   add     rbx, 4979342Bh
0x393E1C: 488B9B58060000                   mov     rbx, [rbx+658h]
0x393E84: 49039AF0000000                   add     rbx, [r10+0F0h]
0x06E068: 408A3B                           mov     dil, [rbx]
0x06E06B: 480FB6FF                         movzx   rdi, dil
0x06E06F: 48C1E718                         shl     rdi, 18h
0x393EEC: 4929BAB0000000                   sub     [r10+0B0h], rdi
0x06E07A: 498B6928                         mov     rbp, [r9+28h]
0x393F57: 4C8BADB0000000                   mov     r13, [rbp+0B0h]
0x393FBE: 49BE8D26C7F100000000             mov     r14, 0F1C7268Dh
0x394027: 4981C63344424E                   add     r14, 4E424433h
0x06E185: 4D8B4928                         mov     r9, [r9+28h]
0x06E189: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x394100: 4D8BA9A8000000                   mov     r13, [r9+0A8h]
0x394169: 498BA9E0000000                   mov     rbp, [r9+0E0h]
0x06E282: 498B4928                         mov     rcx, [r9+28h]
0x394236: 488BA9A0000000                   mov     rbp, [rcx+0A0h]
0x06E28D: 8B7934                           mov     edi, [rcx+34h]
0x39429C: 4803B9E0000000                   add     rdi, [rcx+0E0h]
0x06E297: 448A1F                           mov     r11b, [rdi]
0x394306: 49C7C1FF000000                   mov     r9, 0FFh
0x06E2A1: 49C1E110                         shl     r9, 10h
0x06E2A5: 49F7D1                           not     r9
0x06E2A8: 4C21CD                           and     rbp, r9
0x06E2AB: 4D0FB6CB                         movzx   r9, r11b
0x06E2AF: 49C1E110                         shl     r9, 10h
0x06E2B3: 4C09CD                           or      rbp, r9
0x06E393: 498B6928                         mov     rbp, [r9+28h]
0x3943D6: 4C8B95A0000000                   mov     r10, [rbp+0A0h]
0x06E39E: 4152                             push    r10
0x06E3A0: 4889E3                           mov     rbx, rsp
0x39443D: 4C8BB5A0000000                   mov     r14, [rbp+0A0h]
0x06E488: 4D8B4928                         mov     r9, [r9+28h]
0x06E48C: 4D8B7178                         mov     r14, [r9+78h]
0x394513: 498BB1E8000000                   mov     rsi, [r9+0E8h]
0x06E497: 4D0FB6F6                         movzx   r14, r14b
0x06E585: 4D8B6928                         mov     r13, [r9+28h]
0x3945E8: 410FAE95E8000000                 ldmxcsr dword ptr [r13+0E8h]
0x394655: 49BF711B7F0C01000000             mov     r15, 10C7F1B71h
0x3946C2: 4981C74F578A33                   add     r15, 338A574Fh
0x39472A: 4D8BBF90060000                   mov     r15, [r15+690h]
0x394795: 4D03BDE8000000                   add     r15, [r13+0E8h]
0x06E5B0: 458A1F                           mov     r11b, [r15]
0x06E5B3: 4D0FB6DB                         movzx   r11, r11b
0x06E5B7: 49C1E320                         shl     r11, 20h
0x3947FB: 4D299DA8000000                   sub     [r13+0A8h], r11
0x06E5C2: 4D8B6128                         mov     r12, [r9+28h]
0x394867: 4D8BA424A8000000                 mov     r12, [r12+0A8h]
0x3948D3: 48BE0BF06F1E01000000             mov     rsi, 11E6FF00Bh
0x39493D: 4881C6B57A9921                   add     rsi, 21997AB5h
0x06E6C4: 4D8B4928                         mov     r9, [r9+28h]
0x06E6C8: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x394A0F: 498BB1B8000000                   mov     rsi, [r9+0B8h]
0x394A77: 498BB9D8000000                   mov     rdi, [r9+0D8h]
0x06E7C6: 498B4928                         mov     rcx, [r9+28h]
0x394B4C: 488BB1B0000000                   mov     rsi, [rcx+0B0h]
0x06E7D1: 448B6134                         mov     r12d, [rcx+34h]
0x394BB9: 4C03A1A8000000                   add     r12, [rcx+0A8h]
0x06E7DC: 418A3C24                         mov     dil, [r12]
0x394C25: 49C7C5FF000000                   mov     r13, 0FFh
0x06E7E7: 49C1E518                         shl     r13, 18h
0x06E7EB: 49F7D5                           not     r13
0x06E7EE: 4C21EE                           and     rsi, r13
0x06E7F1: 4C0FB6EF                         movzx   r13, dil
0x06E7F5: 49C1E518                         shl     r13, 18h
0x06E7F9: 4C09EE                           or      rsi, r13
0x06E8D7: 4D8B5128                         mov     r10, [r9+28h]
0x394CF5: 498BAAA8000000                   mov     rbp, [r10+0A8h]
0x06E8E2: 55                               push    rbp
0x06E8E3: 4889E7                           mov     rdi, rsp
0x394D5D: 498BB2A8000000                   mov     rsi, [r10+0A8h]
0x06E9C9: 4D8B5128                         mov     r10, [r9+28h]
0x394E2E: 498BBAB0000000                   mov     rdi, [r10+0B0h]
0x394E98: 498B9AA8000000                   mov     rbx, [r10+0A8h]
0x06E9DB: 57                               push    rdi
0x06E9DC: 68B85F1623                       push    23165FB8h
0x06E9E1: 68AC738409                       push    98473ACh
0x06E9E6: 681F6A1477                       push    77146A1Fh
0x06EAC2: 498B4928                         mov     rcx, [r9+28h]
0x394F61: 4C8BB9F0000000                   mov     r15, [rcx+0F0h]
0x394FCC: 488B9990000000                   mov     rbx, [rcx+90h]
0x06EAD4: 4D0FB6FF                         movzx   r15, r15b
0x06EBB5: 498B7928                         mov     rdi, [r9+28h]
0x39509E: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x39510A: 48BAFFF4F43A01000000             mov     rdx, 13AF4F4FFh
0x395176: 4881C2C17D1405                   add     rdx, 5147DC1h
0x06EBD1: 488B12                           mov     rdx, [rdx]
0x3951DB: 480397F0000000                   add     rdx, [rdi+0F0h]
0x06EBDB: 448A32                           mov     r14b, [rdx]
0x06EBDE: 4D0FB6F6                         movzx   r14, r14b
0x06EBE2: 49C1E638                         shl     r14, 38h
0x395246: 4C29B790000000                   sub     [rdi+90h], r14
0x3952B0: 48BA4BF6BC2B01000000             mov     rdx, 12BBCF64Bh
0x06EBF7: 52                               push    rdx
0x06EBF8: 68A30D397F                       push    7F390DA3h
0x06EBFD: 6816195329                       push    29531916h
0x06EC02: 681022AC32                       push    32AC2210h
0x39531E: 488144241875744C14               add     qword ptr [rsp+18h], 144C7475h
0x06EC10: 4D8B4928                         mov     r9, [r9+28h]
0x39538D: 498BA990000000                   mov     rbp, [r9+90h]
0x06ED04: 4D8B4928                         mov     r9, [r9+28h]
0x06ED08: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x395461: 498B99C0000000                   mov     rbx, [r9+0C0h]
0x3954CF: 498BB1A0000000                   mov     rsi, [r9+0A0h]
0x06EE06: 4D8B5928                         mov     r11, [r9+28h]
0x3955A1: 498BB3A8000000                   mov     rsi, [r11+0A8h]
0x06EE11: 458B4334                         mov     r8d, [r11+34h]
0x395609: 4D038390000000                   add     r8, [r11+90h]
0x06EE1C: 458A20                           mov     r12b, [r8]
0x395674: 48C7C5FF000000                   mov     rbp, 0FFh
0x06EE26: 48C1E530                         shl     rbp, 30h
0x06EE2A: 48F7D5                           not     rbp
0x06EE2D: 4821EE                           and     rsi, rbp
0x06EE30: 490FB6EC                         movzx   rbp, r12b
0x06EE34: 48C1E530                         shl     rbp, 30h
0x06EE38: 4809EE                           or      rsi, rbp
0x06EF0F: 498B5128                         mov     rdx, [r9+28h]
0x395744: 4C8BAAA8000000                   mov     r13, [rdx+0A8h]
0x06EF1A: 4155                             push    r13
0x06EF1C: 4889E3                           mov     rbx, rsp
0x3957AA: 488BB2A8000000                   mov     rsi, [rdx+0A8h]
0x06F018: 4D8B5928                         mov     r11, [r9+28h]
0x06F01C: 498B5B78                         mov     rbx, [r11+78h]
0x39587C: 4D8BBBA8000000                   mov     r15, [r11+0A8h]
0x06F027: 480FB6DB                         movzx   rbx, bl
0x06F113: 4D8B4128                         mov     r8, [r9+28h]
0x395949: 410FAE9090000000                 ldmxcsr dword ptr [r8+90h]
0x3959B8: 48BAB01852DD00000000             mov     rdx, 0DD5218B0h
0x395A21: 4881C2105AB762                   add     rdx, 62B75A10h
0x395A8A: 488B9200040000                   mov     rdx, [rdx+400h]
0x395AEF: 49039090000000                   add     rdx, [r8+90h]
0x06F13E: 408A3A                           mov     dil, [rdx]
0x06F141: 480FB6FF                         movzx   rdi, dil
0x06F145: 48C1E708                         shl     rdi, 8
0x395B5B: 4929B8F0000000                   sub     [r8+0F0h], rdi
0x06F150: 4D8B4128                         mov     r8, [r9+28h]
0x395BC2: 498BA8F0000000                   mov     rbp, [r8+0F0h]
0x395C27: 48BE9649703A01000000             mov     rsi, 13A704996h
0x395C91: 4881C62A219905                   add     rsi, 599212Ah
0x06F24D: 498B7128                         mov     rsi, [r9+28h]
0x06F251: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x395D5F: 488BBEC0000000                   mov     rdi, [rsi+0C0h]
0x395DCD: 488B9EA0000000                   mov     rbx, [rsi+0A0h]
0x06F32A: 4D8B7928                         mov     r15, [r9+28h]
0x395E97: 4D8BAF90000000                   mov     r13, [r15+90h]
0x06F335: 418B4734                         mov     eax, [r15+34h]
0x395EFF: 490387B0000000                   add     rax, [r15+0B0h]
0x06F340: 448A18                           mov     r11b, [rax]
0x06F343: 4588DD                           mov     r13b, r11b
0x06F424: 4D8B4128                         mov     r8, [r9+28h]
0x395FD8: 4D8B90E0000000                   mov     r10, [r8+0E0h]
0x06F42F: 4152                             push    r10
0x06F431: 4889E5                           mov     rbp, rsp
0x39603F: 498B98E0000000                   mov     rbx, [r8+0E0h]
0x06F52A: 498B4128                         mov     rax, [r9+28h]
0x39610D: 4C8B88A0000000                   mov     r9, [rax+0A0h]
0x39617B: 4C8BA890000000                   mov     r13, [rax+90h]
0x06F53C: 4151                             push    r9
0x06F53E: 68EA06DE30                       push    30DE06EAh
0x06F543: 681A6F4C1C                       push    1C4C6F1Ah
0x06F548: 6877485B26                       push    265B4877h
0x06F63E: 4D8B5928                         mov     r11, [r9+28h]
0x39624A: 4D8BAB90000000                   mov     r13, [r11+90h]
0x3962B6: 498BABE0000000                   mov     rbp, [r11+0E0h]
0x06F650: 4D0FB6ED                         movzx   r13, r13b
0x06F73A: 4D8B6928                         mov     r13, [r9+28h]
0x396384: 410FAE95E0000000                 ldmxcsr dword ptr [r13+0E0h]
0x3963ED: 49B88F0538E700000000             mov     r8, 0E738058Fh
0x396458: 4981C0316DD158                   add     r8, 58D16D31h
0x3964BE: 4D8B8080040000                   mov     r8, [r8+480h]
0x396523: 4D0385E0000000                   add     r8, [r13+0E0h]
0x06F765: 418A10                           mov     dl, [r8]
0x06F768: 480FB6D2                         movzx   rdx, dl
0x06F76C: 48C1E210                         shl     rdx, 10h
0x396591: 492995A0000000                   sub     [r13+0A0h], rdx
0x3965FE: 48BEAA1601FA00000000             mov     rsi, 0FA0116AAh
0x06F781: 56                               push    rsi
0x06F782: 68B27EE930                       push    30E97EB2h
0x06F787: 68942ED43D                       push    3DD42E94h
0x06F78C: 68BF67AA51                       push    51AA67BFh
0x06F791: 68C200207C                       push    7C2000C2h
0x39666C: 488144242016540846               add     qword ptr [rsp+20h], 46085416h
0x06F79F: 498B7128                         mov     rsi, [r9+28h]
0x3966D8: 4C8BBEA0000000                   mov     r15, [rsi+0A0h]
0x06F89A: 498B7928                         mov     rdi, [r9+28h]
0x06F89E: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x3967A2: 488B9FD0000000                   mov     rbx, [rdi+0D0h]
0x396808: 4C8BA7F0000000                   mov     r12, [rdi+0F0h]
0x06F99B: 498B7928                         mov     rdi, [r9+28h]
0x3968E2: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x06F9A6: 448B5734                         mov     r10d, [rdi+34h]
0x396950: 4C039790000000                   add     r10, [rdi+90h]
0x06F9B1: 458A3A                           mov     r15b, [r10]
0x3969B5: 48C7C3FF000000                   mov     rbx, 0FFh
0x06F9BB: 48C1E308                         shl     rbx, 8
0x06F9BF: 48F7D3                           not     rbx
0x06F9C2: 4921DD                           and     r13, rbx
0x06F9C5: 490FB6DF                         movzx   rbx, r15b
0x06F9C9: 48C1E308                         shl     rbx, 8
0x06F9CD: 4909DD                           or      r13, rbx
0x06FAAD: 4D8B5128                         mov     r10, [r9+28h]
0x396A89: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x06FAB8: 53                               push    rbx
0x06FAB9: 4989E4                           mov     r12, rsp
0x396AF3: 498BAAE0000000                   mov     rbp, [r10+0E0h]
0x06FB9C: 4D8B4128                         mov     r8, [r9+28h]
0x396BC9: 498B90D8000000                   mov     rdx, [r8+0D8h]
0x396C36: 4D8BB8A0000000                   mov     r15, [r8+0A0h]
0x06FBAE: 52                               push    rdx
0x06FBAF: 688B35D411                       push    11D4358Bh
0x06FBB4: 683D412854                       push    5428413Dh
0x06FBB9: 68202E7D45                       push    457D2E20h
0x06FCA2: 4D8B7128                         mov     r14, [r9+28h]
0x396D09: 4D8BAEE8000000                   mov     r13, [r14+0E8h]
0x396D70: 4D8BA6F0000000                   mov     r12, [r14+0F0h]
0x06FCB4: 4D0FB6ED                         movzx   r13, r13b
0x06FD85: 4D8B5128                         mov     r10, [r9+28h]
0x396E41: 410FAE92E0000000                 ldmxcsr dword ptr [r10+0E0h]
0x396EAF: 48BD9344F41C01000000             mov     rbp, 11CF44493h
0x396F1E: 4881C52D2E1523                   add     rbp, 23152E2Dh
0x396F89: 488BAD38070000                   mov     rbp, [rbp+738h]
0x396FF3: 4903AAE0000000                   add     rbp, [r10+0E0h]
0x06FDB0: 8A5500                           mov     dl, [rbp+0]
0x06FDB3: 480FB6D2                         movzx   rdx, dl
0x06FDB7: 48C1E218                         shl     rdx, 18h
0x39705C: 492992D8000000                   sub     [r10+0D8h], rdx
0x3970C8: 49BDAB30AAD100000000             mov     r13, 0D1AA30ABh
0x06FDCC: 4155                             push    r13
0x06FDCE: 686D563418                       push    1834566Dh
0x06FDD3: 68FD0A7958                       push    58790AFDh
0x06FDD8: 68F1537375                       push    757353F1h
0x397132: 4881442418153A5F6E               add     [rsp-8+arg_18], 6E5F3A15h
0x06FDE6: 4D8B4128                         mov     r8, [r9+28h]
0x39719B: 4D8BB0D8000000                   mov     r14, [r8+0D8h]
0x06FEDF: 4D8B5128                         mov     r10, [r9+28h]
0x06FEE3: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x397264: 498BBAB0000000                   mov     rdi, [r10+0B0h]
0x3972CD: 498BB2E8000000                   mov     rsi, [r10+0E8h]
0x06FFE2: 498B4128                         mov     rax, [r9+28h]
0x3973A1: 4C8BA8A8000000                   mov     r13, [rax+0A8h]
0x06FFED: 448B4034                         mov     r8d, [rax+34h]
0x397407: 4C0380B0000000                   add     r8, [rax+0B0h]
0x06FFF8: 458A30                           mov     r14b, [r8]
0x397472: 49C7C4FF000000                   mov     r12, 0FFh
0x070002: 49C1E410                         shl     r12, 10h
0x070006: 49F7D4                           not     r12
0x070009: 4D21E5                           and     r13, r12
0x07000C: 4D0FB6E6                         movzx   r12, r14b
0x070010: 49C1E410                         shl     r12, 10h
0x070014: 4D09E5                           or      r13, r12
0x0700F3: 4D8B6928                         mov     r13, [r9+28h]
0x397548: 498BBDE0000000                   mov     rdi, [r13+0E0h]
0x0700FE: 57                               push    rdi
0x0700FF: 4989E4                           mov     r12, rsp
0x3975AD: 4D8BADE0000000                   mov     r13, [r13+0E0h]
0x0701E9: 4D8B4928                         mov     r9, [r9+28h]
0x39767E: 498B81D8000000                   mov     rax, [r9+0D8h]
0x3976EA: 498B99E0000000                   mov     rbx, [r9+0E0h]
0x0701FB: 50                               push    rax
0x0701FC: 686400D658                       push    58D60064h
0x070201: 68D27BDC62                       push    62DC7BD2h
0x070206: 68F17E8633                       push    33867EF1h
0x0702F8: 498B5928                         mov     rbx, [r9+28h]
0x3977B6: 4C8BB3A8000000                   mov     r14, [rbx+0A8h]
0x397823: 488BAB90000000                   mov     rbp, [rbx+90h]
0x07030A: 4D0FB6F6                         movzx   r14, r14b
0x0703E4: 4D8B6928                         mov     r13, [r9+28h]
0x3978F1: 410FAE95E8000000                 ldmxcsr dword ptr [r13+0E8h]
0x397960: 49B841F756EA00000000             mov     r8, 0EA56F741h
0x3979CC: 4981C07F7BB255                   add     r8, 55B27B7Fh
0x070401: 4D8B4008                         mov     r8, [r8+8]
0x397A33: 4D0385E8000000                   add     r8, [r13+0E8h]
0x07040C: 418A18                           mov     bl, [r8]
0x07040F: 480FB6DB                         movzx   rbx, bl
0x070413: 48C1E328                         shl     rbx, 28h
0x397A9E: 49299DA0000000                   sub     [r13+0A0h], rbx
0x07041E: 4D8B6928                         mov     r13, [r9+28h]
0x397B0A: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x397B73: 48BB8FEE862801000000             mov     rbx, 12886EE8Fh
0x397BDE: 4881C3317C8217                   add     rbx, 17827C31h
0x070520: 498B5128                         mov     rdx, [r9+28h]
0x070524: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x397CA7: 4C8BBAC0000000                   mov     r15, [rdx+0C0h]
0x397D0E: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x070612: 4D8B7928                         mov     r15, [r9+28h]
0x397DE1: 4D8BAFD8000000                   mov     r13, [r15+0D8h]
0x07061D: 418B4F34                         mov     ecx, [r15+34h]
0x397E4C: 49038FF0000000                   add     rcx, [r15+0F0h]
0x070628: 448A19                           mov     r11b, [rcx]
0x397EB3: 49C7C4FF000000                   mov     r12, 0FFh
0x070632: 49C1E420                         shl     r12, 20h
0x070636: 49F7D4                           not     r12
0x070639: 4D21E5                           and     r13, r12
0x07063C: 4D0FB6E3                         movzx   r12, r11b
0x070640: 49C1E420                         shl     r12, 20h
0x070644: 4D09E5                           or      r13, r12
0x070723: 4D8B7928                         mov     r15, [r9+28h]
0x397F7F: 4D8BA7E0000000                   mov     r12, [r15+0E0h]
0x07072E: 4154                             push    r12
0x070730: 4889E7                           mov     rdi, rsp
0x397FE4: 4D8BAFE0000000                   mov     r13, [r15+0E0h]
0x07082A: 498B4928                         mov     rcx, [r9+28h]
0x3980B1: 488BB1B8000000                   mov     rsi, [rcx+0B8h]
0x39811C: 488BA9E0000000                   mov     rbp, [rcx+0E0h]
0x07083C: 480FB6F6                         movzx   rsi, sil
0x07091D: 498B6928                         mov     rbp, [r9+28h]
0x3981E8: 0FAE95A8000000                   ldmxcsr dword ptr [rbp+0A8h]
0x39824E: 49BAD549BEFA00000000             mov     r10, 0FABE49D5h
0x070932: 4152                             push    r10
0x070934: 681233FC12                       push    12FC3312h
0x070939: 68B009A96B                       push    6BA909B0h
0x07093E: 6830173875                       push    75381730h
0x070943: 683009564C                       push    4C560930h
0x3982B9: 4881442420EB204B45               add     qword ptr [rsp+20h], 454B20EBh
0x070951: 4D8B7928                         mov     r15, [r9+28h]
0x398324: 4D8BBFA0000000                   mov     r15, [r15+0A0h]
0x070A33: 498B6928                         mov     rbp, [r9+28h]
0x070A37: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x3983F5: 488B9DB8000000                   mov     rbx, [rbp+0B8h]
0x398462: 4C8BBDF0000000                   mov     r15, [rbp+0F0h]
0x070B37: 4D8B4928                         mov     r9, [r9+28h]
0x39853B: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x070B42: 418B4934                         mov     ecx, [r9+34h]
0x3985A3: 49038990000000                   add     rcx, [r9+90h]
0x070B4D: 8A19                             mov     bl, [rcx]
0x39860D: 49C7C7FF000000                   mov     r15, 0FFh
0x070B56: 49C1E738                         shl     r15, 38h
0x070B5A: 49F7D7                           not     r15
0x070B5D: 4C21FF                           and     rdi, r15
0x070B60: 4C0FB6FB                         movzx   r15, bl
0x070B64: 49C1E738                         shl     r15, 38h
0x070B68: 4C09FF                           or      rdi, r15
0x070C4B: 4D8B6928                         mov     r13, [r9+28h]
0x3986DD: 4D8B9DB0000000                   mov     r11, [r13+0B0h]
0x070C56: 4153                             push    r11
0x070C58: 4889E7                           mov     rdi, rsp
0x39874A: 4D8BB5B0000000                   mov     r14, [r13+0B0h]
0x070D4B: 498B5928                         mov     rbx, [r9+28h]
0x398820: 4C8B83B0000000                   mov     r8, [rbx+0B0h]
0x398887: 488BABE8000000                   mov     rbp, [rbx+0E8h]
0x070D5D: 4150                             push    r8
0x070D5F: 682C6E3022                       push    22306E2Ch
0x070D64: 68C5009265                       push    659200C5h
0x070D69: 6838241315                       push    15132438h
0x070D6E: 68A2784807                       push    74878A2h
0x070E66: 4D8B7128                         mov     r14, [r9+28h]
0x398954: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x3989BD: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x070E78: 480FB6FF                         movzx   rdi, dil
0x070F67: 498B7928                         mov     rdi, [r9+28h]
0x398A8F: 0FAE97B0000000                   ldmxcsr dword ptr [rdi+0B0h]
0x398AFC: 48BE4AECC4DB00000000             mov     rsi, 0DBC4EC4Ah
0x070F7C: 56                               push    rsi
0x070F7D: 683F5D8C2D                       push    2D8C5D3Fh
0x070F82: 6899638502                       push    2856399h
0x070F87: 68BC00975A                       push    5A9700BCh
0x398B6A: 488144241876564464               add     qword ptr [rsp+18h], 64445676h
0x070F95: 4D8B7128                         mov     r14, [r9+28h]
0x398BD8: 4D8BA690000000                   mov     r12, [r14+90h]
0x07107E: 498B5128                         mov     rdx, [r9+28h]
0x071082: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x398CA9: 488B9AA8000000                   mov     rbx, [rdx+0A8h]
0x398D11: 488BB2D8000000                   mov     rsi, [rdx+0D8h]
0x071173: 498B4128                         mov     rax, [r9+28h]
0x398DE0: 4C8BA8A8000000                   mov     r13, [rax+0A8h]
0x07117E: 8B7034                           mov     esi, [rax+34h]
0x398E49: 4803B090000000                   add     rsi, [rax+90h]
0x071188: 408A36                           mov     sil, [rsi]
0x398EB1: 49C7C4FF000000                   mov     r12, 0FFh
0x071192: 49C1E408                         shl     r12, 8
0x071196: 49F7D4                           not     r12
0x071199: 4D21E5                           and     r13, r12
0x07119C: 4C0FB6E6                         movzx   r12, sil
0x0711A0: 49C1E408                         shl     r12, 8
0x0711A4: 4D09E5                           or      r13, r12
0x07127C: 498B7128                         mov     rsi, [r9+28h]
0x398F89: 4C8B9EE0000000                   mov     r11, [rsi+0E0h]
0x071287: 4153                             push    r11
0x071289: 4889E3                           mov     rbx, rsp
0x398FF2: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x071386: 4D8B7128                         mov     r14, [r9+28h]
0x3990CB: 498BB688000000                   mov     rsi, [r14+88h]
0x399137: 4D8BAEF0000000                   mov     r13, [r14+0F0h]
0x071398: 480FB6F6                         movzx   rsi, sil
0x071485: 498B4928                         mov     rcx, [r9+28h]
0x399209: 0FAE91A8000000                   ldmxcsr dword ptr [rcx+0A8h]
0x399277: 49BE4625912B01000000             mov     r14, 12B912546h
0x07149A: 4156                             push    r14
0x07149C: 68ED517240                       push    407251EDh
0x0714A1: 68A0159233                       push    339215A0h
0x0714A6: 683A42FB59                       push    59FB423Ah
0x0714AB: 68BF5CFE35                       push    35FE5CBFh
0x3992E1: 48814424207A1D7814               add     qword ptr [rsp+20h], 14781D7Ah
0x0714B9: 498B6928                         mov     rbp, [r9+28h]
0x39934A: 4C8BA5E0000000                   mov     r12, [rbp+0E0h]
0x0715AF: 4D8B5128                         mov     r10, [r9+28h]
0x0715B3: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x399422: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x399488: 498BAAD8000000                   mov     rbp, [r10+0D8h]
0x0716A1: 4D8B4928                         mov     r9, [r9+28h]
0x399556: 498BA9A0000000                   mov     rbp, [r9+0A0h]
0x0716AC: 458B4134                         mov     r8d, [r9+34h]
0x3995BC: 4D0381E8000000                   add     r8, [r9+0E8h]
0x0716B7: 458A08                           mov     r9b, [r8]
0x399623: 49C7C6FF000000                   mov     r14, 0FFh
0x0716C1: 49C1E618                         shl     r14, 18h
0x0716C5: 49F7D6                           not     r14
0x0716C8: 4C21F5                           and     rbp, r14
0x0716CB: 4D0FB6F1                         movzx   r14, r9b
0x0716CF: 49C1E618                         shl     r14, 18h
0x0716D3: 4C09F5                           or      rbp, r14
0x0717B1: 498B4128                         mov     rax, [r9+28h]
0x3996F2: 4C8BA0A0000000                   mov     r12, [rax+0A0h]
0x0717BC: 4154                             push    r12
0x0717BE: 4889E3                           mov     rbx, rsp
0x39975B: 4C8BB0A0000000                   mov     r14, [rax+0A0h]
0x0718A3: 4D8B6128                         mov     r12, [r9+28h]
0x39982C: 498B942490000000                 mov     rdx, [r12+90h]
0x399892: 4D8BA424E8000000                 mov     r12, [r12+0E8h]
0x0718B7: 52                               push    rdx
0x0718B8: 6833438316                       push    16834333h
0x0718BD: 68FA514F4E                       push    4E4F51FAh
0x0718C2: 685020C01B                       push    1BC02050h
0x0718C7: 68A5006903                       push    36900A5h
0x0719A0: 498B5928                         mov     rbx, [r9+28h]
0x399965: 488BB3C8000000                   mov     rsi, [rbx+0C8h]
0x3999CD: 4C8BBBD8000000                   mov     r15, [rbx+0D8h]
0x0719B2: 480FB6F6                         movzx   rsi, sil
0x071A9C: 4D8B6128                         mov     r12, [r9+28h]
0x399AA0: 410FAE9424A8000000               ldmxcsr dword ptr [r12+0A8h]
0x399B07: 48B837F67BE500000000             mov     rax, 0E57BF637h
0x071AB3: 50                               push    rax
0x071AB4: 682513A11A                       push    1AA11325h
0x071AB9: 68D524EF46                       push    46EF24D5h
0x071ABE: 687276A85E                       push    5EA87672h
0x071AC3: 689E49152B                       push    2B15499Eh
0x399B72: 4881442420894C8D5A               add     [rsp-8+arg_20], 5A8D4C89h
0x071AD1: 498B7928                         mov     rdi, [r9+28h]
0x399BDE: 488BB7F0000000                   mov     rsi, [rdi+0F0h]
0x071BD1: 498B7928                         mov     rdi, [r9+28h]
0x071BD5: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x399CAB: 4C8BB7C0000000                   mov     r14, [rdi+0C0h]
0x399D13: 4C8BAFA8000000                   mov     r13, [rdi+0A8h]
0x071CCB: 498B7928                         mov     rdi, [r9+28h]
0x399DE3: 4C8BBFE0000000                   mov     r15, [rdi+0E0h]
0x071CD6: 448B7734                         mov     r14d, [rdi+34h]
0x399E50: 4C03B7E8000000                   add     r14, [rdi+0E8h]
0x071CE1: 458A06                           mov     r8b, [r14]
0x399EBE: 49C7C4FF000000                   mov     r12, 0FFh
0x071CEB: 49C1E420                         shl     r12, 20h
0x071CEF: 49F7D4                           not     r12
0x071CF2: 4D21E7                           and     r15, r12
0x071CF5: 4D0FB6E0                         movzx   r12, r8b
0x071CF9: 49C1E420                         shl     r12, 20h
0x071CFD: 4D09E7                           or      r15, r12
0x071DF0: 498B6928                         mov     rbp, [r9+28h]
0x399F93: 4C8BADF0000000                   mov     r13, [rbp+0F0h]
0x071DFB: 4155                             push    r13
0x071DFD: 4989E6                           mov     r14, rsp
0x399FFF: 4C8BBDF0000000                   mov     r15, [rbp+0F0h]
0x071EEB: 498B5128                         mov     rdx, [r9+28h]
0x39A0CA: 488BB2C8000000                   mov     rsi, [rdx+0C8h]
0x39A132: 488B9AF0000000                   mov     rbx, [rdx+0F0h]
0x071EFD: 480FB6F6                         movzx   rsi, sil
0x071FE7: 4D8B6928                         mov     r13, [r9+28h]
0x39A1FF: 410FAE95A8000000                 ldmxcsr dword ptr [r13+0A8h]
0x071FF3: 4D8B4128                         mov     r8, [r9+28h]
0x39A268: 4D8BB890000000                   mov     r15, [r8+90h]
0x39A2CD: 48BF50F5080701000000             mov     rdi, 10708F550h
0x39A33D: 4881C7704D0039                   add     rdi, 39004D70h
0x0720E3: 4D8B5928                         mov     r11, [r9+28h]
0x0720E7: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x39A40A: 4D8BB3B8000000                   mov     r14, [r11+0B8h]
0x39A475: 4D8BBBF0000000                   mov     r15, [r11+0F0h]
0x0721D4: 4D8B5128                         mov     r10, [r9+28h]
0x39A53E: 4D8BBAF0000000                   mov     r15, [r10+0F0h]
0x0721DF: 418B4A34                         mov     ecx, [r10+34h]
0x39A5A8: 49038AE8000000                   add     rcx, [r10+0E8h]
0x0721EA: 408A39                           mov     dil, [rcx]
0x39A612: 48C7C0FF000000                   mov     rax, 0FFh
0x0721F4: 48C1E028                         shl     rax, 28h
0x0721F8: 48F7D0                           not     rax
0x0721FB: 4921C7                           and     r15, rax
0x0721FE: 480FB6C7                         movzx   rax, dil
0x072202: 48C1E028                         shl     rax, 28h
0x072206: 4909C7                           or      r15, rax
0x0722EF: 498B5928                         mov     rbx, [r9+28h]
0x39A6E1: 4C8BBBF0000000                   mov     r15, [rbx+0F0h]
0x39A749: 49BC5FD5800B01000000             mov     r12, 10B80D55Fh
0x39A7B9: 4981C4913C7F34                   add     r12, 347F3C91h
0x07230B: 4D85FF                           test    r15, r15
0x39A81F: 4C8D3DF67ACDFF                   lea     r15, unk_6A9231C
0x072315: 4D0F45FC                         cmovnz  r15, r12
