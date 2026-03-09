0x30A488: 49BF288F5A0001000000             mov     r15, 1005A8F28h
0x30A4F2: 4981C7C0292F40                   add     r15, 402F29C0h
0x017C0C: 498B7928                         mov     rdi, [r9+28h]
0x30A5C9: 4C8BB7B0000000                   mov     r14, [rdi+0B0h]
0x017C17: 4D0FB6F6                         movzx   r14, r14b
0x017CF1: 498B7928                         mov     rdi, [r9+28h]
0x30A698: 488B87E8000000                   mov     rax, [rdi+0E8h]
0x30A706: 48C7C2EE5D8CC4                   mov     rdx, 0FFFFFFFFC48C5DEEh
0x30A76C: 4881C2934C0D3C                   add     rdx, 3C0D4C93h
0x017D0A: 52                               push    rdx
0x017D0B: 48F72424                         mul     qword ptr [rsp]
0x017D0F: 4989C5                           mov     r13, rax
0x017E01: 498B5928                         mov     rbx, [r9+28h]
0x30A83A: 4C8BBBE0000000                   mov     r15, [rbx+0E0h]
0x017E0C: 4157                             push    r15
0x017E0E: 4889E7                           mov     rdi, rsp
0x30A8A6: 4C8BBBE0000000                   mov     r15, [rbx+0E0h]
0x017F01: 498B6928                         mov     rbp, [r9+28h]
0x30A97B: 488BB580000000                   mov     rsi, [rbp+80h]
0x30A9E1: 4C8BB5F0000000                   mov     r14, [rbp+0F0h]
0x017F13: 480FB6F6                         movzx   rsi, sil
0x017FF6: 498B5928                         mov     rbx, [r9+28h]
0x30AAAB: 0FAE93A8000000                   ldmxcsr dword ptr [rbx+0A8h]
0x30AB14: 48BEFF3B632101000000             mov     rsi, 121633BFFh
0x30AB7C: 4881C6C136A61E                   add     rsi, 1EA636C1h
0x30ABE5: 488BB688020000                   mov     rsi, [rsi+288h]
0x30AC52: 4803B3A8000000                   add     rsi, [rbx+0A8h]
0x018020: 448A26                           mov     r12b, [rsi]
0x018023: 4D0FB6E4                         movzx   r12, r12b
0x018027: 49C1E408                         shl     r12, 8
0x30ACBD: 4C29A3E8000000                   sub     [rbx+0E8h], r12
0x30AD29: 48BD4D19841401000000             mov     rbp, 11484194Dh
0x01803C: 55                               push    rbp
0x01803D: 68EC60CF0F                       push    0FCF60ECh
0x018042: 681008FC79                       push    79FC0810h
0x018047: 68E2172618                       push    182617E2h
0x01804C: 68B2159B17                       push    179B15B2h
0x30AD94: 48814424207351852B               add     [rsp-8+arg_20], 2B855173h
0x01805A: 498B5128                         mov     rdx, [r9+28h]
0x30AE04: 488B9AE8000000                   mov     rbx, [rdx+0E8h]
0x01814A: 4D8B6928                         mov     r13, [r9+28h]
0x01814E: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x30AEDB: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x30AF47: 4D8BBD90000000                   mov     r15, [r13+90h]
0x018240: 498B5928                         mov     rbx, [r9+28h]
0x30B01F: 488BBBF0000000                   mov     rdi, [rbx+0F0h]
0x01824B: 448B6B34                         mov     r13d, [rbx+34h]
0x30B08D: 4C03ABB0000000                   add     r13, [rbx+0B0h]
0x018256: 458A6D00                         mov     r13b, [r13+0]
0x01825A: 4488EF                           mov     dil, r13b
0x01834B: 498B7928                         mov     rdi, [r9+28h]
0x30B15E: 4C8BAFB0000000                   mov     r13, [rdi+0B0h]
0x018356: 4155                             push    r13
0x018358: 4989E7                           mov     r15, rsp
0x30B1C6: 4C8BA7B0000000                   mov     r12, [rdi+0B0h]
0x018446: 4D8B6928                         mov     r13, [r9+28h]
0x30B29C: 4D8BA5F0000000                   mov     r12, [r13+0F0h]
0x30B306: 498B9DD8000000                   mov     rbx, [r13+0D8h]
0x018458: 4154                             push    r12
0x01845A: 68C6024623                       push    234602C6h
0x01845F: 686E313426                       push    2634316Eh
0x018464: 68965F044C                       push    4C045F96h
0x01856C: 4D8B7928                         mov     r15, [r9+28h]
0x30B3D3: 4D8BB7B8000000                   mov     r14, [r15+0B8h]
0x30B43F: 4D8BA790000000                   mov     r12, [r15+90h]
0x01857E: 4D0FB6F6                         movzx   r14, r14b
0x01866B: 4D8B4128                         mov     r8, [r9+28h]
0x30B50F: 410FAE90E8000000                 ldmxcsr dword ptr [r8+0E8h]
0x30B57A: 48B91C693B0101000000             mov     rcx, 1013B691Ch
0x30B5E4: 4881C1A409CE3E                   add     rcx, 3ECE09A4h
0x30B649: 488B8950070000                   mov     rcx, [rcx+750h]
0x30B6B1: 490388E8000000                   add     rcx, [r8+0E8h]
0x018696: 408A39                           mov     dil, [rcx]
0x018699: 480FB6FF                         movzx   rdi, dil
0x01869D: 48C1E710                         shl     rdi, 10h
0x30B71F: 4929B8D8000000                   sub     [r8+0D8h], rdi
0x30B789: 49BBECECEE1401000000             mov     r11, 114EEECECh
0x0186B2: 4153                             push    r11
0x0186B4: 68F9337A41                       push    417A33F9h
0x0186B9: 680E52BD20                       push    20BD520Eh
0x0186BE: 6860709557                       push    57957060h
0x0186C3: 68206B7878                       push    78786B20h
0x30B7F3: 4881442420D47D1A2B               add     [rsp-8+arg_20], 2B1A7DD4h
0x0186D1: 4D8B4928                         mov     r9, [r9+28h]
0x30B85C: 4D8BA9D8000000                   mov     r13, [r9+0D8h]
0x0187C2: 4D8B6928                         mov     r13, [r9+28h]
0x0187C6: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x30B931: 4D8BBD90000000                   mov     r15, [r13+90h]
0x30B99A: 498BADE0000000                   mov     rbp, [r13+0E0h]
0x0188BE: 4D8B6928                         mov     r13, [r9+28h]
0x30BA67: 498BADA0000000                   mov     rbp, [r13+0A0h]
0x0188C9: 458B7534                         mov     r14d, [r13+34h]
0x30BACD: 4D03B5F0000000                   add     r14, [r13+0F0h]
0x0188D4: 458A0E                           mov     r9b, [r14]
0x30BB36: 49C7C6FF000000                   mov     r14, 0FFh
0x0188DE: 49C1E608                         shl     r14, 8
0x0188E2: 49F7D6                           not     r14
0x0188E5: 4C21F5                           and     rbp, r14
0x0188E8: 4D0FB6F1                         movzx   r14, r9b
0x0188EC: 49C1E608                         shl     r14, 8
0x0188F0: 4C09F5                           or      rbp, r14
0x0189C6: 4D8B7128                         mov     r14, [r9+28h]
0x30BC06: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x0189D1: 53                               push    rbx
0x0189D2: 4989E7                           mov     r15, rsp
0x30BC73: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x018ABB: 498B5128                         mov     rdx, [r9+28h]
0x30BD3E: 4C8BAA90000000                   mov     r13, [rdx+90h]
0x30BDA5: 488BAAB0000000                   mov     rbp, [rdx+0B0h]
0x018ACD: 4D0FB6ED                         movzx   r13, r13b
0x018BB0: 4D8B7128                         mov     r14, [r9+28h]
0x30BE76: 410FAE96E0000000                 ldmxcsr dword ptr [r14+0E0h]
0x30BEE1: 49BC7244890201000000             mov     r12, 102894472h
0x30BF4D: 4981C44E2E803D                   add     r12, 3D802E4Eh
0x30BFBB: 4D8BA42468070000                 mov     r12, [r12+768h]
0x30C021: 4D03A6E0000000                   add     r12, [r14+0E0h]
0x018BDC: 418A2C24                         mov     bpl, [r12]
0x018BE0: 480FB6ED                         movzx   rbp, bpl
0x018BE4: 48C1E518                         shl     rbp, 18h
0x30C087: 4929AEA0000000                   sub     [r14+0A0h], rbp
0x30C0F5: 49B85D012E1701000000             mov     r8, 1172E015Dh
0x018BF9: 4150                             push    r8
0x018BFB: 688E29D403                       push    3D4298Eh
0x018C00: 68D1529933                       push    339952D1h
0x018C05: 6872320673                       push    73063272h
0x30C166: 48814424186369DB28               add     qword ptr [rsp+18h], 28DB6963h
0x018C13: 4D8B6128                         mov     r12, [r9+28h]
0x30C1D5: 4D8BA424A0000000                 mov     r12, [r12+0A0h]
0x018D0F: 498B6928                         mov     rbp, [r9+28h]
0x018D13: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x30C2A2: 4C8BAD90000000                   mov     r13, [rbp+90h]
0x30C309: 488B9DD8000000                   mov     rbx, [rbp+0D8h]
0x018E0D: 4D8B7928                         mov     r15, [r9+28h]
0x30C3D5: 4D8BA790000000                   mov     r12, [r15+90h]
0x018E18: 418B7F34                         mov     edi, [r15+34h]
0x30C43E: 4903BFE0000000                   add     rdi, [r15+0E0h]
0x018E23: 448A1F                           mov     r11b, [rdi]
0x30C4A6: 49C7C1FF000000                   mov     r9, 0FFh
0x018E2D: 49C1E110                         shl     r9, 10h
0x018E31: 49F7D1                           not     r9
0x018E34: 4D21CC                           and     r12, r9
0x018E37: 4D0FB6CB                         movzx   r9, r11b
0x018E3B: 49C1E110                         shl     r9, 10h
0x018E3F: 4D09CC                           or      r12, r9
0x018F14: 498B7928                         mov     rdi, [r9+28h]
0x30C573: 4C8B97D8000000                   mov     r10, [rdi+0D8h]
0x018F1F: 4152                             push    r10
0x018F21: 4989E6                           mov     r14, rsp
0x30C5E0: 4C8BBFD8000000                   mov     r15, [rdi+0D8h]
0x019012: 498B4128                         mov     rax, [r9+28h]
0x30C6B1: 4C8BB0E8000000                   mov     r14, [rax+0E8h]
0x30C718: 488B98F0000000                   mov     rbx, [rax+0F0h]
0x019024: 4156                             push    r14
0x019026: 68FA089223                       push    239208FAh
0x01902B: 683422C27F                       push    7FC22234h
0x019030: 68AD4C5D1F                       push    1F5D4CADh
0x019035: 68A721BC09                       push    9BC21A7h
0x019137: 4D8B7128                         mov     r14, [r9+28h]
0x30C7E6: 498B9EB8000000                   mov     rbx, [r14+0B8h]
0x30C84B: 498BBE90000000                   mov     rdi, [r14+90h]
0x019149: 480FB6DB                         movzx   rbx, bl
0x019228: 498B6928                         mov     rbp, [r9+28h]
0x30C918: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x30C97D: 48B89D0FFFD100000000             mov     rax, 0D1FF0F9Dh
0x30C9EC: 480523630A6E                     add     rax, 6E0A6323h
0x30CA56: 488B80A0030000                   mov     rax, [rax+3A0h]
0x30CABB: 48038590000000                   add     rax, [rbp+90h]
0x019251: 448A20                           mov     r12b, [rax]
0x019254: 4D0FB6E4                         movzx   r12, r12b
0x019258: 49C1E420                         shl     r12, 20h
0x30CB29: 4C29A5B0000000                   sub     [rbp+0B0h], r12
0x30CB96: 48BBAEFFE41201000000             mov     rbx, 112E4FFAEh
0x01926D: 53                               push    rbx
0x01926E: 682C050B2A                       push    2A0B052Ch
0x019273: 687D5D2922                       push    22295D7Dh
0x019278: 689027C60B                       push    0BC62790h
0x01927D: 68E3578C64                       push    648C57E3h
0x30CBFE: 4881442420126B242D               add     qword ptr [rsp+20h], 2D246B12h
0x01928B: 498B4928                         mov     rcx, [r9+28h]
0x30CC6D: 4C8BB1B0000000                   mov     r14, [rcx+0B0h]
0x01938E: 4D8B6128                         mov     r12, [r9+28h]
0x30CD36: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x30CDA1: 498BBC2488000000                 mov     rdi, [r12+88h]
0x30CE0B: 4D8BAC24E8000000                 mov     r13, [r12+0E8h]
0x019488: 4D8B5928                         mov     r11, [r9+28h]
0x30CEE5: 498B9BE0000000                   mov     rbx, [r11+0E0h]
0x019493: 458B5334                         mov     r10d, [r11+34h]
0x30CF4B: 4D0393B0000000                   add     r10, [r11+0B0h]
0x01949E: 418A2A                           mov     bpl, [r10]
0x30CFB2: 49C7C5FF000000                   mov     r13, 0FFh
0x0194A8: 49C1E518                         shl     r13, 18h
0x0194AC: 49F7D5                           not     r13
0x0194AF: 4C21EB                           and     rbx, r13
0x0194B2: 4C0FB6ED                         movzx   r13, bpl
0x0194B6: 49C1E518                         shl     r13, 18h
0x0194BA: 4C09EB                           or      rbx, r13
0x019595: 4D8B7128                         mov     r14, [r9+28h]
0x30D083: 498B9690000000                   mov     rdx, [r14+90h]
0x0195A0: 52                               push    rdx
0x0195A1: 4889E7                           mov     rdi, rsp
0x30D0F0: 498B9E90000000                   mov     rbx, [r14+90h]
0x01968E: 4D8B7928                         mov     r15, [r9+28h]
0x30D1C6: 4D8BA7B0000000                   mov     r12, [r15+0B0h]
0x30D22F: 4D8BAF90000000                   mov     r13, [r15+90h]
0x0196A0: 4154                             push    r12
0x0196A2: 68F8330464                       push    640433F8h
0x0196A7: 68C27BD444                       push    44D47BC2h
0x0196AC: 68EA60376E                       push    6E3760EAh
0x0197A1: 498B4128                         mov     rax, [r9+28h]
0x30D2FF: 4C8BA090000000                   mov     r12, [rax+90h]
0x30D364: 4C8BA8E0000000                   mov     r13, [rax+0E0h]
0x0197B3: 4D0FB6E4                         movzx   r12, r12b
0x01988C: 4D8B5928                         mov     r11, [r9+28h]
0x30D437: 410FAE93D8000000                 ldmxcsr dword ptr [r11+0D8h]
0x30D4A4: 49BAA63E973501000000             mov     r10, 135973EA6h
0x30D512: 4981C21A34720A                   add     r10, 0A72341Ah
0x0198A9: 4D8B12                           mov     r10, [r10]
0x30D57A: 4D0393D8000000                   add     r10, [r11+0D8h]
0x0198B3: 458A22                           mov     r12b, [r10]
0x0198B6: 4D0FB6E4                         movzx   r12, r12b
0x0198BA: 49C1E428                         shl     r12, 28h
0x30D5E3: 4D29A3E0000000                   sub     [r11+0E0h], r12
0x0198C5: 4D8B5128                         mov     r10, [r9+28h]
0x30D648: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x30D6AE: 48BE2404BC3B01000000             mov     rsi, 13BBC0424h
0x30D71C: 4881C69C664D04                   add     rsi, 44D669Ch
0x0199D1: 4D8B6928                         mov     r13, [r9+28h]
0x0199D5: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x30D7ED: 4D8BBDC8000000                   mov     r15, [r13+0C8h]
0x30D856: 4D8BB590000000                   mov     r14, [r13+90h]
0x019ABA: 498B7928                         mov     rdi, [r9+28h]
0x30D929: 4C8BB7E8000000                   mov     r14, [rdi+0E8h]
0x019AC5: 448B7F34                         mov     r15d, [rdi+34h]
0x30D995: 4C03BFF0000000                   add     r15, [rdi+0F0h]
0x019AD0: 418A2F                           mov     bpl, [r15]
0x30DA03: 48C7C1FF000000                   mov     rcx, 0FFh
0x019ADA: 48C1E120                         shl     rcx, 20h
0x019ADE: 48F7D1                           not     rcx
0x019AE1: 4921CE                           and     r14, rcx
0x019AE4: 480FB6CD                         movzx   rcx, bpl
0x019AE8: 48C1E120                         shl     rcx, 20h
0x019AEC: 4909CE                           or      r14, rcx
0x019BDC: 498B6928                         mov     rbp, [r9+28h]
0x30DAD7: 488B85E8000000                   mov     rax, [rbp+0E8h]
0x019BE7: 50                               push    rax
0x019BE8: 4989E7                           mov     r15, rsp
0x30DB43: 488BBDE8000000                   mov     rdi, [rbp+0E8h]
0x019CC8: 4D8B7128                         mov     r14, [r9+28h]
0x30DC11: 4D8B8EF0000000                   mov     r9, [r14+0F0h]
0x30DC7C: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x019CDA: 4151                             push    r9
0x019CDC: 68E17EEC1C                       push    1CEC7EE1h
0x019CE1: 68A474E11D                       push    1DE174A4h
0x019CE6: 682A7FC339                       push    39C37F2Ah
0x019DCB: 498B5128                         mov     rdx, [r9+28h]
0x30DD4E: 4C8BBAF0000000                   mov     r15, [rdx+0F0h]
0x30DDBB: 4C8BA2A0000000                   mov     r12, [rdx+0A0h]
0x019DDD: 4D0FB6FF                         movzx   r15, r15b
0x019ECD: 498B6928                         mov     rbp, [r9+28h]
0x30DE8F: 0FAE95F0000000                   ldmxcsr dword ptr [rbp+0F0h]
0x30DEFD: 49BCC143DA3101000000             mov     r12, 131DA43C1h
0x30DF6B: 4981C4FF2E2F0E                   add     r12, 0E2F2EFFh
0x019EE9: 4D8B2424                         mov     r12, [r12]
0x30DFD5: 4C03A5F0000000                   add     r12, [rbp+0F0h]
0x019EF4: 458A2424                         mov     r12b, [r12]
0x019EF8: 4D0FB6E4                         movzx   r12, r12b
0x019EFC: 49C1E438                         shl     r12, 38h
0x30E042: 4C29A5D8000000                   sub     [rbp+0D8h], r12
0x019F07: 4D8B7928                         mov     r15, [r9+28h]
0x30E0AD: 4D8BBFD8000000                   mov     r15, [r15+0D8h]
0x30E11A: 48BF0BF8042901000000             mov     rdi, 12904F80Bh
0x30E186: 4881C7B5720417                   add     rdi, 170472B5h
0x01A006: 498B7128                         mov     rsi, [r9+28h]
0x01A00A: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x30E251: 488BBEE8000000                   mov     rdi, [rsi+0E8h]
0x30E2B7: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x01A0F5: 4D8B5928                         mov     r11, [r9+28h]
0x30E386: 498BB3E0000000                   mov     rsi, [r11+0E0h]
0x01A100: 458B6B34                         mov     r13d, [r11+34h]
0x30E3EC: 4D03ABB0000000                   add     r13, [r11+0B0h]
0x01A10B: 418A6D00                         mov     bpl, [r13+0]
0x30E451: 49C7C7FF000000                   mov     r15, 0FFh
0x01A116: 49C1E730                         shl     r15, 30h
0x01A11A: 49F7D7                           not     r15
0x01A11D: 4C21FE                           and     rsi, r15
0x01A120: 4C0FB6FD                         movzx   r15, bpl
0x01A124: 49C1E730                         shl     r15, 30h
0x01A128: 4C09FE                           or      rsi, r15
0x30E525: 48BD579D223201000000             mov     rbp, 132229D57h
0x01A218: 55                               push    rbp
0x01A219: 68633DA650                       push    50A63D63h
0x01A21E: 682A52E507                       push    7E5522Ah
0x01A223: 684C330119                       push    1901334Ch
0x30E594: 4881442418911B670E               add     qword ptr [rsp+18h], 0E671B91h
0x01A231: 4D8B4128                         mov     r8, [r9+28h]
0x30E5FB: 498B98A8000000                   mov     rbx, [r8+0A8h]
0x01A32E: 498B6928                         mov     rbp, [r9+28h]
0x30E6D1: 4C8BADA0000000                   mov     r13, [rbp+0A0h]
0x30E737: 488B9D90000000                   mov     rbx, [rbp+90h]
0x01A340: 4D0FB6ED                         movzx   r13, r13b
0x01A41F: 4D8B4128                         mov     r8, [r9+28h]
0x30E808: 498B80E0000000                   mov     rax, [r8+0E0h]
0x30E86F: 48C7C59BB23B94                   mov     rbp, 0FFFFFFFF943BB29Bh
0x30E8D8: 4881C587070F6C                   add     rbp, 6C0F0787h
0x01A438: 55                               push    rbp
0x30E944: 4D8BB090000000                   mov     r14, [r8+90h]
0x01A440: 48F72424                         mul     qword ptr [rsp]
0x01A444: 4889C7                           mov     rdi, rax
0x01A51E: 4D8B7928                         mov     r15, [r9+28h]
0x30EA11: 4D8BAFE8000000                   mov     r13, [r15+0E8h]
0x30EA77: 4D33AFB0000000                   xor     r13, [r15+0B0h]
0x01A61F: 498B4128                         mov     rax, [r9+28h]
0x30EB49: 4C8BA8E0000000                   mov     r13, [rax+0E0h]
0x01A62A: 4155                             push    r13
0x01A62C: 4989E4                           mov     r12, rsp
0x30EBB3: 4C8BB8E0000000                   mov     r15, [rax+0E0h]
0x01A710: 498B4128                         mov     rax, [r9+28h]
0x30EC7E: 488BB8D8000000                   mov     rdi, [rax+0D8h]
0x30ECE4: 4C8BB8F0000000                   mov     r15, [rax+0F0h]
0x01A722: 57                               push    rdi
0x01A723: 68CB7AC548                       push    48C57ACBh
0x01A728: 684472B241                       push    41B27244h
0x01A72D: 68121DA565                       push    65A51D12h
0x01A732: 68FA61FD4A                       push    4AFD61FAh
0x01A825: 4D8B4128                         mov     r8, [r9+28h]
0x30EDB3: 498BA8A0000000                   mov     rbp, [r8+0A0h]
0x30EE1B: 4D8BB8F0000000                   mov     r15, [r8+0F0h]
0x01A837: 480FB6ED                         movzx   rbp, bpl
0x01A922: 4D8B5928                         mov     r11, [r9+28h]
0x30EEEC: 410FAE93A0000000                 ldmxcsr dword ptr [r11+0A0h]
0x30EF58: 48BDA81965ED00000000             mov     rbp, 0ED6519A8h
0x30EFC9: 4881C51849A452                   add     rbp, 52A44918h
0x30F02F: 488BADF8050000                   mov     rbp, [rbp+5F8h]
0x30F094: 4903ABA0000000                   add     rbp, [r11+0A0h]
0x01A94D: 8A5500                           mov     dl, [rbp+0]
0x01A950: 480FB6D2                         movzx   rdx, dl
0x01A954: 48C1E208                         shl     rdx, 8
0x30F100: 490193F0000000                   add     [r11+0F0h], rdx
0x01A95F: 4D8B5928                         mov     r11, [r9+28h]
0x30F167: 4D8BA3F0000000                   mov     r12, [r11+0F0h]
0x30F1CE: 48BFD92104DC00000000             mov     rdi, 0DC0421D9h
0x30F238: 4881C7E7380564                   add     rdi, 640538E7h
0x01AA71: 498B5928                         mov     rbx, [r9+28h]
0x01AA75: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x30F308: 4C8BB3C8000000                   mov     r14, [rbx+0C8h]
0x30F371: 4C8BBBD8000000                   mov     r15, [rbx+0D8h]
0x01AB5B: 498B7928                         mov     rdi, [r9+28h]
0x30F442: 488B9FF0000000                   mov     rbx, [rdi+0F0h]
0x01AB66: 8B6F34                           mov     ebp, [rdi+34h]
0x30F4A7: 4803AFE8000000                   add     rbp, [rdi+0E8h]
0x01AB70: 408A7D00                         mov     dil, [rbp+0]
0x01AB74: 4088FB                           mov     bl, dil
0x01AC57: 498B4928                         mov     rcx, [r9+28h]
0x30F57E: 4C8B9190000000                   mov     r10, [rcx+90h]
0x01AC62: 4152                             push    r10
0x01AC64: 4889E6                           mov     rsi, rsp
0x30F5EC: 4C8BB190000000                   mov     r14, [rcx+90h]
0x01AD68: 4D8B5928                         mov     r11, [r9+28h]
0x30F6C2: 498BAB90000000                   mov     rbp, [r11+90h]
0x30F72D: 498BBBE8000000                   mov     rdi, [r11+0E8h]
0x01AD7A: 480FB6ED                         movzx   rbp, bpl
0x01AE5A: 4D8B7128                         mov     r14, [r9+28h]
0x30F801: 410FAE96A0000000                 ldmxcsr dword ptr [r14+0A0h]
0x30F86A: 49BFF00CFAE100000000             mov     r15, 0E1FA0CF0h
0x30F8D4: 4981C7D0550F5E                   add     r15, 5E0F55D0h
0x30F93C: 4D8BBFA8000000                   mov     r15, [r15+0A8h]
0x30F9A1: 4D03BEA0000000                   add     r15, [r14+0A0h]
0x01AE85: 458A17                           mov     r10b, [r15]
0x01AE88: 4D0FB6D2                         movzx   r10, r10b
0x01AE8C: 49C1E210                         shl     r10, 10h
0x30FA0A: 4D0196B0000000                   add     [r14+0B0h], r10
0x01AE97: 498B6928                         mov     rbp, [r9+28h]
0x30FA74: 4C8BADB0000000                   mov     r13, [rbp+0B0h]
0x30FADB: 48BB68FCF00801000000             mov     rbx, 108F0FC68h
0x30FB45: 4881C3585E1837                   add     rbx, 37185E58h
0x01AF96: 498B4128                         mov     rax, [r9+28h]
0x01AF9A: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x30FC0D: 488BA890000000                   mov     rbp, [rax+90h]
0x30FC76: 488B98E0000000                   mov     rbx, [rax+0E0h]
0x01B092: 498B4128                         mov     rax, [r9+28h]
0x30FD45: 4C8BA090000000                   mov     r12, [rax+90h]
0x01B09D: 8B5034                           mov     edx, [rax+34h]
0x30FDAF: 480390A0000000                   add     rdx, [rax+0A0h]
0x01B0A7: 408A2A                           mov     bpl, [rdx]
0x30FE19: 49C7C7FF000000                   mov     r15, 0FFh
0x01B0B1: 49C1E708                         shl     r15, 8
0x01B0B5: 49F7D7                           not     r15
0x01B0B8: 4D21FC                           and     r12, r15
0x01B0BB: 4C0FB6FD                         movzx   r15, bpl
0x01B0BF: 49C1E708                         shl     r15, 8
0x01B0C3: 4D09FC                           or      r12, r15
0x01B192: 498B4128                         mov     rax, [r9+28h]
0x30FEE5: 488B98D8000000                   mov     rbx, [rax+0D8h]
0x01B19D: 53                               push    rbx
0x01B19E: 4889E5                           mov     rbp, rsp
0x30FF4D: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x01B29B: 4D8B7128                         mov     r14, [r9+28h]
0x31001C: 4D8B8EA0000000                   mov     r9, [r14+0A0h]
0x310087: 498BAED8000000                   mov     rbp, [r14+0D8h]
0x01B2AD: 4151                             push    r9
0x01B2AF: 68D00F2D13                       push    132D0FD0h
0x01B2B4: 68776B6A2E                       push    2E6A6B77h
0x01B2B9: 685169CB37                       push    37CB6951h
0x01B2BE: 68003DE61C                       push    1CE63D00h
0x01B3A8: 4D8B7128                         mov     r14, [r9+28h]
0x310160: 4D8BA688000000                   mov     r12, [r14+88h]
0x3101CE: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x01B3BA: 4D0FB6E4                         movzx   r12, r12b
0x01B49C: 4D8B4128                         mov     r8, [r9+28h]
0x31029F: 410FAE90D8000000                 ldmxcsr dword ptr [r8+0D8h]
0x310308: 48B9AA51493301000000             mov     rcx, 1334951AAh
0x310376: 4881C11611C00C                   add     rcx, 0CC01116h
0x3103E3: 488B8900040000                   mov     rcx, [rcx+400h]
0x31044F: 490388D8000000                   add     rcx, [r8+0D8h]
0x01B4C7: 408A39                           mov     dil, [rcx]
0x01B4CA: 480FB6FF                         movzx   rdi, dil
0x01B4CE: 48C1E718                         shl     rdi, 18h
0x3104BC: 4901B8B0000000                   add     [r8+0B0h], rdi
0x01B4D9: 4D8B4928                         mov     r9, [r9+28h]
0x310524: 4D8BA1B0000000                   mov     r12, [r9+0B0h]
0x31058B: 49BF09EB551201000000             mov     r15, 11255EB09h
0x3105FA: 4981C7B76FB32D                   add     r15, 2DB36FB7h
0x01B5E7: 4D8B7128                         mov     r14, [r9+28h]
0x01B5EB: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x3106D1: 498BAED0000000                   mov     rbp, [r14+0D0h]
0x31073E: 498B9ED8000000                   mov     rbx, [r14+0D8h]
0x01B6D8: 498B6928                         mov     rbp, [r9+28h]
0x310812: 4C8BAD90000000                   mov     r13, [rbp+90h]
0x01B6E3: 448B7534                         mov     r14d, [rbp+34h]
0x31087D: 4C03B5A0000000                   add     r14, [rbp+0A0h]
0x01B6EE: 458A26                           mov     r12b, [r14]
0x3108E2: 49C7C0FF000000                   mov     r8, 0FFh
0x01B6F8: 49C1E010                         shl     r8, 10h
0x01B6FC: 49F7D0                           not     r8
0x01B6FF: 4D21C5                           and     r13, r8
0x01B702: 4D0FB6C4                         movzx   r8, r12b
0x01B706: 49C1E010                         shl     r8, 10h
0x01B70A: 4D09C5                           or      r13, r8
0x01B7FF: 498B4928                         mov     rcx, [r9+28h]
0x3109AB: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x01B80A: 56                               push    rsi
0x01B80B: 4889E5                           mov     rbp, rsp
0x310A16: 488B99E0000000                   mov     rbx, [rcx+0E0h]
0x01B90E: 498B4928                         mov     rcx, [r9+28h]
0x310AE8: 488BB9A0000000                   mov     rdi, [rcx+0A0h]
0x310B53: 4C8BB990000000                   mov     r15, [rcx+90h]
0x01B920: 480FB6FF                         movzx   rdi, dil
0x01BA04: 4D8B4128                         mov     r8, [r9+28h]
0x310C22: 410FAE90B0000000                 ldmxcsr dword ptr [r8+0B0h]
0x310C8B: 48BA0A5A33D500000000             mov     rdx, 0D5335A0Ah
0x310CFC: 4881C2B608D66A                   add     rdx, 6AD608B6h
0x310D67: 488B92C8020000                   mov     rdx, [rdx+2C8h]
0x310DD2: 490390B0000000                   add     rdx, [r8+0B0h]
0x01BA2F: 8A1A                             mov     bl, [rdx]
0x01BA31: 480FB6DB                         movzx   rbx, bl
0x01BA35: 48C1E320                         shl     rbx, 20h
0x310E40: 490198F0000000                   add     [r8+0F0h], rbx
0x310EA9: 49B8A90A640601000000             mov     r8, 106640AA9h
0x01BA4A: 4150                             push    r8
0x01BA4C: 68D13D3A73                       push    733A3DD1h
0x01BA51: 68E73F143B                       push    3B143FE7h
0x01BA56: 68216EAF4E                       push    4EAF6E21h
0x01BA5B: 6833269E7F                       push    7F9E2633h
0x310F14: 48814424201750A539               add     qword ptr [rsp+20h], 39A55017h
0x01BA69: 4D8B4928                         mov     r9, [r9+28h]
0x310F7C: 498BB1F0000000                   mov     rsi, [r9+0F0h]
0x01BB65: 498B4928                         mov     rcx, [r9+28h]
0x01BB69: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x311050: 488B99F0000000                   mov     rbx, [rcx+0F0h]
0x3110B9: 488BA9A8000000                   mov     rbp, [rcx+0A8h]
0x01BC51: 4D8B6928                         mov     r13, [r9+28h]
0x31118A: 4D8BBDA0000000                   mov     r15, [r13+0A0h]
0x01BC5C: 418B7534                         mov     esi, [r13+34h]
0x3111F4: 4903B590000000                   add     rsi, [r13+90h]
0x01BC67: 8A16                             mov     dl, [rsi]
0x31125B: 48C7C3FF000000                   mov     rbx, 0FFh
0x01BC70: 48C1E318                         shl     rbx, 18h
0x01BC74: 48F7D3                           not     rbx
0x01BC77: 4921DF                           and     r15, rbx
0x01BC7A: 480FB6DA                         movzx   rbx, dl
0x01BC7E: 48C1E318                         shl     rbx, 18h
0x01BC82: 4909DF                           or      r15, rbx
0x01BD5E: 4D8B6128                         mov     r12, [r9+28h]
0x311326: 498B9C24F0000000                 mov     rbx, [r12+0F0h]
0x01BD6A: 53                               push    rbx
0x01BD6B: 4889E6                           mov     rsi, rsp
0x311391: 498B9C24F0000000                 mov     rbx, [r12+0F0h]
0x01BE4F: 498B5128                         mov     rdx, [r9+28h]
0x311462: 4C8B9AA8000000                   mov     r11, [rdx+0A8h]
0x3114D0: 4C8BA290000000                   mov     r12, [rdx+90h]
0x01BE61: 4153                             push    r11
0x01BE63: 688179E245                       push    45E27981h
0x01BE68: 6882774543                       push    43457782h
0x01BE6D: 68440FDE69                       push    69DE0F44h
0x01BF60: 498B6928                         mov     rbp, [r9+28h]
0x3115A1: 488BBDA8000000                   mov     rdi, [rbp+0A8h]
0x311607: 4C8BBDD8000000                   mov     r15, [rbp+0D8h]
0x01BF72: 480FB6FF                         movzx   rdi, dil
0x01C052: 4D8B5128                         mov     r10, [r9+28h]
0x3116DF: 410FAE92B0000000                 ldmxcsr dword ptr [r10+0B0h]
0x311748: 48BB9D1CDCC500000000             mov     rbx, 0C5DC1C9Dh
0x3117B6: 4881C323462D7A                   add     rbx, 7A2D4623h
0x01C06F: 488B1B                           mov     rbx, [rbx]
0x311820: 49039AB0000000                   add     rbx, [r10+0B0h]
0x01C079: 408A33                           mov     sil, [rbx]
0x01C07C: 480FB6F6                         movzx   rsi, sil
0x01C080: 48C1E628                         shl     rsi, 28h
0x31188D: 4901B2F0000000                   add     [r10+0F0h], rsi
0x3118F7: 49BF5647DA1B01000000             mov     r15, 11BDA4756h
0x01C095: 4157                             push    r15
0x01C097: 6801761D23                       push    231D7601h
0x01C09C: 684167DE5E                       push    5EDE6741h
0x01C0A1: 689578B703                       push    3B77895h
0x01C0A6: 6829214C1C                       push    1C4C2129h
0x311963: 48814424206A132F24               add     qword ptr [rsp+20h], 242F136Ah
0x01C0B4: 4D8B5928                         mov     r11, [r9+28h]
0x3119D3: 498BABF0000000                   mov     rbp, [r11+0F0h]
0x01C19F: 4D8B5128                         mov     r10, [r9+28h]
0x01C1A3: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x311AA1: 498B9AF0000000                   mov     rbx, [r10+0F0h]
0x311B08: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x01C282: 498B4128                         mov     rax, [r9+28h]
0x311BD9: 488BB8E8000000                   mov     rdi, [rax+0E8h]
0x01C28D: 448B4834                         mov     r9d, [rax+34h]
0x311C3E: 4C038890000000                   add     r9, [rax+90h]
0x01C298: 418A31                           mov     sil, [r9]
0x311CAC: 48C7C2FF000000                   mov     rdx, 0FFh
0x01C2A2: 48C1E220                         shl     rdx, 20h
0x01C2A6: 48F7D2                           not     rdx
0x01C2A9: 4821D7                           and     rdi, rdx
0x01C2AC: 480FB6D6                         movzx   rdx, sil
0x01C2B0: 48C1E220                         shl     rdx, 20h
0x01C2B4: 4809D7                           or      rdi, rdx
0x01C38E: 498B4128                         mov     rax, [r9+28h]
0x311D7A: 488B90B0000000                   mov     rdx, [rax+0B0h]
0x01C399: 52                               push    rdx
0x01C39A: 4889E5                           mov     rbp, rsp
0x311DE8: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x01C49B: 498B5928                         mov     rbx, [r9+28h]
0x311EBA: 4C8BA3E0000000                   mov     r12, [rbx+0E0h]
0x311F1F: 4C8BABD8000000                   mov     r13, [rbx+0D8h]
0x01C4AD: 4D0FB6E4                         movzx   r12, r12b
0x01C593: 4D8B6128                         mov     r12, [r9+28h]
0x311FED: 410FAE9424D8000000               ldmxcsr dword ptr [r12+0D8h]
0x312055: 48BD7FFDD22501000000             mov     rbp, 125D2FD7Fh
0x3120BD: 4881C54165361A                   add     rbp, 1A366541h
0x01C5B1: 488B6D00                         mov     rbp, [rbp+0]
0x312127: 4903AC24D8000000                 add     rbp, [r12+0D8h]
0x01C5BD: 448A5500                         mov     r10b, [rbp+0]
0x01C5C1: 4D0FB6D2                         movzx   r10, r10b
0x01C5C5: 49C1E230                         shl     r10, 30h
0x312193: 4D019424E0000000                 add     [r12+0E0h], r10
0x01C5D1: 4D8B5928                         mov     r11, [r9+28h]
0x312200: 498BBBE0000000                   mov     rdi, [r11+0E0h]
0x31226E: 49BE923F133D01000000             mov     r14, 13D133F92h
0x3122DA: 4981C62E1BF602                   add     r14, 2F61B2Eh
0x01C6E5: 4D8B5928                         mov     r11, [r9+28h]
0x01C6E9: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x3123A9: 4D8BA3C0000000                   mov     r12, [r11+0C0h]
0x312410: 498BBBB0000000                   mov     rdi, [r11+0B0h]
0x01C7E5: 4D8B5128                         mov     r10, [r9+28h]
0x3124E2: 498BAAB0000000                   mov     rbp, [r10+0B0h]
0x01C7F0: 458B6A34                         mov     r13d, [r10+34h]
0x31254C: 4D03AAD8000000                   add     r13, [r10+0D8h]
0x01C7FB: 458A7D00                         mov     r15b, [r13+0]
0x3125B7: 49C7C2FF000000                   mov     r10, 0FFh
0x01C806: 49C1E228                         shl     r10, 28h
0x01C80A: 49F7D2                           not     r10
0x01C80D: 4C21D5                           and     rbp, r10
0x01C810: 4D0FB6D7                         movzx   r10, r15b
0x01C814: 49C1E228                         shl     r10, 28h
0x01C818: 4C09D5                           or      rbp, r10
0x01C8E6: 4D8B5928                         mov     r11, [r9+28h]
0x312688: 4D8B83A0000000                   mov     r8, [r11+0A0h]
0x01C8F1: 4150                             push    r8
0x01C8F3: 4989E7                           mov     r15, rsp
0x3126ED: 498BABA0000000                   mov     rbp, [r11+0A0h]
0x01C9DB: 4D8B6928                         mov     r13, [r9+28h]
0x3127C0: 4D8BBDF0000000                   mov     r15, [r13+0F0h]
0x312828: 498BADA0000000                   mov     rbp, [r13+0A0h]
0x01C9ED: 4157                             push    r15
0x01C9EF: 681C4ABC20                       push    20BC4A1Ch
0x01C9F4: 686F6A8D23                       push    238D6A6Fh
0x01C9F9: 68BF78F86D                       push    6DF878BFh
0x01C9FE: 68F45F751A                       push    1A755FF4h
0x01CAFA: 4D8B7128                         mov     r14, [r9+28h]
0x3128FC: 498BB6B8000000                   mov     rsi, [r14+0B8h]
0x312967: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x01CB0C: 480FB6F6                         movzx   rsi, sil
0x01CBE7: 4D8B7928                         mov     r15, [r9+28h]
0x312A37: 410FAE97A8000000                 ldmxcsr dword ptr [r15+0A8h]
0x312AA2: 49BC8111F3F000000000             mov     r12, 0F0F31181h
0x312B11: 4981C43F51164F                   add     r12, 4F16513Fh
0x01CC04: 4D8B2424                         mov     r12, [r12]
0x312B7A: 4D03A7A8000000                   add     r12, [r15+0A8h]
0x01CC0F: 458A1424                         mov     r10b, [r12]
0x01CC13: 4D0FB6D2                         movzx   r10, r10b
0x01CC17: 49C1E238                         shl     r10, 38h
0x312BE8: 4D0197E8000000                   add     [r15+0E8h], r10
0x312C4E: 49BD33E2780801000000             mov     r13, 10878E233h
0x01CC2C: 4155                             push    r13
0x01CC2E: 685F52E02D                       push    2DE0525Fh
0x01CC33: 68443D5378                       push    78533D44h
0x01CC38: 68A55EA12B                       push    2BA15EA5h
0x312CBA: 48814424188D789037               add     qword ptr [rsp+18h], 3790788Dh
0x01CC46: 4D8B4128                         mov     r8, [r9+28h]
0x312D22: 498B98E8000000                   mov     rbx, [r8+0E8h]
0x01CD40: 4D8B5128                         mov     r10, [r9+28h]
0x01CD44: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x312DF0: 498BB2B8000000                   mov     rsi, [r10+0B8h]
0x312E5D: 4D8BA290000000                   mov     r12, [r10+90h]
0x01CE2E: 498B6928                         mov     rbp, [r9+28h]
0x312F2E: 488BBDD8000000                   mov     rdi, [rbp+0D8h]
0x01CE39: 8B7534                           mov     esi, [rbp+34h]
0x312F96: 4803B5A8000000                   add     rsi, [rbp+0A8h]
0x01CE43: 448A1E                           mov     r11b, [rsi]
0x313001: 49C7C6FF000000                   mov     r14, 0FFh
0x01CE4D: 49C1E630                         shl     r14, 30h
0x01CE51: 49F7D6                           not     r14
0x01CE54: 4C21F7                           and     rdi, r14
0x01CE57: 4D0FB6F3                         movzx   r14, r11b
0x01CE5B: 49C1E630                         shl     r14, 30h
0x01CE5F: 4C09F7                           or      rdi, r14
0x01CF41: 4D8B6928                         mov     r13, [r9+28h]
0x3130D3: 4D8BBDB0000000                   mov     r15, [r13+0B0h]
0x313141: 48BB4496FAF200000000             mov     rbx, 0F2FA9644h
0x3131AC: 4881C3A4228F4D                   add     rbx, 4D8F22A4h
0x01D04A: 498B5128                         mov     rdx, [r9+28h]
0x31327D: 4C8BBA88000000                   mov     r15, [rdx+88h]
0x3132E8: 488BAAF0000000                   mov     rbp, [rdx+0F0h]
0x01D05C: 4D0FB6FF                         movzx   r15, r15b
0x01D149: 498B5928                         mov     rbx, [r9+28h]
0x3133B7: 488B83F0000000                   mov     rax, [rbx+0F0h]
0x31341D: 49C7C0D772C6B0                   mov     r8, 0FFFFFFFFB0C672D7h
0x313488: 4981C0B333CB4F                   add     r8, 4FCB33B3h
0x01D162: 4150                             push    r8
0x3134EF: 488B9BA0000000                   mov     rbx, [rbx+0A0h]
0x01D16B: 48F72424                         mul     qword ptr [rsp]
0x01D16F: 4889C6                           mov     rsi, rax
0x01D24C: 4D8B6928                         mov     r13, [r9+28h]
0x3135BC: 4D8BB590000000                   mov     r14, [r13+90h]
0x313621: 4D33B5A8000000                   xor     r14, [r13+0A8h]
0x01D337: 498B7928                         mov     rdi, [r9+28h]
0x3136EB: 4C8B9FE8000000                   mov     r11, [rdi+0E8h]
0x01D342: 4153                             push    r11
0x01D344: 4989E5                           mov     r13, rsp
0x313758: 4C8BB7E8000000                   mov     r14, [rdi+0E8h]
0x01D426: 498B5128                         mov     rdx, [r9+28h]
0x31382E: 4C8B82E0000000                   mov     r8, [rdx+0E0h]
0x313896: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x01D438: 4150                             push    r8
0x01D43A: 683471753D                       push    3D757134h
0x01D43F: 684073252D                       push    2D257340h
0x01D444: 68D52C1C28                       push    281C2CD5h
0x01D52D: 4D8B4928                         mov     r9, [r9+28h]
0x313964: 4D8BA9C8000000                   mov     r13, [r9+0C8h]
0x3139CE: 4D8BB1D8000000                   mov     r14, [r9+0D8h]
0x01D53F: 4D0FB6ED                         movzx   r13, r13b
0x01D626: 498B5128                         mov     rdx, [r9+28h]
0x313AA4: 0FAE92E0000000                   ldmxcsr dword ptr [rdx+0E0h]
0x313B11: 48BFFFED352501000000             mov     rdi, 12535EDFFh
0x01D63B: 57                               push    rdi
0x01D63C: 680F693318                       push    1833690Fh
0x01D641: 68B1632543                       push    432563B1h
0x01D646: 68EF384E4D                       push    4D4E38EFh
0x01D64B: 6804224B79                       push    794B2204h
0x313B79: 4881442420C15CD31A               add     [rsp-8+arg_20], 1AD35CC1h
0x01D659: 498B5928                         mov     rbx, [r9+28h]
0x313BE4: 4C8BA3E8000000                   mov     r12, [rbx+0E8h]
0x01D75C: 498B4928                         mov     rcx, [r9+28h]
0x01D760: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x313CB0: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x313D1C: 488BA9D8000000                   mov     rbp, [rcx+0D8h]
0x01D84E: 4D8B5128                         mov     r10, [r9+28h]
0x313DE6: 4D8BAAA0000000                   mov     r13, [r10+0A0h]
0x01D859: 458B6234                         mov     r12d, [r10+34h]
0x313E4E: 4D03A2A8000000                   add     r12, [r10+0A8h]
0x01D864: 458A2424                         mov     r12b, [r12]
0x01D868: 4588E5                           mov     r13b, r12b
0x01D955: 498B4128                         mov     rax, [r9+28h]
0x313F17: 488B90E0000000                   mov     rdx, [rax+0E0h]
0x01D960: 52                               push    rdx
0x01D961: 4989E7                           mov     r15, rsp
0x313F83: 488BB0E0000000                   mov     rsi, [rax+0E0h]
0x01DA4C: 4D8B6128                         mov     r12, [r9+28h]
0x314059: 498BB424E8000000                 mov     rsi, [r12+0E8h]
0x3140C5: 4D8BB424A8000000                 mov     r14, [r12+0A8h]
0x01DA60: 480FB6F6                         movzx   rsi, sil
0x01DB3B: 498B7928                         mov     rdi, [r9+28h]
0x314194: 0FAE97A8000000                   ldmxcsr dword ptr [rdi+0A8h]
0x01DB46: 4D8B6128                         mov     r12, [r9+28h]
0x3141FF: 4D8BAC24E8000000                 mov     r13, [r12+0E8h]
0x314269: 48BBE5D805F800000000             mov     rbx, 0F805D8E5h
0x3142D3: 4881C3DB710348                   add     rbx, 480371DBh
0x01DC4D: 498B4928                         mov     rcx, [r9+28h]
0x01DC51: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x3143A7: 488BB188000000                   mov     rsi, [rcx+88h]
0x31440E: 488BB9E0000000                   mov     rdi, [rcx+0E0h]
0x01DD42: 4D8B5128                         mov     r10, [r9+28h]
0x3144DD: 4D8BA2B0000000                   mov     r12, [r10+0B0h]
0x01DD4D: 418B5234                         mov     edx, [r10+34h]
0x314543: 490392A8000000                   add     rdx, [r10+0A8h]
0x01DD58: 8A02                             mov     al, [rdx]
0x3145AF: 49C7C0FF000000                   mov     r8, 0FFh
0x01DD61: 49C1E008                         shl     r8, 8
0x01DD65: 49F7D0                           not     r8
0x01DD68: 4D21C4                           and     r12, r8
0x01DD6B: 4C0FB6C0                         movzx   r8, al
0x01DD6F: 49C1E008                         shl     r8, 8
0x01DD73: 4D09C4                           or      r12, r8
0x01DE63: 4D8B6928                         mov     r13, [r9+28h]
0x314683: 498BBDD8000000                   mov     rdi, [r13+0D8h]
0x01DE6E: 57                               push    rdi
0x01DE6F: 4989E6                           mov     r14, rsp
0x3146EF: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x01DF59: 498B5928                         mov     rbx, [r9+28h]
0x3147C2: 4C8B9BE8000000                   mov     r11, [rbx+0E8h]
0x31482A: 488B9BA8000000                   mov     rbx, [rbx+0A8h]
0x01DF6B: 4153                             push    r11
0x01DF6D: 680170F94C                       push    4CF97001h
0x01DF72: 682334A022                       push    22A03423h
0x01DF77: 68AB50B869                       push    69B850ABh
0x01E06A: 4D8B5928                         mov     r11, [r9+28h]
0x3148F6: 498BBBE0000000                   mov     rdi, [r11+0E0h]
0x31495F: 4D8BA390000000                   mov     r12, [r11+90h]
0x01E07C: 480FB6FF                         movzx   rdi, dil
0x01E167: 4D8B7128                         mov     r14, [r9+28h]
0x314A2F: 410FAE96B0000000                 ldmxcsr dword ptr [r14+0B0h]
0x01E173: 4D8B6128                         mov     r12, [r9+28h]
0x314A99: 498B9C24D8000000                 mov     rbx, [r12+0D8h]
0x314B06: 49BE881BEFED00000000             mov     r14, 0EDEF1B88h
0x314B75: 4981C6382F1A52                   add     r14, 521A2F38h
0x01E287: 498B7128                         mov     rsi, [r9+28h]
0x01E28B: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x314C4B: 4C8BBEC8000000                   mov     r15, [rsi+0C8h]
0x314CB6: 488BBE90000000                   mov     rdi, [rsi+90h]
0x01E385: 498B6928                         mov     rbp, [r9+28h]
0x314D81: 488BBDB0000000                   mov     rdi, [rbp+0B0h]
0x01E390: 448B4534                         mov     r8d, [rbp+34h]
0x314DE7: 4C0385F0000000                   add     r8, [rbp+0F0h]
0x01E39B: 418A10                           mov     dl, [r8]
0x314E4E: 48C7C3FF000000                   mov     rbx, 0FFh
0x01E3A5: 48C1E310                         shl     rbx, 10h
0x01E3A9: 48F7D3                           not     rbx
0x01E3AC: 4821DF                           and     rdi, rbx
0x01E3AF: 480FB6DA                         movzx   rbx, dl
0x01E3B3: 48C1E310                         shl     rbx, 10h
0x01E3B7: 4809DF                           or      rdi, rbx
0x01E4A0: 4D8B6128                         mov     r12, [r9+28h]
0x314F1C: 498BB424B0000000                 mov     rsi, [r12+0B0h]
0x01E4AC: 56                               push    rsi
0x01E4AD: 4989E6                           mov     r14, rsp
0x314F87: 4D8BAC24B0000000                 mov     r13, [r12+0B0h]
0x01E5AB: 498B5928                         mov     rbx, [r9+28h]
0x315058: 4C8BABA8000000                   mov     r13, [rbx+0A8h]
0x3150C1: 488BABE0000000                   mov     rbp, [rbx+0E0h]
0x01E5BD: 4D0FB6ED                         movzx   r13, r13b
0x01E691: 498B5928                         mov     rbx, [r9+28h]
0x315192: 0FAE93E0000000                   ldmxcsr dword ptr [rbx+0E0h]
0x3151FB: 49BB9E3A1F3E01000000             mov     r11, 13E1F3A9Eh
0x01E6A6: 4153                             push    r11
0x01E6A8: 68A9221907                       push    71922A9h
0x01E6AD: 68EB4A811C                       push    1C814AEBh
0x01E6B2: 684C3F3504                       push    4353F4Ch
0x315267: 48814424182210EA01               add     [rsp-8+arg_18], 1EA1022h
0x01E6C0: 498B7128                         mov     rsi, [r9+28h]
0x3152D4: 4C8BA6A0000000                   mov     r12, [rsi+0A0h]
0x01E7BC: 4D8B6928                         mov     r13, [r9+28h]
0x01E7C0: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x3153A6: 4D8BB5E8000000                   mov     r14, [r13+0E8h]
0x315411: 498B9DD8000000                   mov     rbx, [r13+0D8h]
0x01E8AE: 4D8B4128                         mov     r8, [r9+28h]
0x3154DB: 498BB890000000                   mov     rdi, [r8+90h]
0x01E8B9: 418B4034                         mov     eax, [r8+34h]
0x315542: 490380E8000000                   add     rax, [r8+0E8h]
0x01E8C4: 448A10                           mov     r10b, [rax]
0x3155B0: 49C7C6FF000000                   mov     r14, 0FFh
0x01E8CE: 49C1E618                         shl     r14, 18h
0x01E8D2: 49F7D6                           not     r14
0x01E8D5: 4C21F7                           and     rdi, r14
0x01E8D8: 4D0FB6F2                         movzx   r14, r10b
0x01E8DC: 49C1E618                         shl     r14, 18h
0x01E8E0: 4C09F7                           or      rdi, r14
0x01E9C8: 498B5128                         mov     rdx, [r9+28h]
0x31567E: 4C8BB2B0000000                   mov     r14, [rdx+0B0h]
0x01E9D3: 4156                             push    r14
0x01E9D5: 4989E7                           mov     r15, rsp
0x3156E8: 488BBAB0000000                   mov     rdi, [rdx+0B0h]
0x01EAC3: 498B7128                         mov     rsi, [r9+28h]
0x3157BA: 4C8BBEF0000000                   mov     r15, [rsi+0F0h]
0x315822: 4C8BB6B0000000                   mov     r14, [rsi+0B0h]
0x01EAD5: 4157                             push    r15
0x01EAD7: 68ED435168                       push    685143EDh
0x01EADC: 681D75BA5D                       push    5DBA751Dh
0x01EAE1: 681140F128                       push    28F14011h
0x01EAE6: 681B372D11                       push    112D371Bh
0x01EBDF: 4D8B6928                         mov     r13, [r9+28h]
0x3158FC: 4D8BBDC8000000                   mov     r15, [r13+0C8h]
0x315968: 498BBDE8000000                   mov     rdi, [r13+0E8h]
0x01EBF1: 4D0FB6FF                         movzx   r15, r15b
0x01ECD3: 4D8B6928                         mov     r13, [r9+28h]
0x315A34: 410FAE95F0000000                 ldmxcsr dword ptr [r13+0F0h]
0x01ECDF: 4D8B7128                         mov     r14, [r9+28h]
0x315A9B: 4D8BBEB0000000                   mov     r15, [r14+0B0h]
0x315B04: 48BDCFD083D700000000             mov     rbp, 0D783D0CFh
0x315B72: 4881C5F1798568                   add     rbp, 688579F1h
0x01EDDC: 4D8B5928                         mov     r11, [r9+28h]
0x01EDE0: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x315C47: 4D8BB3C0000000                   mov     r14, [r11+0C0h]
0x315CB1: 498BABF0000000                   mov     rbp, [r11+0F0h]
0x01EEDA: 4D8B6928                         mov     r13, [r9+28h]
0x315D7E: 4D8BB5A0000000                   mov     r14, [r13+0A0h]
0x01EEE5: 458B7D34                         mov     r15d, [r13+34h]
0x315DE7: 4D03BDE8000000                   add     r15, [r13+0E8h]
0x01EEF0: 458A3F                           mov     r15b, [r15]
0x315E4C: 48C7C6FF000000                   mov     rsi, 0FFh
0x01EEFA: 48C1E630                         shl     rsi, 30h
0x01EEFE: 48F7D6                           not     rsi
0x01EF01: 4921F6                           and     r14, rsi
0x01EF04: 490FB6F7                         movzx   rsi, r15b
0x01EF08: 48C1E630                         shl     rsi, 30h
0x01EF0C: 4909F6                           or      r14, rsi
0x315F1D: 49BBE04E95F600000000             mov     r11, 0F6954EE0h
0x01F006: 4153                             push    r11
0x01F008: 68870FFC5E                       push    5EFC0F87h
0x01F00D: 68845FE162                       push    62E15F84h
0x01F012: 68D914F729                       push    29F714D9h
0x01F017: 68835A1D47                       push    471D5A83h
0x315F89: 4881442420086AF449               add     [rsp-8+arg_20], 49F46A08h
0x01F025: 4D8B5128                         mov     r10, [r9+28h]
0x315FF6: 4D8BAAE8000000                   mov     r13, [r10+0E8h]
0x01F121: 4D8B4128                         mov     r8, [r9+28h]
0x3160C6: 4D8BB8D8000000                   mov     r15, [r8+0D8h]
0x316131: 498BB0E0000000                   mov     rsi, [r8+0E0h]
0x01F133: 4D0FB6FF                         movzx   r15, r15b
0x01F21D: 4D8B4928                         mov     r9, [r9+28h]
0x316203: 498B81F0000000                   mov     rax, [r9+0F0h]
0x31626A: 49C7C52EDE8EE7                   mov     r13, 0FFFFFFFFE78EDE2Eh
0x3162D6: 4981C5B0510519                   add     r13, 190551B0h
0x01F236: 4155                             push    r13
0x31633F: 498B99A8000000                   mov     rbx, [r9+0A8h]
0x01F23F: 48F72424                         mul     qword ptr [rsp]
0x01F243: 4989C5                           mov     r13, rax
0x01F325: 498B5928                         mov     rbx, [r9+28h]
0x31640D: 4C8BA390000000                   mov     r12, [rbx+90h]
0x316477: 4C33A3E0000000                   xor     r12, [rbx+0E0h]
0x01F412: 498B4928                         mov     rcx, [r9+28h]
0x316543: 4C8BA9D8000000                   mov     r13, [rcx+0D8h]
0x01F41D: 4155                             push    r13
0x01F41F: 4989E6                           mov     r14, rsp
0x3165AF: 488B99D8000000                   mov     rbx, [rcx+0D8h]
0x01F506: 4D8B7928                         mov     r15, [r9+28h]
0x31667B: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x3166E1: 4D8BA790000000                   mov     r12, [r15+90h]
0x01F518: 480FB6DB                         movzx   rbx, bl
0x01F601: 4D8B6928                         mov     r13, [r9+28h]
0x3167BA: 410FAE9590000000                 ldmxcsr dword ptr [r13+90h]
0x316821: 48BA3E0127D500000000             mov     rdx, 0D527013Eh
0x316892: 4881C28261E26A                   add     rdx, 6AE26182h
0x3168FF: 488B9270070000                   mov     rdx, [rdx+770h]
0x31696A: 49039590000000                   add     rdx, [r13+90h]
0x01F62C: 8A1A                             mov     bl, [rdx]
0x01F62E: 480FB6DB                         movzx   rbx, bl
0x01F632: 48C1E308                         shl     rbx, 8
0x3169D8: 49019DD8000000                   add     [r13+0D8h], rbx
0x316A41: 48B8CE10FDDE00000000             mov     rax, 0DEFD10CEh
0x01F647: 50                               push    rax
0x01F648: 68001D8C58                       push    588C1D00h
0x01F64D: 68233E5B51                       push    515B3E23h
0x01F652: 68A8650D31                       push    310D65A8h
0x01F657: 6856667010                       push    10706656h
0x316AB1: 4881442420F2490C61               add     qword ptr [rsp+20h], 610C49F2h
0x01F665: 498B4128                         mov     rax, [r9+28h]
0x316B1D: 488BA8D8000000                   mov     rbp, [rax+0D8h]
0x01F759: 4D8B5928                         mov     r11, [r9+28h]
0x01F75D: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x316BEC: 4D8BBBD8000000                   mov     r15, [r11+0D8h]
0x316C56: 4D8BB3A0000000                   mov     r14, [r11+0A0h]
0x01F861: 4D8B5128                         mov     r10, [r9+28h]
0x316D28: 4D8BB2E8000000                   mov     r14, [r10+0E8h]
0x01F86C: 458B7A34                         mov     r15d, [r10+34h]
0x316D90: 4D03BAF0000000                   add     r15, [r10+0F0h]
0x01F877: 458A07                           mov     r8b, [r15]
0x01F87A: 4588C6                           mov     r14b, r8b
0x01F95F: 498B5128                         mov     rdx, [r9+28h]
0x316E5B: 488B8AE8000000                   mov     rcx, [rdx+0E8h]
0x01F96A: 51                               push    rcx
0x01F96B: 4989E7                           mov     r15, rsp
0x316EC4: 488B9AE8000000                   mov     rbx, [rdx+0E8h]
0x01FA4D: 498B4928                         mov     rcx, [r9+28h]
0x316F95: 4C8BA9F0000000                   mov     r13, [rcx+0F0h]
0x316FFE: 4C8BB990000000                   mov     r15, [rcx+90h]
0x01FA5F: 4D0FB6ED                         movzx   r13, r13b
0x01FB44: 4D8B6128                         mov     r12, [r9+28h]
0x3170D2: 410FAE9424E0000000               ldmxcsr dword ptr [r12+0E0h]
0x31713A: 48B9611CD72E01000000             mov     rcx, 12ED71C61h
0x3171A3: 4881C15F463211                   add     rcx, 1132465Fh
0x31720D: 488B8928010000                   mov     rcx, [rcx+128h]
0x317279: 49038C24E0000000                 add     rcx, [r12+0E0h]
0x01FB71: 448A01                           mov     r8b, [rcx]
0x01FB74: 4D0FB6C0                         movzx   r8, r8b
0x01FB78: 49C1E010                         shl     r8, 10h
0x3172E5: 4D018424F0000000                 add     [r12+0F0h], r8
0x01FB84: 498B7128                         mov     rsi, [r9+28h]
0x31734E: 4C8BBEF0000000                   mov     r15, [rsi+0F0h]
0x3173B6: 49BD1405C6CC00000000             mov     r13, 0CCC60514h
0x317423: 4981C5AC554373                   add     r13, 734355ACh
0x01FC91: 4D8B4128                         mov     r8, [r9+28h]
0x01FC95: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x3174FA: 498BA888000000                   mov     rbp, [r8+88h]
0x317564: 4D8BA0F0000000                   mov     r12, [r8+0F0h]
0x01FD7D: 4D8B4928                         mov     r9, [r9+28h]
0x317637: 4D8BA9D8000000                   mov     r13, [r9+0D8h]
0x01FD88: 418B5134                         mov     edx, [r9+34h]
0x31769E: 490391A0000000                   add     rdx, [r9+0A0h]
0x01FD93: 8A12                             mov     dl, [rdx]
0x31770C: 49C7C1FF000000                   mov     r9, 0FFh
0x01FD9C: 49C1E108                         shl     r9, 8
0x01FDA0: 49F7D1                           not     r9
0x01FDA3: 4D21CD                           and     r13, r9
0x01FDA6: 4C0FB6CA                         movzx   r9, dl
0x01FDAA: 49C1E108                         shl     r9, 8
0x01FDAE: 4D09CD                           or      r13, r9
0x01FE8F: 498B4928                         mov     rcx, [r9+28h]
0x3177DF: 4C8BB9E0000000                   mov     r15, [rcx+0E0h]
0x01FE9A: 4157                             push    r15
0x01FE9C: 4989E6                           mov     r14, rsp
0x317848: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x01FF8F: 4D8B5128                         mov     r10, [r9+28h]
0x317919: 498BB2D0000000                   mov     rsi, [r10+0D0h]
0x31797F: 4D8BAAA8000000                   mov     r13, [r10+0A8h]
0x01FFA1: 480FB6F6                         movzx   rsi, sil
0x020087: 498B5128                         mov     rdx, [r9+28h]
0x317A4B: 0FAE92A8000000                   ldmxcsr dword ptr [rdx+0A8h]
0x317AB7: 49BCC518833001000000             mov     r12, 1308318C5h
0x317B28: 4981C4FB49860F                   add     r12, 0F8649FBh
0x317B95: 4D8BA42440060000                 mov     r12, [r12+640h]
0x317C00: 4C03A2A8000000                   add     r12, [rdx+0A8h]
0x0200B2: 458A1424                         mov     r10b, [r12]
0x0200B6: 4D0FB6D2                         movzx   r10, r10b
0x0200BA: 49C1E218                         shl     r10, 18h
0x317C6A: 4C0192E0000000                   add     [rdx+0E0h], r10
0x317CD7: 48BD0905CBEF00000000             mov     rbp, 0EFCB0509h
0x0200CF: 55                               push    rbp
0x0200D0: 6824322D22                       push    222D3224h
0x0200D5: 685532C33C                       push    3CC33255h
0x0200DA: 68B6195847                       push    475819B6h
0x0200DF: 68D078A14D                       push    4DA178D0h
0x317D42: 4881442420B7553E50               add     qword ptr [rsp+20h], 503E55B7h
0x0200ED: 498B6928                         mov     rbp, [r9+28h]
0x317DAA: 488BB5E0000000                   mov     rsi, [rbp+0E0h]
0x0201DF: 498B4128                         mov     rax, [r9+28h]
0x0201E3: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x317E78: 488BB0D8000000                   mov     rsi, [rax+0D8h]
0x317EE3: 488BA8A8000000                   mov     rbp, [rax+0A8h]
0x0202BD: 498B7128                         mov     rsi, [r9+28h]
0x317FB6: 4C8BB6A0000000                   mov     r14, [rsi+0A0h]
0x0202C8: 8B4E34                           mov     ecx, [rsi+34h]
0x31801D: 48038EA8000000                   add     rcx, [rsi+0A8h]
0x0202D2: 408A31                           mov     sil, [rcx]
0x31808A: 49C7C3FF000000                   mov     r11, 0FFh
0x0202DC: 49C1E310                         shl     r11, 10h
0x0202E0: 49F7D3                           not     r11
0x0202E3: 4D21DE                           and     r14, r11
0x0202E6: 4C0FB6DE                         movzx   r11, sil
0x0202EA: 49C1E310                         shl     r11, 10h
0x0202EE: 4D09DE                           or      r14, r11
0x0203C0: 4D8B7128                         mov     r14, [r9+28h]
0x31815C: 498B9EE8000000                   mov     rbx, [r14+0E8h]
0x0203CB: 53                               push    rbx
0x0203CC: 4889E6                           mov     rsi, rsp
0x3181C5: 498BAEE8000000                   mov     rbp, [r14+0E8h]
0x0204C1: 4D8B6128                         mov     r12, [r9+28h]
0x0204C5: 4D8B6C2478                       mov     r13, [r12+78h]
0x31829A: 498BAC24A0000000                 mov     rbp, [r12+0A0h]
0x0204D2: 4D0FB6ED                         movzx   r13, r13b
0x0205BC: 498B6928                         mov     rbp, [r9+28h]
0x318370: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x3183DE: 49BF16EEFCD000000000             mov     r15, 0D0FCEE16h
0x318447: 4981C7AA740C6F                   add     r15, 6F0C74AAh
0x3184B0: 4D8BBFA8000000                   mov     r15, [r15+0A8h]
0x318517: 4C03BDE0000000                   add     r15, [rbp+0E0h]
0x0205E6: 418A17                           mov     dl, [r15]
0x0205E9: 480FB6D2                         movzx   rdx, dl
0x0205ED: 48C1E220                         shl     rdx, 20h
0x318580: 480195A0000000                   add     [rbp+0A0h], rdx
0x3185E9: 49BBE029863201000000             mov     r11, 1328629E0h
0x020602: 4153                             push    r11
0x020604: 68F8512C70                       push    702C51F8h
0x020609: 68C6228733                       push    338722C6h
0x02060E: 680B57D63C                       push    3CD6570Bh
0x318659: 4881442418E030830D               add     qword ptr [rsp+18h], 0D8330E0h
0x02061C: 4D8B7928                         mov     r15, [r9+28h]
0x3186C1: 498BB7A0000000                   mov     rsi, [r15+0A0h]
0x020703: 4D8B5128                         mov     r10, [r9+28h]
0x020707: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x318793: 4D8BAAB8000000                   mov     r13, [r10+0B8h]
0x3187FD: 4D8BA2A8000000                   mov     r12, [r10+0A8h]
0x0207F0: 498B7128                         mov     rsi, [r9+28h]
0x3188D2: 488BBED8000000                   mov     rdi, [rsi+0D8h]
0x0207FB: 8B6E34                           mov     ebp, [rsi+34h]
0x318939: 4803AEE0000000                   add     rbp, [rsi+0E0h]
0x020805: 448A5500                         mov     r10b, [rbp+0]
0x3189A2: 48C7C0FF000000                   mov     rax, 0FFh
0x020810: 48C1E018                         shl     rax, 18h
0x020814: 48F7D0                           not     rax
0x020817: 4821C7                           and     rdi, rax
0x02081A: 490FB6C2                         movzx   rax, r10b
0x02081E: 48C1E018                         shl     rax, 18h
0x020822: 4809C7                           or      rdi, rax
0x0208F1: 498B5128                         mov     rdx, [r9+28h]
0x318A70: 488BAAB0000000                   mov     rbp, [rdx+0B0h]
0x0208FC: 55                               push    rbp
0x0208FD: 4989E6                           mov     r14, rsp
0x318ADB: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x0209D4: 4D8B7128                         mov     r14, [r9+28h]
0x318BA9: 4D8B96E8000000                   mov     r10, [r14+0E8h]
0x318C11: 4D8BB6D8000000                   mov     r14, [r14+0D8h]
0x0209E6: 4152                             push    r10
0x0209E8: 681A0C1220                       push    20120C1Ah
0x0209ED: 689361804F                       push    4F806193h
0x0209F2: 685D2E0E18                       push    180E2E5Dh
0x020AE2: 498B5928                         mov     rbx, [r9+28h]
0x020AE6: 488B7B78                         mov     rdi, [rbx+78h]
0x318CE5: 4C8BABE8000000                   mov     r13, [rbx+0E8h]
0x020AF1: 480FB6FF                         movzx   rdi, dil
0x020BC9: 498B4128                         mov     rax, [r9+28h]
0x318DB7: 0FAE90B0000000                   ldmxcsr dword ptr [rax+0B0h]
0x318E1E: 48BD5F18F7FA00000000             mov     rbp, 0FAF7185Fh
0x318E86: 4881C5614A1245                   add     rbp, 45124A61h
0x020BE5: 488B6D00                         mov     rbp, [rbp+0]
0x318EF0: 4803A8B0000000                   add     rbp, [rax+0B0h]
0x020BF0: 408A7D00                         mov     dil, [rbp+0]
0x020BF4: 480FB6FF                         movzx   rdi, dil
0x020BF8: 48C1E728                         shl     rdi, 28h
0x318F56: 4801B8E0000000                   add     [rax+0E0h], rdi
0x020C03: 498B4928                         mov     rcx, [r9+28h]
0x318FBD: 4C8BB9E0000000                   mov     r15, [rcx+0E0h]
0x319028: 48BE4725F43401000000             mov     rsi, 134F42547h
0x319097: 4881C67935150B                   add     rsi, 0B153579h
0x020CF7: 498B6928                         mov     rbp, [r9+28h]
0x020CFB: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x31915F: 4C8BADA8000000                   mov     r13, [rbp+0A8h]
0x3191C4: 488B9DF0000000                   mov     rbx, [rbp+0F0h]
0x020DEA: 498B4928                         mov     rcx, [r9+28h]
0x319299: 488B9990000000                   mov     rbx, [rcx+90h]
0x020DF5: 448B4934                         mov     r9d, [rcx+34h]
0x319300: 4C0389E0000000                   add     r9, [rcx+0E0h]
0x020E00: 458A19                           mov     r11b, [r9]
0x319367: 49C7C7FF000000                   mov     r15, 0FFh
0x020E0A: 49C1E720                         shl     r15, 20h
0x020E0E: 49F7D7                           not     r15
0x020E11: 4C21FB                           and     rbx, r15
0x020E14: 4D0FB6FB                         movzx   r15, r11b
0x020E18: 49C1E720                         shl     r15, 20h
0x020E1C: 4C09FB                           or      rbx, r15
0x020F0C: 498B4928                         mov     rcx, [r9+28h]
0x319437: 4C8B8190000000                   mov     r8, [rcx+90h]
0x020F17: 4150                             push    r8
0x020F19: 4889E3                           mov     rbx, rsp
0x3194A1: 4C8BA990000000                   mov     r13, [rcx+90h]
0x021007: 4D8B5928                         mov     r11, [r9+28h]
0x319575: 4D8BA388000000                   mov     r12, [r11+88h]
0x3195DD: 4D8BABE0000000                   mov     r13, [r11+0E0h]
0x021019: 4D0FB6E4                         movzx   r12, r12b
0x0210F5: 498B4928                         mov     rcx, [r9+28h]
0x3196A9: 0FAE91D8000000                   ldmxcsr dword ptr [rcx+0D8h]
0x319711: 48BBA0082CEC00000000             mov     rbx, 0EC2C08A0h
0x31977A: 4881C3205ADD53                   add     rbx, 53DD5A20h
0x021111: 488B1B                           mov     rbx, [rbx]
0x3197E0: 480399D8000000                   add     rbx, [rcx+0D8h]
0x02111B: 448A13                           mov     r10b, [rbx]
0x02111E: 4D0FB6D2                         movzx   r10, r10b
0x021122: 49C1E230                         shl     r10, 30h
0x319848: 4C0191E0000000                   add     [rcx+0E0h], r10
0x02112D: 498B7128                         mov     rsi, [r9+28h]
0x3198B2: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x31991B: 49BD3BE095C400000000             mov     r13, 0C495E03Bh
0x319983: 4981C5857A737B                   add     r13, 7B737A85h
0x021223: 4D8B6928                         mov     r13, [r9+28h]
0x021227: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x319A55: 4D8BB5B0000000                   mov     r14, [r13+0B0h]
0x319AC0: 498BB5F0000000                   mov     rsi, [r13+0F0h]
0x021319: 498B6928                         mov     rbp, [r9+28h]
0x319B94: 4C8BBDA8000000                   mov     r15, [rbp+0A8h]
0x021324: 448B7534                         mov     r14d, [rbp+34h]
0x319BFC: 4C03B5E8000000                   add     r14, [rbp+0E8h]
0x02132F: 458A2E                           mov     r13b, [r14]
0x319C66: 49C7C4FF000000                   mov     r12, 0FFh
0x021339: 49C1E428                         shl     r12, 28h
0x02133D: 49F7D4                           not     r12
0x021340: 4D21E7                           and     r15, r12
0x021343: 4D0FB6E5                         movzx   r12, r13b
0x021347: 49C1E428                         shl     r12, 28h
0x02134B: 4D09E7                           or      r15, r12
0x02142E: 498B5128                         mov     rdx, [r9+28h]
0x319D3E: 488B82F0000000                   mov     rax, [rdx+0F0h]
0x021439: 50                               push    rax
0x02143A: 4989E4                           mov     r12, rsp
0x319DA6: 488B9AF0000000                   mov     rbx, [rdx+0F0h]
0x021520: 4D8B6128                         mov     r12, [r9+28h]
0x319E77: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x319EE4: 498BBC2490000000                 mov     rdi, [r12+90h]
0x021534: 4157                             push    r15
0x021536: 680B021412                       push    1214020Bh
0x02153B: 680E248D02                       push    28D240Eh
0x021540: 68BD59522C                       push    2C5259BDh
0x021545: 687A0AB172                       push    72B10A7Ah
0x02162A: 4D8B7928                         mov     r15, [r9+28h]
0x319FBA: 498BB7E8000000                   mov     rsi, [r15+0E8h]
0x31A026: 498B9FB0000000                   mov     rbx, [r15+0B0h]
0x02163C: 480FB6F6                         movzx   rsi, sil
0x021724: 4D8B6928                         mov     r13, [r9+28h]
0x31A0FB: 410FAE95A8000000                 ldmxcsr dword ptr [r13+0A8h]
0x021730: 4D8B4928                         mov     r9, [r9+28h]
0x31A166: 4D8BA990000000                   mov     r13, [r9+90h]
0x31A1CE: 49BE57E6FF2901000000             mov     r14, 129FFE657h
0x31A23F: 4981C669740916                   add     r14, 16097469h
0x021834: 4D8B4128                         mov     r8, [r9+28h]
0x021838: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x31A30C: 498BA8A8000000                   mov     rbp, [r8+0A8h]
0x31A373: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x021924: 498B4128                         mov     rax, [r9+28h]
0x31A448: 488BB8E0000000                   mov     rdi, [rax+0E0h]
0x02192F: 448B5034                         mov     r10d, [rax+34h]
0x31A4B4: 4C0390A0000000                   add     r10, [rax+0A0h]
0x02193A: 418A1A                           mov     bl, [r10]
0x31A51E: 49C7C5FF000000                   mov     r13, 0FFh
0x021944: 49C1E538                         shl     r13, 38h
0x021948: 49F7D5                           not     r13
0x02194B: 4C21EF                           and     rdi, r13
0x02194E: 4C0FB6EB                         movzx   r13, bl
0x021952: 49C1E538                         shl     r13, 38h
0x021956: 4C09EF                           or      rdi, r13
0x31A5EB: 48BEC0446A2D01000000             mov     rsi, 12D6A44C0h
0x021A3E: 56                               push    rsi
0x021A3F: 68B52A7461                       push    61742AB5h
0x021A44: 68E2730A4B                       push    4B0A73E2h
0x021A49: 68EB422C29                       push    292C42EBh
0x021A4E: 68A66D443D                       push    3D446DA6h
0x31A65A: 488144242028741F13               add     [rsp-8+arg_20], 131F7428h
0x021A5C: 4D8B7928                         mov     r15, [r9+28h]
0x31A6CA: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x021B50: 498B4128                         mov     rax, [r9+28h]
0x31A79C: 488BB0D8000000                   mov     rsi, [rax+0D8h]
0x31A804: 488B98B0000000                   mov     rbx, [rax+0B0h]
0x021B62: 480FB6F6                         movzx   rsi, sil
0x021C46: 4D8B4128                         mov     r8, [r9+28h]
0x31A8D8: 498B80A8000000                   mov     rax, [r8+0A8h]
0x31A945: 48C7C33D0925E1                   mov     rbx, 0FFFFFFFFE125093Dh
0x31A9AD: 4881C38126D91F                   add     rbx, 1FD92681h
0x021C5F: 53                               push    rbx
0x31AA12: 4D8BB890000000                   mov     r15, [r8+90h]
0x021C67: 48F72424                         mul     qword ptr [rsp]
0x021C6B: 4889C6                           mov     rsi, rax
0x021D43: 4D8B6928                         mov     r13, [r9+28h]
0x31AADE: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x31AB47: 4D2BB5A8000000                   sub     r14, [r13+0A8h]
0x021E25: 4D8B5128                         mov     r10, [r9+28h]
0x31AC14: 4D8BAAE8000000                   mov     r13, [r10+0E8h]
0x021E30: 4155                             push    r13
0x021E32: 4889E6                           mov     rsi, rsp
0x31AC7F: 4D8BAAE8000000                   mov     r13, [r10+0E8h]
0x021F1A: 4D8B6128                         mov     r12, [r9+28h]
0x31AD52: 4D8BBC24B0000000                 mov     r15, [r12+0B0h]
0x31ADBD: 498B9C24E0000000                 mov     rbx, [r12+0E0h]
0x021F2E: 4D0FB6FF                         movzx   r15, r15b
0x02200F: 498B4928                         mov     rcx, [r9+28h]
0x31AE88: 0FAE91F0000000                   ldmxcsr dword ptr [rcx+0F0h]
0x31AEEF: 48BF23F6F10601000000             mov     rdi, 106F1F623h
0x31AF5A: 4881C79D6C1739                   add     rdi, 39176C9Dh
0x31AFC8: 488BBF20030000                   mov     rdi, [rdi+320h]
0x31B02D: 4803B9F0000000                   add     rdi, [rcx+0F0h]
0x022039: 408A3F                           mov     dil, [rdi]
0x02203C: 480FB6FF                         movzx   rdi, dil
0x022040: 48C1E708                         shl     rdi, 8
0x31B093: 4801B990000000                   add     [rcx+90h], rdi
0x31B0FD: 49BD121F9C3801000000             mov     r13, 1389C1F12h
0x022055: 4155                             push    r13
0x022057: 684A07D550                       push    50D5074Ah
0x02205C: 687D019B4D                       push    4D9B017Dh
0x022061: 68317D1368                       push    68137D31h
0x022066: 68814CCB38                       push    38CB4C81h
0x31B16A: 4881442420AE3B6D07               add     qword ptr [rsp+20h], 76D3BAEh
0x022074: 4D8B7128                         mov     r14, [r9+28h]
0x31B1D4: 4D8BBE90000000                   mov     r15, [r14+90h]
0x022166: 498B7128                         mov     rsi, [r9+28h]
0x02216A: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x31B2A5: 4C8BB6D8000000                   mov     r14, [rsi+0D8h]
0x31B30D: 488B9EF0000000                   mov     rbx, [rsi+0F0h]
0x022256: 498B5928                         mov     rbx, [r9+28h]
0x31B3DA: 4C8BBB90000000                   mov     r15, [rbx+90h]
0x022261: 8B6B34                           mov     ebp, [rbx+34h]
0x31B448: 4803ABE8000000                   add     rbp, [rbx+0E8h]
0x02226B: 8A4D00                           mov     cl, [rbp+0]
0x02226E: 4188CF                           mov     r15b, cl
0x022358: 4D8B7928                         mov     r15, [r9+28h]
0x31B519: 4D8BB7F0000000                   mov     r14, [r15+0F0h]
0x022363: 4156                             push    r14
0x022365: 4989E6                           mov     r14, rsp
0x31B57E: 498B9FF0000000                   mov     rbx, [r15+0F0h]
0x02244B: 498B5128                         mov     rdx, [r9+28h]
0x31B652: 4C8BBAE8000000                   mov     r15, [rdx+0E8h]
0x31B6BE: 4C8BA290000000                   mov     r12, [rdx+90h]
0x02245D: 4157                             push    r15
0x02245F: 68C546CE4F                       push    4FCE46C5h
0x022464: 683974D22E                       push    2ED27439h
0x022469: 682514C33E                       push    3EC31425h
0x02246E: 68C73BA029                       push    29A03BC7h
0x022566: 4D8B7128                         mov     r14, [r9+28h]
0x31B791: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x31B7FB: 4D8BBED8000000                   mov     r15, [r14+0D8h]
0x022578: 480FB6DB                         movzx   rbx, bl
0x022659: 498B4128                         mov     rax, [r9+28h]
0x31B8D4: 0FAE9090000000                   ldmxcsr dword ptr [rax+90h]
0x31B939: 48BBD8FAF5CE00000000             mov     rbx, 0CEF5FAD8h
0x31B9A1: 4881C3E8671371                   add     rbx, 711367E8h
0x31BA09: 488B9B58010000                   mov     rbx, [rbx+158h]
0x31BA6E: 48039890000000                   add     rbx, [rax+90h]
0x022683: 8A0B                             mov     cl, [rbx]
0x022685: 480FB6C9                         movzx   rcx, cl
0x022689: 48C1E110                         shl     rcx, 10h
0x31BAD8: 480188F0000000                   add     [rax+0F0h], rcx
0x31BB40: 49BB8B3D312E01000000             mov     r11, 12E313D8Bh
0x02269E: 4153                             push    r11
0x0226A0: 68D7265412                       push    125426D7h
0x0226A5: 68DD06F520                       push    20F506DDh
0x0226AA: 6886557231                       push    31725586h
0x31BBA9: 4881442418351DD811               add     qword ptr [rsp+18h], 11D81D35h
0x0226B8: 498B5928                         mov     rbx, [r9+28h]
0x31BC16: 4C8BB3F0000000                   mov     r14, [rbx+0F0h]
0x0227AE: 4D8B7128                         mov     r14, [r9+28h]
0x0227B2: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x31BCEC: 4D8BBEB8000000                   mov     r15, [r14+0B8h]
0x31BD5A: 498B9EE8000000                   mov     rbx, [r14+0E8h]
0x0228B9: 4D8B7128                         mov     r14, [r9+28h]
0x31BE30: 4D8BA690000000                   mov     r12, [r14+90h]
0x0228C4: 458B7E34                         mov     r15d, [r14+34h]
0x31BE9A: 4D03BEF0000000                   add     r15, [r14+0F0h]
0x0228CF: 418A0F                           mov     cl, [r15]
0x31BF06: 49C7C5FF000000                   mov     r13, 0FFh
0x0228D9: 49C1E508                         shl     r13, 8
0x0228DD: 49F7D5                           not     r13
0x0228E0: 4D21EC                           and     r12, r13
0x0228E3: 4C0FB6E9                         movzx   r13, cl
0x0228E7: 49C1E508                         shl     r13, 8
0x0228EB: 4D09EC                           or      r12, r13
0x0229CA: 498B6928                         mov     rbp, [r9+28h]
0x31BFE0: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x0229D5: 56                               push    rsi
0x0229D6: 4989E6                           mov     r14, rsp
0x31C04C: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x022ACD: 498B5928                         mov     rbx, [r9+28h]
0x31C118: 4C8BA3F0000000                   mov     r12, [rbx+0F0h]
0x31C180: 488BBBA8000000                   mov     rdi, [rbx+0A8h]
0x022ADF: 4D0FB6E4                         movzx   r12, r12b
0x022BBB: 4D8B7928                         mov     r15, [r9+28h]
0x31C253: 410FAE97D8000000                 ldmxcsr dword ptr [r15+0D8h]
0x31C2BF: 48B82844AF2601000000             mov     rax, 126AF4428h
0x31C32B: 4805981E5A19                     add     rax, 195A1E98h
0x31C38F: 488B8040030000                   mov     rax, [rax+340h]
0x31C3F7: 490387D8000000                   add     rax, [r15+0D8h]
0x022BE5: 448A20                           mov     r12b, [rax]
0x022BE8: 4D0FB6E4                         movzx   r12, r12b
0x022BEC: 49C1E418                         shl     r12, 18h
0x31C45C: 4D01A7B0000000                   add     [r15+0B0h], r12
0x31C4C2: 48B88C2187E000000000             mov     rax, 0E087218Ch
0x022C01: 50                               push    rax
0x022C02: 683B1D1304                       push    4131D3Bh
0x022C07: 68AE19E83B                       push    3BE819AEh
0x022C0C: 68C9276B39                       push    396B27C9h
0x022C11: 68C1180312                       push    120318C1h
0x31C52B: 48814424203439825F               add     qword ptr [rsp+20h], 5F823934h
0x022C1F: 4D8B6128                         mov     r12, [r9+28h]
0x31C599: 498B9C24B0000000                 mov     rbx, [r12+0B0h]
0x022D20: 4D8B5928                         mov     r11, [r9+28h]
0x022D24: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x31C668: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x31C6D5: 4D8BA390000000                   mov     r12, [r11+90h]
0x022E11: 4D8B6128                         mov     r12, [r9+28h]
0x31C79F: 498BAC24D8000000                 mov     rbp, [r12+0D8h]
0x022E1D: 458B542434                       mov     r10d, [r12+34h]
0x31C80C: 4D039424E8000000                 add     r10, [r12+0E8h]
0x022E2A: 418A12                           mov     dl, [r10]
0x31C872: 48C7C1FF000000                   mov     rcx, 0FFh
0x022E34: 48C1E110                         shl     rcx, 10h
0x022E38: 48F7D1                           not     rcx
0x022E3B: 4821CD                           and     rbp, rcx
0x022E3E: 480FB6CA                         movzx   rcx, dl
0x022E42: 48C1E110                         shl     rcx, 10h
0x022E46: 4809CD                           or      rbp, rcx
0x022F2F: 4D8B6928                         mov     r13, [r9+28h]
0x31C940: 4D8BB5A0000000                   mov     r14, [r13+0A0h]
0x022F3A: 4156                             push    r14
0x022F3C: 4889E7                           mov     rdi, rsp
0x31C9A7: 4D8BB5A0000000                   mov     r14, [r13+0A0h]
0x02303B: 4D8B5128                         mov     r10, [r9+28h]
0x02303F: 498B5A78                         mov     rbx, [r10+78h]
0x31CA80: 4D8BBAE8000000                   mov     r15, [r10+0E8h]
0x02304A: 480FB6DB                         movzx   rbx, bl
0x02312A: 498B4128                         mov     rax, [r9+28h]
0x31CB56: 0FAE9090000000                   ldmxcsr dword ptr [rax+90h]
0x31CBC3: 48BF14407FD800000000             mov     rdi, 0D87F4014h
0x31CC33: 4881C7AC228A67                   add     rdi, 678A22ACh
0x31CC9B: 488BBFA8060000                   mov     rdi, [rdi+6A8h]
0x31CD01: 4803B890000000                   add     rdi, [rax+90h]
0x023154: 448A3F                           mov     r15b, [rdi]
0x023157: 4D0FB6FF                         movzx   r15, r15b
0x02315B: 49C1E720                         shl     r15, 20h
0x31CD69: 4C01B8F0000000                   add     [rax+0F0h], r15
0x023166: 4D8B5128                         mov     r10, [r9+28h]
0x31CDD3: 4D8BA2F0000000                   mov     r12, [r10+0F0h]
0x31CE38: 48BB09DB810201000000             mov     rbx, 10281DB09h
0x31CEA0: 4881C3B77F873D                   add     rbx, 3D877FB7h
0x023263: 498B4928                         mov     rcx, [r9+28h]
0x023267: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x31CF73: 488BB9B0000000                   mov     rdi, [rcx+0B0h]
0x31CFE0: 488BB1D8000000                   mov     rsi, [rcx+0D8h]
0x02335C: 4D8B4928                         mov     r9, [r9+28h]
0x31D0AB: 4D8BA1A8000000                   mov     r12, [r9+0A8h]
0x023367: 458B5134                         mov     r10d, [r9+34h]
0x31D110: 4D0391B0000000                   add     r10, [r9+0B0h]
0x023372: 458A0A                           mov     r9b, [r10]
0x31D177: 48C7C6FF000000                   mov     rsi, 0FFh
0x02337C: 48C1E618                         shl     rsi, 18h
0x023380: 48F7D6                           not     rsi
0x023383: 4921F4                           and     r12, rsi
0x023386: 490FB6F1                         movzx   rsi, r9b
0x02338A: 48C1E618                         shl     rsi, 18h
0x02338E: 4909F4                           or      r12, rsi
0x023477: 4D8B6128                         mov     r12, [r9+28h]
0x31D24F: 4D8BAC24D8000000                 mov     r13, [r12+0D8h]
0x023483: 4155                             push    r13
0x023485: 4989E6                           mov     r14, rsp
0x31D2BC: 4D8BA424D8000000                 mov     r12, [r12+0D8h]
0x023580: 498B6928                         mov     rbp, [r9+28h]
0x31D38F: 4C8BA5D0000000                   mov     r12, [rbp+0D0h]
0x31D3F4: 4C8BADD8000000                   mov     r13, [rbp+0D8h]
0x023592: 4D0FB6E4                         movzx   r12, r12b
0x02367F: 498B6928                         mov     rbp, [r9+28h]
0x31D4C0: 0FAE95D8000000                   ldmxcsr dword ptr [rbp+0D8h]
0x31D527: 48BE3C3BE51F01000000             mov     rsi, 11FE53B3Ch
0x31D590: 4881C684272420                   add     rsi, 20242784h
0x02369B: 488B36                           mov     rsi, [rsi]
0x31D5F7: 4803B5D8000000                   add     rsi, [rbp+0D8h]
0x0236A5: 448A36                           mov     r14b, [rsi]
0x0236A8: 4D0FB6F6                         movzx   r14, r14b
0x0236AC: 49C1E628                         shl     r14, 28h
0x31D664: 4C01B5E0000000                   add     [rbp+0E0h], r14
0x0236B7: 498B5128                         mov     rdx, [r9+28h]
0x31D6D2: 488BBAE0000000                   mov     rdi, [rdx+0E0h]
0x31D73B: 49BE0DF2DB3801000000             mov     r14, 138DBF20Dh
0x31D7A8: 4981C6B3682D07                   add     r14, 72D68B3h
0x0237C0: 4D8B4128                         mov     r8, [r9+28h]
0x0237C4: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x31D87A: 498BB080000000                   mov     rsi, [r8+80h]
0x31D8E7: 4D8BB0B0000000                   mov     r14, [r8+0B0h]
0x0238B3: 4D8B5128                         mov     r10, [r9+28h]
0x31D9B6: 498BBAE8000000                   mov     rdi, [r10+0E8h]
0x0238BE: 458B5A34                         mov     r11d, [r10+34h]
0x31DA1F: 4D039AA8000000                   add     r11, [r10+0A8h]
0x0238C9: 458A23                           mov     r12b, [r11]
0x31DA89: 49C7C6FF000000                   mov     r14, 0FFh
0x0238D3: 49C1E620                         shl     r14, 20h
0x0238D7: 49F7D6                           not     r14
0x0238DA: 4C21F7                           and     rdi, r14
0x0238DD: 4D0FB6F4                         movzx   r14, r12b
0x0238E1: 49C1E620                         shl     r14, 20h
0x0238E5: 4C09F7                           or      rdi, r14
0x0239B9: 498B5928                         mov     rbx, [r9+28h]
0x31DB58: 4C8BA3B0000000                   mov     r12, [rbx+0B0h]
0x0239C4: 4154                             push    r12
0x0239C6: 4889E6                           mov     rsi, rsp
0x31DBC1: 4C8BBBB0000000                   mov     r15, [rbx+0B0h]
0x023ABF: 498B5928                         mov     rbx, [r9+28h]
0x31DC91: 4C8B83A8000000                   mov     r8, [rbx+0A8h]
0x31DCF6: 4C8BB3F0000000                   mov     r14, [rbx+0F0h]
0x023AD1: 4150                             push    r8
0x023AD3: 686D09A922                       push    22A9096Dh
0x023AD8: 681C6EFE60                       push    60FE6E1Ch
0x023ADD: 6897783F51                       push    513F7897h
0x023BD3: 4D8B7928                         mov     r15, [r9+28h]
0x31DDC3: 498BBFE0000000                   mov     rdi, [r15+0E0h]
0x31DE2A: 498BAFE8000000                   mov     rbp, [r15+0E8h]
0x023BE5: 480FB6FF                         movzx   rdi, dil
0x023CBA: 4D8B7928                         mov     r15, [r9+28h]
0x31DEF7: 410FAE97B0000000                 ldmxcsr dword ptr [r15+0B0h]
0x31DF61: 48BEDF4245F900000000             mov     rsi, 0F94542DFh
0x31DFD1: 4881C6E11FC446                   add     rsi, 46C41FE1h
0x023CD7: 488B36                           mov     rsi, [rsi]
0x31E03F: 4903B7B0000000                   add     rsi, [r15+0B0h]
0x023CE1: 448A36                           mov     r14b, [rsi]
0x023CE4: 4D0FB6F6                         movzx   r14, r14b
0x023CE8: 49C1E630                         shl     r14, 30h
0x31E0AA: 4D01B7A0000000                   add     [r15+0A0h], r14
0x31E112: 49BD7D0B27FA00000000             mov     r13, 0FA270B7Dh
0x023CFD: 4155                             push    r13
0x023CFF: 684D23A72D                       push    2DA7234Dh
0x023D04: 6877335D4D                       push    4D5D3377h
0x023D09: 68D86F5421                       push    21546FD8h
0x023D0E: 68A062A70E                       push    0EA762A0h
0x31E180: 4881442420434FE245               add     qword ptr [rsp+20h], 45E24F43h
0x023D1C: 4D8B6928                         mov     r13, [r9+28h]
0x31E1EF: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x023E05: 498B4928                         mov     rcx, [r9+28h]
0x023E09: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x31E2C3: 488B99D0000000                   mov     rbx, [rcx+0D0h]
0x31E328: 4C8BA9A8000000                   mov     r13, [rcx+0A8h]
0x023EFA: 498B5128                         mov     rdx, [r9+28h]
0x31E3FA: 488B9AE0000000                   mov     rbx, [rdx+0E0h]
0x023F05: 8B4A34                           mov     ecx, [rdx+34h]
0x31E468: 48038A90000000                   add     rcx, [rdx+90h]
0x023F0F: 8A11                             mov     dl, [rcx]
0x31E4D6: 49C7C6FF000000                   mov     r14, 0FFh
0x023F18: 49C1E628                         shl     r14, 28h
0x023F1C: 49F7D6                           not     r14
0x023F1F: 4C21F3                           and     rbx, r14
0x023F22: 4C0FB6F2                         movzx   r14, dl
0x023F26: 49C1E628                         shl     r14, 28h
0x023F2A: 4C09F3                           or      rbx, r14
0x024008: 4D8B6128                         mov     r12, [r9+28h]
0x31E5AD: 4D8BAC2490000000                 mov     r13, [r12+90h]
0x024014: 4155                             push    r13
0x024016: 4989E6                           mov     r14, rsp
0x31E614: 4D8BAC2490000000                 mov     r13, [r12+90h]
0x02410B: 4D8B7928                         mov     r15, [r9+28h]
0x31E6E5: 4D8B8FE8000000                   mov     r9, [r15+0E8h]
0x31E74D: 4D8BAFE0000000                   mov     r13, [r15+0E0h]
0x02411D: 4151                             push    r9
0x02411F: 68F77E441F                       push    1F447EF7h
0x024124: 684036D34D                       push    4DD33640h
0x024129: 68F8649E6B                       push    6B9E64F8h
0x024224: 498B4928                         mov     rcx, [r9+28h]
0x31E81F: 4C8BA1D0000000                   mov     r12, [rcx+0D0h]
0x31E88C: 488BB9E0000000                   mov     rdi, [rcx+0E0h]
0x024236: 4D0FB6E4                         movzx   r12, r12b
0x024324: 4D8B7128                         mov     r14, [r9+28h]
0x31E960: 410FAE96D8000000                 ldmxcsr dword ptr [r14+0D8h]
0x31E9C8: 48BEECE2ECC100000000             mov     rsi, 0C1ECE2ECh
0x02433A: 56                               push    rsi
0x02433B: 684A1F5B5C                       push    5C5B1F4Ah
0x024340: 684A4D4424                       push    24444D4Ah
0x024345: 68707B5215                       push    15527B70h
0x31EA32: 4881442418D4771C7E               add     qword ptr [rsp+18h], 7E1C77D4h
0x024353: 498B7928                         mov     rdi, [r9+28h]
0x31EAA0: 4C8BBFB0000000                   mov     r15, [rdi+0B0h]
0x024447: 4D8B4128                         mov     r8, [r9+28h]
0x02444B: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x31EB74: 498BA890000000                   mov     rbp, [r8+90h]
0x31EBDB: 4D8BA8F0000000                   mov     r13, [r8+0F0h]
0x02453E: 498B4128                         mov     rax, [r9+28h]
0x31ECAE: 488B98E0000000                   mov     rbx, [rax+0E0h]
0x024549: 448B4034                         mov     r8d, [rax+34h]
0x31ED16: 4C0380A0000000                   add     r8, [rax+0A0h]
0x024554: 418A10                           mov     dl, [r8]
0x31ED7F: 48C7C1FF000000                   mov     rcx, 0FFh
0x02455E: 48C1E138                         shl     rcx, 38h
0x024562: 48F7D1                           not     rcx
0x024565: 4821CB                           and     rbx, rcx
0x024568: 480FB6CA                         movzx   rcx, dl
0x02456C: 48C1E138                         shl     rcx, 38h
0x024570: 4809CB                           or      rbx, rcx
0x024655: 4D8B6128                         mov     r12, [r9+28h]
0x31EE48: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x31EEB1: 48BFDAB4AF2601000000             mov     rdi, 126AFB4DAh
0x31EF1C: 4881C70E04DA19                   add     rdi, 19DA040Eh
0x024758: 498B4928                         mov     rcx, [r9+28h]
0x31EFE9: 4C8BA9C8000000                   mov     r13, [rcx+0C8h]
0x31F055: 488BB9F0000000                   mov     rdi, [rcx+0F0h]
0x02476A: 4D0FB6ED                         movzx   r13, r13b
0x02485B: 4D8B6128                         mov     r12, [r9+28h]
0x31F126: 498B8424E0000000                 mov     rax, [r12+0E0h]
0x31F190: 49C7C33A881CE6                   mov     r11, 0FFFFFFFFE61C883Ah
0x31F1F7: 4981C3F55CBB1A                   add     r11, 1ABB5CF5h
0x024875: 4153                             push    r11
0x31F265: 498BB424B0000000                 mov     rsi, [r12+0B0h]
0x02487F: 48F72424                         mul     qword ptr [rsp]
0x024883: 4989C5                           mov     r13, rax
0x02496A: 498B7128                         mov     rsi, [r9+28h]
0x31F33F: 488B9EA8000000                   mov     rbx, [rsi+0A8h]
0x31F3A9: 482B9EE0000000                   sub     rbx, [rsi+0E0h]
0x024A5C: 498B7128                         mov     rsi, [r9+28h]
0x31F479: 488B9E90000000                   mov     rbx, [rsi+90h]
0x024A67: 53                               push    rbx
0x024A68: 4989E6                           mov     r14, rsp
0x31F4E7: 4C8BBE90000000                   mov     r15, [rsi+90h]
0x024B47: 498B7128                         mov     rsi, [r9+28h]
0x31F5B8: 4C8B86E8000000                   mov     r8, [rsi+0E8h]
0x31F620: 4C8BB6F0000000                   mov     r14, [rsi+0F0h]
0x024B59: 4150                             push    r8
0x024B5B: 68DC5D2533                       push    33255DDCh
0x024B60: 68B916A10E                       push    0EA116B9h
0x024B65: 682D18315C                       push    5C31182Dh
0x024B6A: 68AE48F457                       push    57F448AEh
0x024C4F: 4D8B5928                         mov     r11, [r9+28h]
0x31F6F8: 4D8BABC8000000                   mov     r13, [r11+0C8h]
0x31F763: 498B9BE8000000                   mov     rbx, [r11+0E8h]
0x024C61: 4D0FB6ED                         movzx   r13, r13b
0x024D57: 498B7928                         mov     rdi, [r9+28h]
0x31F831: 0FAE97E0000000                   ldmxcsr dword ptr [rdi+0E0h]
0x31F89D: 49BD495FA8C900000000             mov     r13, 0C9A85F49h
0x31F907: 4981C577036176                   add     r13, 76610377h
0x31F970: 4D8BADC0000000                   mov     r13, [r13+0C0h]
0x31F9DD: 4C03AFE0000000                   add     r13, [rdi+0E0h]
0x024D81: 458A6500                         mov     r12b, [r13+0]
0x024D85: 4D0FB6E4                         movzx   r12, r12b
0x024D89: 49C1E408                         shl     r12, 8
0x31FA43: 4C01A790000000                   add     [rdi+90h], r12
0x024D94: 4D8B6128                         mov     r12, [r9+28h]
0x31FAA8: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x31FB17: 48BDE04405E200000000             mov     rbp, 0E20544E0h
0x31FB80: 4881C5E015045E                   add     rbp, 5E0415E0h
0x024E97: 498B5128                         mov     rdx, [r9+28h]
0x024E9B: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x31FC4B: 488BBAB8000000                   mov     rdi, [rdx+0B8h]
0x31FCB6: 4C8BAAF0000000                   mov     r13, [rdx+0F0h]
0x024F85: 498B7128                         mov     rsi, [r9+28h]
0x31FD8C: 4C8BA6E0000000                   mov     r12, [rsi+0E0h]
0x024F90: 448B7634                         mov     r14d, [rsi+34h]
0x31FDF7: 4C03B6B0000000                   add     r14, [rsi+0B0h]
0x024F9B: 418A0E                           mov     cl, [r14]
0x024F9E: 4188CC                           mov     r12b, cl
0x02507A: 4D8B6928                         mov     r13, [r9+28h]
0x31FEC3: 498B95D8000000                   mov     rdx, [r13+0D8h]
0x025085: 52                               push    rdx
0x025086: 4989E6                           mov     r14, rsp
0x31FF30: 4D8BADD8000000                   mov     r13, [r13+0D8h]
0x025189: 4D8B7128                         mov     r14, [r9+28h]
0x31FFFF: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x320064: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x02519B: 480FB6ED                         movzx   rbp, bpl
0x025281: 4D8B7128                         mov     r14, [r9+28h]
0x320135: 410FAE96A0000000                 ldmxcsr dword ptr [r14+0A0h]
0x32019D: 48B87727110801000000             mov     rax, 108112777h
0x32020B: 4805493BF837                     add     rax, 37F83B49h
0x320274: 488B8080060000                   mov     rax, [rax+680h]
0x3202E1: 490386A0000000                   add     rax, [r14+0A0h]
0x0252AB: 448A00                           mov     r8b, [rax]
0x0252AE: 4D0FB6C0                         movzx   r8, r8b
0x0252B2: 49C1E010                         shl     r8, 10h
0x32034B: 4D0186B0000000                   add     [r14+0B0h], r8
0x3203B7: 49BAA1E7C2ED00000000             mov     r10, 0EDC2E7A1h
0x0252C7: 4152                             push    r10
0x0252C9: 68FB4ECD0D                       push    0DCD4EFBh
0x0252CE: 6833686033                       push    33606833h
0x0252D3: 68EC257E68                       push    687E25ECh
0x320427: 48814424181F734652               add     [rsp-8+arg_18], 5246731Fh
0x0252E1: 4D8B5128                         mov     r10, [r9+28h]
0x320491: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x0253E0: 4D8B4128                         mov     r8, [r9+28h]
0x0253E4: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x32055F: 498BA8C8000000                   mov     rbp, [r8+0C8h]
0x3205CD: 4D8BB890000000                   mov     r15, [r8+90h]
0x0254E6: 4D8B7928                         mov     r15, [r9+28h]
0x32069A: 4D8BAFF0000000                   mov     r13, [r15+0F0h]
0x0254F1: 458B6734                         mov     r12d, [r15+34h]
0x320704: 4D03A7A0000000                   add     r12, [r15+0A0h]
0x0254FC: 458A1424                         mov     r10b, [r12]
0x32076E: 48C7C3FF000000                   mov     rbx, 0FFh
0x025507: 48C1E308                         shl     rbx, 8
0x02550B: 48F7D3                           not     rbx
0x02550E: 4921DD                           and     r13, rbx
0x025511: 490FB6DA                         movzx   rbx, r10b
0x025515: 48C1E308                         shl     rbx, 8
0x025519: 4909DD                           or      r13, rbx
0x025600: 498B6928                         mov     rbp, [r9+28h]
0x32083D: 4C8BB5E0000000                   mov     r14, [rbp+0E0h]
0x02560B: 4156                             push    r14
0x02560D: 4889E6                           mov     rsi, rsp
0x3208A9: 488BADE0000000                   mov     rbp, [rbp+0E0h]
0x025710: 498B7128                         mov     rsi, [r9+28h]
0x320980: 488BAEB8000000                   mov     rbp, [rsi+0B8h]
0x3209E6: 4C8BAEA0000000                   mov     r13, [rsi+0A0h]
0x025722: 480FB6ED                         movzx   rbp, bpl
0x025803: 4D8B7128                         mov     r14, [r9+28h]
0x320AB2: 410FAE96A0000000                 ldmxcsr dword ptr [r14+0A0h]
0x320B19: 49BDD251A11501000000             mov     r13, 115A151D2h
0x320B88: 4981C5EE10682A                   add     r13, 2A6810EEh
0x320BF0: 4D8BAD58040000                   mov     r13, [r13+458h]
0x320C56: 4D03AEA0000000                   add     r13, [r14+0A0h]
0x02582E: 458A4500                         mov     r8b, [r13+0]
0x025832: 4D0FB6C0                         movzx   r8, r8b
0x025836: 49C1E018                         shl     r8, 18h
0x320CC3: 4D0186E0000000                   add     [r14+0E0h], r8
0x025841: 498B7928                         mov     rdi, [r9+28h]
0x320D2C: 4C8BAFE0000000                   mov     r13, [rdi+0E0h]
0x320D93: 49BCE50539D200000000             mov     r12, 0D23905E5h
0x320DFB: 4981C4DB54D06D                   add     r12, 6DD054DBh
0x02594E: 498B4928                         mov     rcx, [r9+28h]
0x025952: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x320ECF: 488BA9C8000000                   mov     rbp, [rcx+0C8h]
0x320F34: 4C8BB9E0000000                   mov     r15, [rcx+0E0h]
0x025A3E: 4D8B5928                         mov     r11, [r9+28h]
0x321001: 4D8BB3F0000000                   mov     r14, [r11+0F0h]
0x025A49: 418B6B34                         mov     ebp, [r11+34h]
0x32106D: 4903ABA0000000                   add     rbp, [r11+0A0h]
0x025A54: 448A4500                         mov     r8b, [rbp+0]
0x3210D7: 49C7C4FF000000                   mov     r12, 0FFh
0x025A5F: 49C1E410                         shl     r12, 10h
0x025A63: 49F7D4                           not     r12
0x025A66: 4D21E6                           and     r14, r12
0x025A69: 4D0FB6E0                         movzx   r12, r8b
0x025A6D: 49C1E410                         shl     r12, 10h
0x025A71: 4D09E6                           or      r14, r12
0x025B61: 498B5128                         mov     rdx, [r9+28h]
0x3211AC: 488B82E8000000                   mov     rax, [rdx+0E8h]
0x025B6C: 50                               push    rax
0x025B6D: 4989E4                           mov     r12, rsp
0x321215: 4C8BAAE8000000                   mov     r13, [rdx+0E8h]
0x025C61: 4D8B4928                         mov     r9, [r9+28h]
0x3212E6: 498B81D8000000                   mov     rax, [r9+0D8h]
0x321352: 4D8BA9E0000000                   mov     r13, [r9+0E0h]
0x025C73: 50                               push    rax
0x025C74: 686D38FC3C                       push    3CFC386Dh
0x025C79: 68FB5E6F6D                       push    6D6F5EFBh
0x025C7E: 686E1A5029                       push    29501A6Eh
0x025D66: 4D8B5928                         mov     r11, [r9+28h]
0x321421: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x321488: 498B9BE0000000                   mov     rbx, [r11+0E0h]
0x025D78: 4D0FB6F6                         movzx   r14, r14b
0x025E4D: 498B7128                         mov     rsi, [r9+28h]
0x321555: 0FAE96E8000000                   ldmxcsr dword ptr [rsi+0E8h]
0x3215BA: 49BC323F49F300000000             mov     r12, 0F3493F32h
0x32162A: 4981C48E23C04C                   add     r12, 4CC0238Eh
0x321691: 4D8BA424C8030000                 mov     r12, [r12+3C8h]
0x3216FC: 4C03A6E8000000                   add     r12, [rsi+0E8h]
0x025E78: 458A0424                         mov     r8b, [r12]
0x025E7C: 4D0FB6C0                         movzx   r8, r8b
0x025E80: 49C1E020                         shl     r8, 20h
0x321764: 4C018690000000                   add     [rsi+90h], r8
0x025E8B: 4D8B5928                         mov     r11, [r9+28h]
0x3217D2: 4D8BB390000000                   mov     r14, [r11+90h]
0x321837: 49BC9FE216C200000000             mov     r12, 0C216E29Fh
0x32189F: 4981C42178F27D                   add     r12, 7DF27821h
0x025F9B: 4D8B5928                         mov     r11, [r9+28h]
0x025F9F: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x321976: 498B9BC0000000                   mov     rbx, [r11+0C0h]
0x3219E1: 4D8BA3E8000000                   mov     r12, [r11+0E8h]
0x02609F: 498B4128                         mov     rax, [r9+28h]
0x321AB5: 4C8BA8D8000000                   mov     r13, [rax+0D8h]
0x0260AA: 8B4834                           mov     ecx, [rax+34h]
0x321B22: 48038890000000                   add     rcx, [rax+90h]
0x0260B4: 8A11                             mov     dl, [rcx]
0x321B8E: 49C7C1FF000000                   mov     r9, 0FFh
0x0260BD: 49C1E118                         shl     r9, 18h
0x0260C1: 49F7D1                           not     r9
0x0260C4: 4D21CD                           and     r13, r9
0x0260C7: 4C0FB6CA                         movzx   r9, dl
0x0260CB: 49C1E118                         shl     r9, 18h
0x0260CF: 4D09CD                           or      r13, r9
0x0261A8: 498B5928                         mov     rbx, [r9+28h]
0x321C60: 488BB3E0000000                   mov     rsi, [rbx+0E0h]
0x0261B3: 56                               push    rsi
0x0261B4: 4989E7                           mov     r15, rsp
0x321CCE: 4C8BABE0000000                   mov     r13, [rbx+0E0h]
0x0262A2: 498B6928                         mov     rbp, [r9+28h]
0x321DA4: 4C8BA5F0000000                   mov     r12, [rbp+0F0h]
0x321E0F: 4C8BBDE0000000                   mov     r15, [rbp+0E0h]
0x0262B4: 4154                             push    r12
0x0262B6: 6881404B37                       push    374B4081h
0x0262BB: 682B704012                       push    1240702Bh
0x0262C0: 689218D907                       push    7D91892h
0x0263A7: 498B5128                         mov     rdx, [r9+28h]
0x0263AB: 4C8B6278                         mov     r12, [rdx+78h]
0x321EE2: 488B9AF0000000                   mov     rbx, [rdx+0F0h]
0x0263B6: 4D0FB6E4                         movzx   r12, r12b
0x02649E: 498B4128                         mov     rax, [r9+28h]
0x321FB4: 0FAE90D8000000                   ldmxcsr dword ptr [rax+0D8h]
0x322022: 48BA3A390D2401000000             mov     rdx, 1240D393Ah
0x32208A: 4881C28629FC1B                   add     rdx, 1BFC2986h
0x0264BA: 488B12                           mov     rdx, [rdx]
0x3220F3: 480390D8000000                   add     rdx, [rax+0D8h]
0x0264C4: 8A0A                             mov     cl, [rdx]
0x0264C6: 480FB6C9                         movzx   rcx, cl
0x0264CA: 48C1E128                         shl     rcx, 28h
0x32215E: 48018890000000                   add     [rax+90h], rcx
0x0264D5: 4D8B6128                         mov     r12, [r9+28h]
0x3221C6: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x322230: 48BFA5EE6B3901000000             mov     rdi, 1396BEEA5h
0x3222A0: 4881C71B6C9D06                   add     rdi, 69D6C1Bh
0x0265D7: 498B4128                         mov     rax, [r9+28h]
0x0265DB: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x322372: 488BB890000000                   mov     rdi, [rax+90h]
0x3223D7: 4C8BA8F0000000                   mov     r13, [rax+0F0h]
0x0266D8: 4D8B5128                         mov     r10, [r9+28h]
0x3224A8: 4D8BA2E0000000                   mov     r12, [r10+0E0h]
0x0266E3: 418B5A34                         mov     ebx, [r10+34h]
0x32250E: 49039AB0000000                   add     rbx, [r10+0B0h]
0x0266EE: 8A03                             mov     al, [rbx]
0x32257A: 48C7C2FF000000                   mov     rdx, 0FFh
0x0266F7: 48C1E220                         shl     rdx, 20h
0x0266FB: 48F7D2                           not     rdx
0x0266FE: 4921D4                           and     r12, rdx
0x026701: 480FB6D0                         movzx   rdx, al
0x026705: 48C1E220                         shl     rdx, 20h
0x026709: 4909D4                           or      r12, rdx
0x0267F4: 4D8B7928                         mov     r15, [r9+28h]
0x322643: 498BB7D8000000                   mov     rsi, [r15+0D8h]
0x0267FF: 56                               push    rsi
0x026800: 4889E7                           mov     rdi, rsp
0x3226A9: 4D8BAFD8000000                   mov     r13, [r15+0D8h]
0x0268F6: 4D8B4128                         mov     r8, [r9+28h]
0x322778: 4D8B98B0000000                   mov     r11, [r8+0B0h]
0x3227DD: 498BA8E0000000                   mov     rbp, [r8+0E0h]
0x026908: 4153                             push    r11
0x02690A: 68EB35914E                       push    4E9135EBh
0x02690F: 68403CFE4E                       push    4EFE3C40h
0x026914: 684D3BF920                       push    20F93B4Dh
0x0269F3: 498B5128                         mov     rdx, [r9+28h]
0x3228B0: 488BAA88000000                   mov     rbp, [rdx+88h]
0x32291A: 4C8BB2A0000000                   mov     r14, [rdx+0A0h]
0x026A05: 480FB6ED                         movzx   rbp, bpl
0x026B00: 498B6928                         mov     rbp, [r9+28h]
0x3229E8: 0FAE95A0000000                   ldmxcsr dword ptr [rbp+0A0h]
0x322A4D: 49BE3913350501000000             mov     r14, 105351339h
0x322AB7: 4981C6874FD43A                   add     r14, 3AD44F87h
0x026B1C: 4D8B36                           mov     r14, [r14]
0x322B1D: 4C03B5A0000000                   add     r14, [rbp+0A0h]
0x026B26: 458A26                           mov     r12b, [r14]
0x026B29: 4D0FB6E4                         movzx   r12, r12b
0x026B2D: 49C1E438                         shl     r12, 38h
0x322B82: 4C01A5E8000000                   add     [rbp+0E8h], r12
0x026B38: 498B4928                         mov     rcx, [r9+28h]
0x322BEF: 4C8BA1E8000000                   mov     r12, [rcx+0E8h]
0x322C55: 48BBAB03EDF700000000             mov     rbx, 0F7ED03ABh
0x322CBE: 4881C315571C48                   add     rbx, 481C5715h
0x026C2F: 498B4128                         mov     rax, [r9+28h]
0x026C33: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x322D93: 4C8BB8E8000000                   mov     r15, [rax+0E8h]
0x322DFA: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x026D29: 4D8B6128                         mov     r12, [r9+28h]
0x322ECD: 4D8BBC24D8000000                 mov     r15, [r12+0D8h]
0x026D35: 418B442434                       mov     eax, [r12+34h]
0x322F34: 49038424F0000000                 add     rax, [r12+0F0h]
0x026D42: 448A30                           mov     r14b, [rax]
0x322FA3: 49C7C5FF000000                   mov     r13, 0FFh
0x026D4C: 49C1E530                         shl     r13, 30h
0x026D50: 49F7D5                           not     r13
0x026D53: 4D21EF                           and     r15, r13
0x026D56: 4D0FB6EE                         movzx   r13, r14b
0x026D5A: 49C1E530                         shl     r13, 30h
0x026D5E: 4D09EF                           or      r15, r13
0x026E3E: 498B5128                         mov     rdx, [r9+28h]
0x323079: 4C8BA2F0000000                   mov     r12, [rdx+0F0h]
0x3230E0: 48BE3DB6892001000000             mov     rsi, 12089B63Dh
0x32314A: 4881C6AB020020                   add     rsi, 200002ABh
0x026F49: 4D8B5928                         mov     r11, [r9+28h]
0x323223: 4D8BB380000000                   mov     r14, [r11+80h]
0x32328D: 4D8BBBD8000000                   mov     r15, [r11+0D8h]
0x026F5B: 4D0FB6F6                         movzx   r14, r14b
0x027043: 498B6928                         mov     rbp, [r9+28h]
0x32335E: 488B85E8000000                   mov     rax, [rbp+0E8h]
0x3233CA: 48C7C7AB258ED2                   mov     rdi, 0FFFFFFFFD28E25ABh
0x323436: 4881C7BF29562E                   add     rdi, 2E5629BFh
0x02705C: 57                               push    rdi
0x32349D: 488B9DF0000000                   mov     rbx, [rbp+0F0h]
0x027064: 48F72424                         mul     qword ptr [rsp]
0x027068: 4989C4                           mov     r12, rax
0x02715A: 498B6928                         mov     rbp, [r9+28h]
0x323570: 488BBD90000000                   mov     rdi, [rbp+90h]
0x3235DE: 4833BDD8000000                   xor     rdi, [rbp+0D8h]
0x027255: 498B6928                         mov     rbp, [r9+28h]
0x3236B1: 488BBDB0000000                   mov     rdi, [rbp+0B0h]
0x027260: 57                               push    rdi
0x027261: 4889E3                           mov     rbx, rsp
0x323716: 488BB5B0000000                   mov     rsi, [rbp+0B0h]
0x027344: 4D8B4128                         mov     r8, [r9+28h]
0x3237E8: 4D8B8890000000                   mov     r9, [r8+90h]
0x32384D: 498BB8A8000000                   mov     rdi, [r8+0A8h]
0x027356: 4151                             push    r9
0x027358: 68D46DED1B                       push    1BED6DD4h
0x02735D: 680F40535E                       push    5E53400Fh
0x027362: 68BB615A02                       push    25A61BBh
0x027452: 498B5128                         mov     rdx, [r9+28h]
0x323919: 488BAAF0000000                   mov     rbp, [rdx+0F0h]
0x323980: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x027464: 480FB6ED                         movzx   rbp, bpl
0x02753B: 4D8B5928                         mov     r11, [r9+28h]
0x323A53: 410FAE93A0000000                 ldmxcsr dword ptr [r11+0A0h]
0x323ABC: 48B85E14D21401000000             mov     rax, 114D2145Eh
0x323B2B: 4805625E372B                     add     rax, 2B375E62h
0x323B93: 488B80F0010000                   mov     rax, [rax+1F0h]
0x323BFE: 490383A0000000                   add     rax, [r11+0A0h]
0x027565: 408A30                           mov     sil, [rax]
0x027568: 480FB6F6                         movzx   rsi, sil
0x02756C: 48C1E608                         shl     rsi, 8
0x323C6A: 4929B3D8000000                   sub     [r11+0D8h], rsi
0x323CD4: 48BFCC29590001000000             mov     rdi, 1005929CCh
0x027581: 57                               push    rdi
0x027582: 682044DA2F                       push    2FDA4420h
0x027587: 68BC505214                       push    145250BCh
0x02758C: 68911FC061                       push    61C01F91h
0x323D44: 4881442418F440B03F               add     qword ptr [rsp+18h], 3FB040F4h
0x02759A: 4D8B4128                         mov     r8, [r9+28h]
0x323DAF: 498BB0D8000000                   mov     rsi, [r8+0D8h]
0x02769B: 498B7928                         mov     rdi, [r9+28h]
0x02769F: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x323E83: 488BB7A0000000                   mov     rsi, [rdi+0A0h]
0x323EED: 4C8BAFA8000000                   mov     r13, [rdi+0A8h]
0x02778A: 4D8B5928                         mov     r11, [r9+28h]
0x323FC4: 498B9BE0000000                   mov     rbx, [r11+0E0h]
0x027795: 458B7334                         mov     r14d, [r11+34h]
0x32402A: 4D03B3A8000000                   add     r14, [r11+0A8h]
0x0277A0: 418A0E                           mov     cl, [r14]
0x0277A3: 88CB                             mov     bl, cl
0x027897: 498B5928                         mov     rbx, [r9+28h]
0x3240F9: 4C8BBB90000000                   mov     r15, [rbx+90h]
0x0278A2: 4157                             push    r15
0x0278A4: 4989E6                           mov     r14, rsp
0x32415F: 4C8BAB90000000                   mov     r13, [rbx+90h]
0x02799A: 4D8B6928                         mov     r13, [r9+28h]
0x324232: 4D8B8DE8000000                   mov     r9, [r13+0E8h]
0x32429B: 4D8BBDE0000000                   mov     r15, [r13+0E0h]
0x0279AC: 4151                             push    r9
0x0279AE: 689955503B                       push    3B505599h
0x0279B3: 6899696627                       push    27666999h
0x0279B8: 68321FA042                       push    42A01F32h
0x027ABF: 498B6928                         mov     rbp, [r9+28h]
0x324365: 488B9DB8000000                   mov     rbx, [rbp+0B8h]
0x3243D3: 4C8BBDF0000000                   mov     r15, [rbp+0F0h]
0x027AD1: 480FB6DB                         movzx   rbx, bl
0x027BB4: 4D8B4128                         mov     r8, [r9+28h]
0x3244AC: 410FAE9090000000                 ldmxcsr dword ptr [r8+90h]
0x324517: 48B847FD6EF800000000             mov     rax, 0F86EFD47h
0x324587: 480579759A47                     add     rax, 479A7579h
0x3245F0: 488B8090020000                   mov     rax, [rax+290h]
0x324659: 49038090000000                   add     rax, [r8+90h]
0x027BDE: 448A38                           mov     r15b, [rax]
0x027BE1: 4D0FB6FF                         movzx   r15, r15b
0x027BE5: 49C1E710                         shl     r15, 10h
0x3246BF: 4D29B8F0000000                   sub     [r8+0F0h], r15
0x027BF0: 4D8B4128                         mov     r8, [r9+28h]
0x32472B: 498BA8F0000000                   mov     rbp, [r8+0F0h]
0x324799: 49BE860796F200000000             mov     r14, 0F2960786h
0x324808: 4981C63A63734D                   add     r14, 4D73633Ah
0x027D01: 498B4928                         mov     rcx, [r9+28h]
0x027D05: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x3248D3: 4C8BA9C8000000                   mov     r13, [rcx+0C8h]
0x324941: 4C8BB9A0000000                   mov     r15, [rcx+0A0h]
0x027DF4: 4D8B7128                         mov     r14, [r9+28h]
0x324A1B: 4D8BAEF0000000                   mov     r13, [r14+0F0h]
0x027DFF: 458B5634                         mov     r10d, [r14+34h]
0x324A83: 4D0396E0000000                   add     r10, [r14+0E0h]
0x027E0A: 418A1A                           mov     bl, [r10]
0x324AEA: 48C7C0FF000000                   mov     rax, 0FFh
0x027E14: 48C1E008                         shl     rax, 8
0x027E18: 48F7D0                           not     rax
0x027E1B: 4921C5                           and     r13, rax
0x027E1E: 480FB6C3                         movzx   rax, bl
0x027E22: 48C1E008                         shl     rax, 8
0x027E26: 4909C5                           or      r13, rax
0x027F0B: 4D8B7128                         db  4Dh ; M
0x324BB3: 4D8BA6E0000000                   mov     r12, [r14+0E0h]
0x027F16: 4154                             push    r12
0x027F18: 4989E4                           mov     r12, rsp
0x324C1C: 498BB6E0000000                   mov     rsi, [r14+0E0h]
0x028010: 498B6928                         mov     rbp, [r9+28h]
0x324CEC: 488BB5E0000000                   mov     rsi, [rbp+0E0h]
0x324D55: 4C8BA5A8000000                   mov     r12, [rbp+0A8h]
0x028022: 480FB6F6                         movzx   rsi, sil
0x028106: 498B4128                         mov     rax, [r9+28h]
0x324E22: 0FAE90A8000000                   ldmxcsr dword ptr [rax+0A8h]
0x324E8B: 48B9E1FDC8EB00000000             mov     rcx, 0EBC8FDE1h
0x324EF5: 4881C1DF744054                   add     rcx, 544074DFh
0x324F61: 488B8968030000                   mov     rcx, [rcx+368h]
0x324FC9: 480388A8000000                   add     rcx, [rax+0A8h]
0x028130: 408A29                           mov     bpl, [rcx]
0x028133: 480FB6ED                         movzx   rbp, bpl
0x028137: 48C1E518                         shl     rbp, 18h
0x32502F: 4829A8D8000000                   sub     [rax+0D8h], rbp
0x32509C: 48BE6B6300DC00000000             mov     rsi, 0DC00636Bh
0x02814C: 56                               push    rsi
0x02814D: 680656304D                       push    4D305606h
0x028152: 680010925F                       push    5F921000h
0x028157: 680936907B                       push    7B903609h
0x32510A: 488144241855070964               add     [rsp-8+arg_18], 64090755h
0x028165: 4D8B5928                         mov     r11, [r9+28h]
0x325177: 498B9BD8000000                   mov     rbx, [r11+0D8h]
0x02825A: 4D8B6128                         mov     r12, [r9+28h]
0x32524C: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x3252B1: 498BB42480000000                 mov     rsi, [r12+80h]
0x32531E: 4D8BB42490000000                 mov     r14, [r12+90h]
0x028352: 4D8B4128                         mov     r8, [r9+28h]
0x3253F3: 4D8BA0E8000000                   mov     r12, [r8+0E8h]
0x02835D: 458B7834                         mov     r15d, [r8+34h]
0x325461: 4D03B8A8000000                   add     r15, [r8+0A8h]
0x028368: 458A07                           mov     r8b, [r15]
0x3254C7: 48C7C6FF000000                   mov     rsi, 0FFh
0x028372: 48C1E610                         shl     rsi, 10h
0x028376: 48F7D6                           not     rsi
0x028379: 4921F4                           and     r12, rsi
0x02837C: 490FB6F0                         movzx   rsi, r8b
0x028380: 48C1E610                         shl     rsi, 10h
0x028384: 4909F4                           or      r12, rsi
0x028479: 498B4128                         mov     rax, [r9+28h]
0x325599: 488B98D8000000                   mov     rbx, [rax+0D8h]
0x028484: 53                               push    rbx
0x028485: 4989E4                           mov     r12, rsp
0x325601: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x028566: 4D8B7928                         mov     r15, [r9+28h]
0x3256D0: 4D8B9FD8000000                   mov     r11, [r15+0D8h]
0x325737: 4D8BB7F0000000                   mov     r14, [r15+0F0h]
0x028578: 4153                             push    r11
0x02857A: 685F6F4F5C                       push    5C4F6F5Fh
0x02857F: 68B63F8D2D                       push    2D8D3FB6h
0x028584: 68CE17EB09                       push    9EB17CEh
0x028589: 683978E941                       push    41E97839h
0x028680: 498B6928                         mov     rbp, [r9+28h]
0x325805: 488B9DA8000000                   mov     rbx, [rbp+0A8h]
0x32586F: 488BB5E8000000                   mov     rsi, [rbp+0E8h]
0x028692: 480FB6DB                         movzx   rbx, bl
0x02877B: 4D8B5128                         mov     r10, [r9+28h]
0x325942: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x3259AF: 49BF9F1921F900000000             mov     r15, 0F921199Fh
0x325A1F: 4981C72159E846                   add     r15, 46E85921h
0x325A86: 4D8BBF30070000                   mov     r15, [r15+730h]
0x325AEE: 4D03BA90000000                   add     r15, [r10+90h]
0x0287A6: 458A07                           mov     r8b, [r15]
0x0287A9: 4D0FB6C0                         movzx   r8, r8b
0x0287AD: 49C1E020                         shl     r8, 20h
0x325B57: 4D2982A8000000                   sub     [r10+0A8h], r8
0x325BC2: 48BB7609843F01000000             mov     rbx, 13F840976h
0x0287C2: 53                               push    rbx
0x0287C3: 6853579F03                       push    39F5753h
0x0287C8: 6806429B7C                       push    7C9B4206h
0x0287CD: 686B6C837B                       push    7B836C6Bh
0x0287D2: 687F5CCB23                       push    23CB5C7Fh
0x325C32: 48814424204A618500               add     qword ptr [rsp+20h], 85614Ah
0x0287E0: 4D8B6128                         mov     r12, [r9+28h]
0x325C9D: 4D8BAC24A8000000                 mov     r13, [r12+0A8h]
0x0288E4: 498B7128                         mov     rsi, [r9+28h]
0x0288E8: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x325D6E: 4C8BBE88000000                   mov     r15, [rsi+88h]
0x325DDA: 488BAEE0000000                   mov     rbp, [rsi+0E0h]
0x0289CD: 4D8B6928                         mov     r13, [r9+28h]
0x325EA7: 498BB5A0000000                   mov     rsi, [r13+0A0h]
0x0289D8: 458B5534                         mov     r10d, [r13+34h]
0x325F15: 4D0395F0000000                   add     r10, [r13+0F0h]
0x0289E3: 458A3A                           mov     r15b, [r10]
0x325F83: 48C7C7FF000000                   mov     rdi, 0FFh
0x0289ED: 48C1E718                         shl     rdi, 18h
0x0289F1: 48F7D7                           not     rdi
0x0289F4: 4821FE                           and     rsi, rdi
0x0289F7: 490FB6FF                         movzx   rdi, r15b
0x0289FB: 48C1E718                         shl     rdi, 18h
0x0289FF: 4809FE                           or      rsi, rdi
0x028AE8: 4D8B4128                         mov     r8, [r9+28h]
0x326056: 498B80A8000000                   mov     rax, [r8+0A8h]
0x028AF3: 50                               push    rax
0x028AF4: 4889E3                           mov     rbx, rsp
0x3260BF: 4D8BA8A8000000                   mov     r13, [r8+0A8h]
0x028BDE: 498B6928                         mov     rbp, [r9+28h]
0x32618D: 488BB5A0000000                   mov     rsi, [rbp+0A0h]
0x3261F2: 4C8BA5E0000000                   mov     r12, [rbp+0E0h]
0x028BF0: 480FB6F6                         movzx   rsi, sil
0x028CE1: 4D8B7128                         mov     r14, [r9+28h]
0x3262C1: 410FAE96A8000000                 ldmxcsr dword ptr [r14+0A8h]
0x32632B: 49BCBC224A0001000000             mov     r12, 1004A22BCh
0x326394: 4981C40450BF3F                   add     r12, 3FBF5004h
0x028CFE: 4D8B2424                         mov     r12, [r12]
0x3263FA: 4D03A6A8000000                   add     r12, [r14+0A8h]
0x028D09: 418A0C24                         mov     cl, [r12]
0x028D0D: 480FB6C9                         movzx   rcx, cl
0x028D11: 48C1E130                         shl     rcx, 30h
0x326464: 49298ED8000000                   sub     [r14+0D8h], rcx
0x3264D1: 49BE0316201401000000             mov     r14, 114201603h
0x028D26: 4156                             push    r14
0x028D28: 681C70C923                       push    23C9701Ch
0x028D2D: 68A02F7260                       push    60722FA0h
0x028D32: 682636FF0C                       push    0CFF3626h
0x028D37: 68DE07F323                       push    23F307DEh
0x32653A: 4881442420BD54E92B               add     qword ptr [rsp+20h], 2BE954BDh
0x028D45: 498B5928                         mov     rbx, [r9+28h]
0x3265A2: 488BABD8000000                   mov     rbp, [rbx+0D8h]
0x028E25: 498B5128                         mov     rdx, [r9+28h]
0x028E29: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x326674: 4C8BB2E8000000                   mov     r14, [rdx+0E8h]
0x3266D9: 4C8BBAA0000000                   mov     r15, [rdx+0A0h]
0x028F23: 498B5128                         mov     rdx, [r9+28h]
0x3267A7: 488BBAF0000000                   mov     rdi, [rdx+0F0h]
0x028F2E: 448B6234                         mov     r12d, [rdx+34h]
0x32680E: 4C03A2E8000000                   add     r12, [rdx+0E8h]
0x028F39: 418A2C24                         mov     bpl, [r12]
0x32687A: 48C7C2FF000000                   mov     rdx, 0FFh
0x028F44: 48C1E228                         shl     rdx, 28h
0x028F48: 48F7D2                           not     rdx
0x028F4B: 4821D7                           and     rdi, rdx
0x028F4E: 480FB6D5                         movzx   rdx, bpl
0x028F52: 48C1E228                         shl     rdx, 28h
0x028F56: 4809D7                           or      rdi, rdx
0x029031: 498B6928                         mov     rbp, [r9+28h]
0x326945: 4C8BBDB0000000                   mov     r15, [rbp+0B0h]
0x02903C: 4157                             push    r15
0x02903E: 4889E6                           mov     rsi, rsp
0x3269B1: 4C8BBDB0000000                   mov     r15, [rbp+0B0h]
0x029120: 4D8B7128                         mov     r14, [r9+28h]
0x326A87: 4D8B86A8000000                   mov     r8, [r14+0A8h]
0x326AEF: 4D8BB6F0000000                   mov     r14, [r14+0F0h]
0x029132: 4150                             push    r8
0x029134: 68C433135F                       push    5F1333C4h
0x029139: 68DC58D009                       push    9D058DCh
0x02913E: 68B727AC58                       push    58AC27B7h
0x029221: 4D8B6928                         mov     r13, [r9+28h]
0x326BBC: 498BBDB0000000                   mov     rdi, [r13+0B0h]
0x326C2A: 498BADE8000000                   mov     rbp, [r13+0E8h]
0x029233: 480FB6FF                         movzx   rdi, dil
0x029306: 4D8B5928                         mov     r11, [r9+28h]
0x326CFB: 410FAE93B0000000                 ldmxcsr dword ptr [r11+0B0h]
0x326D68: 48BB550AA70F01000000             mov     rbx, 10FA70A55h
0x326DD0: 4881C36B686230                   add     rbx, 3062686Bh
0x029323: 488B1B                           mov     rbx, [rbx]
0x326E37: 49039BB0000000                   add     rbx, [r11+0B0h]
0x02932D: 8A03                             mov     al, [rbx]
0x02932F: 480FB6C0                         movzx   rax, al
0x029333: 48C1E038                         shl     rax, 38h
0x326E9D: 492983A0000000                   sub     [r11+0A0h], rax
0x02933E: 498B6928                         mov     rbp, [r9+28h]
0x326F06: 4C8BA5A0000000                   mov     r12, [rbp+0A0h]
0x326F6E: 49BDEC3172EF00000000             mov     r13, 0EF7231ECh
0x326FD8: 4981C5D4389750                   add     r13, 509738D4h
0x029443: 498B6928                         mov     rbp, [r9+28h]
0x029447: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x3270A3: 4C8BBDA0000000                   mov     r15, [rbp+0A0h]
0x327110: 488B9DD8000000                   mov     rbx, [rbp+0D8h]
0x02951E: 498B5928                         mov     rbx, [r9+28h]
0x3271E2: 4C8BBB90000000                   mov     r15, [rbx+90h]
0x029529: 8B6B34                           mov     ebp, [rbx+34h]
0x327249: 4803ABF0000000                   add     rbp, [rbx+0F0h]
0x029533: 8A5500                           mov     dl, [rbp+0]
0x3272B4: 48C7C6FF000000                   mov     rsi, 0FFh
0x02953D: 48C1E630                         shl     rsi, 30h
0x029541: 48F7D6                           not     rsi
0x029544: 4921F7                           and     r15, rsi
0x029547: 480FB6F2                         movzx   rsi, dl
0x02954B: 48C1E630                         shl     rsi, 30h
0x02954F: 4909F7                           or      r15, rsi
0x327387: 48BDB4B6DCCE00000000             mov     rbp, 0CEDCB6B4h
0x029638: 55                               push    rbp
0x029639: 68613A1720                       push    20173A61h
0x02963E: 68F05F227C                       push    7C225FF0h
0x029643: 684948D225                       push    25D24849h
0x029648: 6870592434                       push    34245970h
0x3273F6: 48814424203402AD71               add     qword ptr [rsp+20h], 71AD0234h
0x029656: 4D8B7128                         mov     r14, [r9+28h]
0x327465: 4D8BA6F0000000                   mov     r12, [r14+0F0h]
0x02974D: 4D8B7928                         mov     r15, [r9+28h]
0x327534: 498BAFA0000000                   mov     rbp, [r15+0A0h]
0x327599: 4D8BAFD8000000                   mov     r13, [r15+0D8h]
0x02975F: 480FB6ED                         movzx   rbp, bpl
0x029859: 498B6928                         mov     rbp, [r9+28h]
0x32766E: 488B85A0000000                   mov     rax, [rbp+0A0h]
0x3276D7: 49C7C0A663FCEA                   mov     r8, 0FFFFFFFFEAFC63A6h
0x32773F: 4981C0300EB315                   add     r8, 15B30E30h
0x029872: 4150                             push    r8
0x3277AC: 4C8BA5E0000000                   mov     r12, [rbp+0E0h]
0x02987B: 48F72424                         mul     qword ptr [rsp]
0x02987F: 4889C7                           mov     rdi, rax
0x029969: 498B5928                         mov     rbx, [r9+28h]
0x32787E: 488BABD8000000                   mov     rbp, [rbx+0D8h]
0x3278E9: 4803ABB0000000                   add     rbp, [rbx+0B0h]
0x029A54: 498B4928                         mov     rcx, [r9+28h]
0x3279B6: 488BB9A0000000                   mov     rdi, [rcx+0A0h]
0x029A5F: 57                               push    rdi
0x029A60: 4889E7                           mov     rdi, rsp
0x327A1F: 4C8BB9A0000000                   mov     r15, [rcx+0A0h]
0x029B44: 4D8B6928                         mov     r13, [r9+28h]
0x327AF3: 4D8BB590000000                   mov     r14, [r13+90h]
0x327B58: 498BADF0000000                   mov     rbp, [r13+0F0h]
0x029B56: 4D0FB6F6                         movzx   r14, r14b
0x029C41: 498B7928                         mov     rdi, [r9+28h]
0x327C2C: 0FAE97E8000000                   ldmxcsr dword ptr [rdi+0E8h]
0x327C98: 49BF841AB3D800000000             mov     r15, 0D8B31A84h
0x327D04: 4981C73C485667                   add     r15, 6756483Ch
0x327D6C: 4D8BBF98060000                   mov     r15, [r15+698h]
0x327DD2: 4C03BFE8000000                   add     r15, [rdi+0E8h]
0x029C6B: 458A07                           mov     r8b, [r15]
0x029C6E: 4D0FB6C0                         movzx   r8, r8b
0x029C72: 49C1E008                         shl     r8, 8
0x327E3D: 4C0187A0000000                   add     [rdi+0A0h], r8
0x327EAA: 49BC0915F3C500000000             mov     r12, 0C5F31509h
0x029C87: 4154                             push    r12
0x029C89: 68C643BA09                       push    9BA43C6h
0x029C8E: 688708182D                       push    2D180887h
0x029C93: 68AC63897D                       push    7D8963ACh
0x029C98: 68256FBD5C                       push    5CBD6F25h
0x327F14: 4881442420B745167A               add     qword ptr [rsp+20h], 7A1645B7h
0x029CA6: 4D8B7128                         mov     r14, [r9+28h]
0x327F84: 4D8BA6A0000000                   mov     r12, [r14+0A0h]
0x029D8F: 498B7928                         mov     rdi, [r9+28h]
0x029D93: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x328053: 488BAFE0000000                   mov     rbp, [rdi+0E0h]
0x3280BE: 4C8BAFD8000000                   mov     r13, [rdi+0D8h]
0x029E72: 4D8B4928                         mov     r9, [r9+28h]
0x32818B: 4D8BB9E0000000                   mov     r15, [r9+0E0h]
0x029E7D: 458B5134                         mov     r10d, [r9+34h]
0x3281F3: 4D0391A0000000                   add     r10, [r9+0A0h]
0x029E88: 458A32                           mov     r14b, [r10]
0x029E8B: 4588F7                           mov     r15b, r14b
0x029F5D: 4D8B6928                         mov     r13, [r9+28h]
0x3282C9: 498BBDF0000000                   mov     rdi, [r13+0F0h]
0x029F68: 57                               push    rdi
0x029F69: 4989E4                           mov     r12, rsp
0x328333: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x02A05D: 4D8B4928                         mov     r9, [r9+28h]
0x3283FE: 498B99D8000000                   mov     rbx, [r9+0D8h]
0x32846C: 4D8BA1E8000000                   mov     r12, [r9+0E8h]
0x02A06F: 53                               push    rbx
0x02A070: 68C8796476                       push    766479C8h
0x02A075: 688527F52D                       push    2DF52785h
0x02A07A: 681A618278                       push    7882611Ah
0x02A07F: 68FE05E373                       push    73E305FEh
0x02A173: 498B4128                         mov     rax, [r9+28h]
0x328544: 4C8BA8C8000000                   mov     r13, [rax+0C8h]
0x3285AC: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x02A185: 4D0FB6ED                         movzx   r13, r13b
0x02A27C: 498B6928                         mov     rbp, [r9+28h]
0x32867C: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x3286E5: 49BBA6024A0601000000             mov     r11, 1064A02A6h
0x32874E: 4981C31A60BF39                   add     r11, 39BF601Ah
0x3287B6: 4D8B9B10010000                   mov     r11, [r11+110h]
0x32881C: 4C039DE0000000                   add     r11, [rbp+0E0h]
0x02A2A6: 418A33                           mov     sil, [r11]
0x02A2A9: 480FB6F6                         movzx   rsi, sil
0x02A2AD: 48C1E610                         shl     rsi, 10h
0x328881: 4801B5F0000000                   add     [rbp+0F0h], rsi
0x02A2B8: 498B6928                         mov     rbp, [r9+28h]
0x3288E6: 488B9DF0000000                   mov     rbx, [rbp+0F0h]
0x32894E: 49BE59202C0E01000000             mov     r14, 10E2C2059h
0x3289BE: 4981C6673ADD31                   add     r14, 31DD3A67h
0x02A3B5: 498B4928                         mov     rcx, [r9+28h]
0x02A3B9: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x328A89: 488B99E8000000                   mov     rbx, [rcx+0E8h]
0x328AF7: 488BB190000000                   mov     rsi, [rcx+90h]
0x02A4BB: 498B7128                         mov     rsi, [r9+28h]
0x328BC2: 488B9EA8000000                   mov     rbx, [rsi+0A8h]
0x02A4C6: 8B4E34                           mov     ecx, [rsi+34h]
0x328C2A: 48038E90000000                   add     rcx, [rsi+90h]
0x02A4D0: 8A01                             mov     al, [rcx]
0x328C94: 48C7C6FF000000                   mov     rsi, 0FFh
0x02A4D9: 48C1E608                         shl     rsi, 8
0x02A4DD: 48F7D6                           not     rsi
0x02A4E0: 4821F3                           and     rbx, rsi
0x02A4E3: 480FB6F0                         movzx   rsi, al
0x02A4E7: 48C1E608                         shl     rsi, 8
0x02A4EB: 4809F3                           or      rbx, rsi
0x02A5E1: 498B4928                         mov     rcx, [r9+28h]
0x328D63: 4C8BB190000000                   mov     r14, [rcx+90h]
0x02A5EC: 4156                             push    r14
0x02A5EE: 4889E7                           mov     rdi, rsp
0x328DCE: 4C8BA190000000                   mov     r12, [rcx+90h]
0x02A6D0: 498B4128                         mov     rax, [r9+28h]
0x328EA0: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x328F06: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x02A6E2: 4155                             push    r13
0x02A6E4: 68EE24AF19                       push    19AF24EEh
0x02A6E9: 68205C9C4E                       push    4E9C5C20h
0x02A6EE: 68F135083F                       push    3F0835F1h
0x02A6F3: 68737AB171                       push    71B17A73h
0x02A7F1: 4D8B7928                         mov     r15, [r9+28h]
0x328FD8: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x329045: 498BB7F0000000                   mov     rsi, [r15+0F0h]
0x02A803: 480FB6FF                         movzx   rdi, dil
0x02A8E9: 4D8B5128                         mov     r10, [r9+28h]
0x329115: 410FAE92B0000000                 ldmxcsr dword ptr [r10+0B0h]
0x32917D: 48B8583B710B01000000             mov     rax, 10B713B58h
0x3291EC: 480568279834                     add     rax, 34982768h
0x329258: 488B8088000000                   mov     rax, [rax+88h]
0x3292C6: 490382B0000000                   add     rax, [r10+0B0h]
0x02A913: 408A30                           mov     sil, [rax]
0x02A916: 480FB6F6                         movzx   rsi, sil
0x02A91A: 48C1E618                         shl     rsi, 18h
0x32932E: 4901B2A8000000                   add     [r10+0A8h], rsi
0x02A925: 4D8B6928                         mov     r13, [r9+28h]
0x32939B: 4D8BBDA8000000                   mov     r15, [r13+0A8h]
0x329404: 49BE59EC910301000000             mov     r14, 10391EC59h
0x329471: 4981C6676E773C                   add     r14, 3C776E67h
0x02AA2A: 498B6928                         mov     rbp, [r9+28h]
0x02AA2E: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x329544: 4C8BB590000000                   mov     r14, [rbp+90h]
0x3295AD: 4C8BA5F0000000                   mov     r12, [rbp+0F0h]
0x02AB27: 498B7128                         mov     rsi, [r9+28h]
0x32967B: 4C8BBED8000000                   mov     r15, [rsi+0D8h]
0x02AB32: 448B7634                         mov     r14d, [rsi+34h]
0x3296E0: 4C03B6E8000000                   add     r14, [rsi+0E8h]
0x02AB3D: 458A2E                           mov     r13b, [r14]
0x32974D: 48C7C5FF000000                   mov     rbp, 0FFh
0x02AB47: 48C1E510                         shl     rbp, 10h
0x02AB4B: 48F7D5                           not     rbp
0x02AB4E: 4921EF                           and     r15, rbp
0x02AB51: 490FB6ED                         movzx   rbp, r13b
0x02AB55: 48C1E510                         shl     rbp, 10h
0x02AB59: 4909EF                           or      r15, rbp
0x02AC32: 498B6928                         mov     rbp, [r9+28h]
0x329820: 4C8BB5F0000000                   mov     r14, [rbp+0F0h]
0x02AC3D: 4156                             push    r14
0x02AC3F: 4889E6                           mov     rsi, rsp
0x32988A: 4C8BADF0000000                   mov     r13, [rbp+0F0h]
0x02AD24: 498B7128                         mov     rsi, [r9+28h]
0x329953: 488B8EA8000000                   mov     rcx, [rsi+0A8h]
0x3299B8: 488BBEE0000000                   mov     rdi, [rsi+0E0h]
0x02AD36: 51                               push    rcx
0x02AD37: 68CE192201                       push    12219CEh
0x02AD3C: 682C556A50                       push    506A552Ch
0x02AD41: 684B78C774                       push    74C7784Bh
0x02AE4B: 498B4928                         mov     rcx, [r9+28h]
0x329A8F: 488BA9E0000000                   mov     rbp, [rcx+0E0h]
0x329AF5: 488BB9B0000000                   mov     rdi, [rcx+0B0h]
0x02AE5D: 480FB6ED                         movzx   rbp, bpl
0x02AF51: 498B5928                         mov     rbx, [r9+28h]
0x329BC9: 0FAE93A0000000                   ldmxcsr dword ptr [rbx+0A0h]
0x329C37: 48BF5BEDA72101000000             mov     rdi, 121A7ED5Bh
0x329CA3: 4881C76575611E                   add     rdi, 1E617565h
0x329D0E: 488BBF90040000                   mov     rdi, [rdi+490h]
0x329D77: 4803BBA0000000                   add     rdi, [rbx+0A0h]
0x02AF7B: 8A0F                             mov     cl, [rdi]
0x02AF7D: 480FB6C9                         movzx   rcx, cl
0x02AF81: 48C1E120                         shl     rcx, 20h
0x329DDF: 48018BB0000000                   add     [rbx+0B0h], rcx
0x02AF8C: 498B4928                         mov     rcx, [r9+28h]
0x329E49: 488B99B0000000                   mov     rbx, [rcx+0B0h]
0x329EB1: 48BE70F2DDF300000000             mov     rsi, 0F3DDF270h
0x329F20: 4881C650682B4C                   add     rsi, 4C2B6850h
0x02B08A: 498B4928                         mov     rcx, [r9+28h]
0x02B08E: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x329FF8: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x32A060: 4C8BA190000000                   mov     r12, [rcx+90h]
0x02B193: 498B7128                         mov     rsi, [r9+28h]
0x32A138: 488B9ED8000000                   mov     rbx, [rsi+0D8h]
0x02B19E: 8B4E34                           mov     ecx, [rsi+34h]
0x32A1A0: 48038EA8000000                   add     rcx, [rsi+0A8h]
0x02B1A8: 408A39                           mov     dil, [rcx]
0x32A209: 48C7C6FF000000                   mov     rsi, 0FFh
0x02B1B2: 48C1E618                         shl     rsi, 18h
0x02B1B6: 48F7D6                           not     rsi
0x02B1B9: 4821F3                           and     rbx, rsi
0x02B1BC: 480FB6F7                         movzx   rsi, dil
0x02B1C0: 48C1E618                         shl     rsi, 18h
0x02B1C4: 4809F3                           or      rbx, rsi
0x02B2A2: 4D8B7128                         mov     r14, [r9+28h]
0x32A2D6: 4D8BBE90000000                   mov     r15, [r14+90h]
0x02B2AD: 4157                             push    r15
0x02B2AF: 4889E3                           mov     rbx, rsp
0x32A343: 4D8BB690000000                   mov     r14, [r14+90h]
0x02B393: 4D8B5928                         mov     r11, [r9+28h]
0x32A413: 4D8BA390000000                   mov     r12, [r11+90h]
0x32A478: 498BABE8000000                   mov     rbp, [r11+0E8h]
0x02B3A5: 4154                             push    r12
0x02B3A7: 682752640E                       push    0E645227h
0x02B3AC: 684E79DE73                       push    73DE794Eh
0x02B3B1: 68B5434A01                       push    14A43B5h
0x02B499: 4D8B5928                         mov     r11, [r9+28h]
0x32A546: 498B9BB0000000                   mov     rbx, [r11+0B0h]
0x32A5AD: 4D8BB3A0000000                   mov     r14, [r11+0A0h]
0x02B4AB: 480FB6DB                         movzx   rbx, bl
0x02B584: 498B7928                         mov     rdi, [r9+28h]
0x32A67C: 0FAE9790000000                   ldmxcsr dword ptr [rdi+90h]
0x32A6E4: 48BA20F675E200000000             mov     rdx, 0E275F620h
0x32A74E: 4881C2A06C935D                   add     rdx, 5D936CA0h
0x02B5A0: 488B12                           mov     rdx, [rdx]
0x32A7B7: 48039790000000                   add     rdx, [rdi+90h]
0x02B5AA: 448A1A                           mov     r11b, [rdx]
0x02B5AD: 4D0FB6DB                         movzx   r11, r11b
0x02B5B1: 49C1E328                         shl     r11, 28h
0x32A81D: 4C019FE8000000                   add     [rdi+0E8h], r11
0x02B5BC: 498B5928                         mov     rbx, [r9+28h]
0x32A886: 488BB3E8000000                   mov     rsi, [rbx+0E8h]
0x32A8EB: 48BD92DE32CA00000000             mov     rbp, 0CA32DE92h
0x32A955: 4881C52E7CD675                   add     rbp, 75D67C2Eh
0x02B6BA: 4D8B6128                         mov     r12, [r9+28h]
0x32AA29: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x02B6C4: 498B5C2478                       mov     rbx, [r12+78h]
0x32AA95: 4D8BB424A8000000                 mov     r14, [r12+0A8h]
0x02B7B0: 498B5928                         mov     rbx, [r9+28h]
0x32AB67: 488BABE8000000                   mov     rbp, [rbx+0E8h]
0x02B7BB: 448B4334                         mov     r8d, [rbx+34h]
0x32ABD0: 4C038390000000                   add     r8, [rbx+90h]
0x02B7C6: 458A20                           mov     r12b, [r8]
0x32AC3A: 48C7C0FF000000                   mov     rax, 0FFh
0x02B7D0: 48C1E020                         shl     rax, 20h
0x02B7D4: 48F7D0                           not     rax
0x02B7D7: 4821C5                           and     rbp, rax
0x02B7DA: 490FB6C4                         movzx   rax, r12b
0x02B7DE: 48C1E020                         shl     rax, 20h
0x02B7E2: 4809C5                           or      rbp, rax
0x02B8C9: 4D8B7928                         mov     r15, [r9+28h]
0x32AD08: 498B8FA0000000                   mov     rcx, [r15+0A0h]
0x02B8D4: 51                               push    rcx
0x02B8D5: 4989E4                           mov     r12, rsp
0x32AD73: 498BB7A0000000                   mov     rsi, [r15+0A0h]
0x02B9D9: 4D8B4928                         mov     r9, [r9+28h]
0x32AE40: 498B99F0000000                   mov     rbx, [r9+0F0h]
0x32AEA9: 4D8BB1A8000000                   mov     r14, [r9+0A8h]
0x02B9EB: 480FB6DB                         movzx   rbx, bl
0x02BAC9: 498B4128                         mov     rax, [r9+28h]
0x32AF77: 0FAE9090000000                   ldmxcsr dword ptr [rax+90h]
0x32AFE2: 48BAED16A2C400000000             mov     rdx, 0C4A216EDh
0x32B04A: 4881C2D34B677B                   add     rdx, 7B674BD3h
0x02BAE5: 488B12                           mov     rdx, [rdx]
0x32B0B3: 48039090000000                   add     rdx, [rax+90h]
0x02BAEF: 448A1A                           mov     r11b, [rdx]
0x02BAF2: 4D0FB6DB                         movzx   r11, r11b
0x02BAF6: 49C1E330                         shl     r11, 30h
0x32B11C: 4C0198E8000000                   add     [rax+0E8h], r11
0x02BB01: 4D8B7128                         mov     r14, [r9+28h]
0x32B182: 498BAEE8000000                   mov     rbp, [r14+0E8h]
0x32B1EA: 49BC19EEE7F300000000             mov     r12, 0F3E7EE19h
0x32B252: 4981C4A76C214C                   add     r12, 4C216CA7h
0x02BC00: 498B6928                         mov     rbp, [r9+28h]
0x02BC04: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x32B325: 488BB5B0000000                   mov     rsi, [rbp+0B0h]
0x32B38A: 4C8BADA0000000                   mov     r13, [rbp+0A0h]
0x02BD03: 498B5928                         mov     rbx, [r9+28h]
0x32B45C: 488BABE0000000                   mov     rbp, [rbx+0E0h]
0x02BD0E: 448B5B34                         mov     r11d, [rbx+34h]
0x32B4C9: 4C039BA8000000                   add     r11, [rbx+0A8h]
0x02BD19: 418A33                           mov     sil, [r11]
0x32B536: 49C7C2FF000000                   mov     r10, 0FFh
0x02BD23: 49C1E228                         shl     r10, 28h
0x02BD27: 49F7D2                           not     r10
0x02BD2A: 4C21D5                           and     rbp, r10
0x02BD2D: 4C0FB6D6                         movzx   r10, sil
0x02BD31: 49C1E228                         shl     r10, 28h
0x02BD35: 4C09D5                           or      rbp, r10
0x02BE0F: 4D8B7128                         mov     r14, [r9+28h]
0x32B60C: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x02BE1A: 53                               push    rbx
0x02BE1B: 4989E7                           mov     r15, rsp
0x32B67A: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x02BF1F: 4D8B7928                         mov     r15, [r9+28h]
0x32B74E: 498B9FC8000000                   mov     rbx, [r15+0C8h]
0x32B7B3: 498BAFE8000000                   mov     rbp, [r15+0E8h]
0x02BF31: 480FB6DB                         movzx   rbx, bl
0x02C005: 4D8B5128                         mov     r10, [r9+28h]
0x32B884: 410FAE9290000000                 ldmxcsr dword ptr [r10+90h]
0x32B8F3: 48BA433C331801000000             mov     rdx, 118333C43h
0x02C01B: 52                               push    rdx
0x02C01C: 68DF42B821                       push    21B842DFh
0x02C021: 68BD35B066                       push    66B035BDh
0x02C026: 68C650E50F                       push    0FE550C6h
0x32B963: 48814424187D1ED627               add     qword ptr [rsp+18h], 27D61E7Dh
0x02C034: 4D8B7928                         mov     r15, [r9+28h]
0x32B9CA: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x02C116: 4D8B5128                         mov     r10, [r9+28h]
0x02C11A: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x32BA95: 4D8BB2F0000000                   mov     r14, [r10+0F0h]
0x32BAFD: 4D8BA2E8000000                   mov     r12, [r10+0E8h]
0x02C214: 4D8B4128                         mov     r8, [r9+28h]
0x32BBC5: 498BA8D8000000                   mov     rbp, [r8+0D8h]
0x02C21F: 458B6834                         mov     r13d, [r8+34h]
0x32BC2C: 4D03A8E8000000                   add     r13, [r8+0E8h]
0x02C22A: 418A5500                         mov     dl, [r13+0]
0x32BC99: 49C7C1FF000000                   mov     r9, 0FFh
0x02C235: 49C1E138                         shl     r9, 38h
0x02C239: 49F7D1                           not     r9
0x02C23C: 4C21CD                           and     rbp, r9
0x02C23F: 4C0FB6CA                         movzx   r9, dl
0x02C243: 49C1E138                         shl     r9, 38h
0x02C247: 4C09CD                           or      rbp, r9
0x02C321: 498B4128                         mov     rax, [r9+28h]
0x32BD66: 488B98A0000000                   mov     rbx, [rax+0A0h]
0x02C32C: 53                               push    rbx
0x02C32D: 4889E6                           mov     rsi, rsp
0x32BDD4: 4C8BA8A0000000                   mov     r13, [rax+0A0h]
0x02C41D: 498B6928                         mov     rbp, [r9+28h]
0x32BEA3: 488BB5A8000000                   mov     rsi, [rbp+0A8h]
0x32BF0D: 488BADE0000000                   mov     rbp, [rbp+0E0h]
0x02C42F: 56                               push    rsi
0x02C430: 68695A8B3F                       push    3F8B5A69h
0x02C435: 68A70BBD00                       push    0BD0BA7h
0x02C43A: 686F71EB5A                       push    5AEB716Fh
0x02C514: 4D8B7928                         mov     r15, [r9+28h]
0x32BFE3: 4D8BAFF0000000                   mov     r13, [r15+0F0h]
0x32C04F: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x02C526: 4D0FB6ED                         movzx   r13, r13b
0x02C5FD: 498B5928                         mov     rbx, [r9+28h]
0x32C122: 0FAE93E0000000                   ldmxcsr dword ptr [rbx+0E0h]
0x32C187: 49BC333B861C01000000             mov     r12, 11C863B33h
0x32C1EF: 4981C48D378323                   add     r12, 2383378Dh
0x32C256: 4D8BA42470050000                 mov     r12, [r12+570h]
0x32C2C4: 4C03A3E0000000                   add     r12, [rbx+0E0h]
0x02C628: 458A0424                         mov     r8b, [r12]
0x02C62C: 4D0FB6C0                         movzx   r8, r8b
0x02C630: 49C1E008                         shl     r8, 8
0x32C32D: 4C298390000000                   sub     [rbx+90h], r8
0x32C392: 48BD643CD03601000000             mov     rbp, 136D03C64h
0x02C645: 55                               push    rbp
0x02C646: 689B6B3841                       push    41386B9Bh
0x02C64B: 680809D35A                       push    5AD30908h
0x02C650: 683120873C                       push    3C872031h
0x32C3FF: 48814424185C2E3909               add     qword ptr [rsp+18h], 9392E5Ch
0x02C65E: 498B6928                         mov     rbp, [r9+28h]
0x32C467: 488B9D90000000                   mov     rbx, [rbp+90h]
0x02C756: 4D8B7128                         mov     r14, [r9+28h]
0x02C75A: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x32C53D: 4D8BBEB8000000                   mov     r15, [r14+0B8h]
0x32C5A4: 498BAE90000000                   mov     rbp, [r14+90h]
0x02C852: 498B7928                         mov     rdi, [r9+28h]
0x32C679: 4C8BB7A0000000                   mov     r14, [rdi+0A0h]
0x02C85D: 8B7734                           mov     esi, [rdi+34h]
0x32C6E7: 4803B7F0000000                   add     rsi, [rdi+0F0h]
0x02C867: 8A1E                             mov     bl, [rsi]
0x02C869: 4188DE                           mov     r14b, bl
0x02C93E: 498B5128                         mov     rdx, [r9+28h]
0x32C7BE: 4C8BB2E8000000                   mov     r14, [rdx+0E8h]
0x02C949: 4156                             push    r14
0x02C94B: 4989E7                           mov     r15, rsp
0x32C824: 488BAAE8000000                   mov     rbp, [rdx+0E8h]
0x02CA31: 498B7928                         mov     rdi, [r9+28h]
0x32C8F8: 488B9F80000000                   mov     rbx, [rdi+80h]
0x32C960: 488BB7A0000000                   mov     rsi, [rdi+0A0h]
0x02CA43: 480FB6DB                         movzx   rbx, bl
0x02CB3D: 498B7928                         mov     rdi, [r9+28h]
0x32CA34: 0FAE9790000000                   ldmxcsr dword ptr [rdi+90h]
0x32CA9B: 48B8E758100D01000000             mov     rax, 10D1058E7h
0x32CB0C: 4805D919F932                     add     rax, 32F919D9h
0x32CB74: 488B8058040000                   mov     rax, [rax+458h]
0x32CBDF: 48038790000000                   add     rax, [rdi+90h]
0x02CB66: 448A10                           mov     r10b, [rax]
0x02CB69: 4D0FB6D2                         movzx   r10, r10b
0x02CB6D: 49C1E210                         shl     r10, 10h
0x32CC44: 4C2997A8000000                   sub     [rdi+0A8h], r10
0x32CCAB: 48BEAE07E23301000000             mov     rsi, 133E207AEh
0x02CB82: 56                               push    rsi
0x02CB83: 68BE4CA478                       push    78A44CBEh
0x02CB88: 685D08A349                       push    49A3085Dh
0x02CB8D: 6874744A28                       push    284A7474h
0x02CB92: 681934FA12                       push    12FA3419h
0x32CD15: 48814424201263270C               add     qword ptr [rsp+20h], 0C276312h
0x02CBA0: 4D8B4128                         mov     r8, [r9+28h]
0x32CD80: 498BB0A8000000                   mov     rsi, [r8+0A8h]
0x02CC9F: 498B5128                         mov     rdx, [r9+28h]
0x02CCA3: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x32CE54: 4C8BBAB0000000                   mov     r15, [rdx+0B0h]
0x32CEC2: 488BBAA8000000                   mov     rdi, [rdx+0A8h]
0x02CD9F: 4D8B6928                         mov     r13, [r9+28h]
0x32CF95: 498BADB0000000                   mov     rbp, [r13+0B0h]
0x02CDAA: 418B5534                         mov     edx, [r13+34h]
0x32CFFF: 490395F0000000                   add     rdx, [r13+0F0h]
0x02CDB5: 448A3A                           mov     r15b, [rdx]
0x32D06C: 48C7C7FF000000                   mov     rdi, 0FFh
0x02CDBF: 48C1E708                         shl     rdi, 8
0x02CDC3: 48F7D7                           not     rdi
0x02CDC6: 4821FD                           and     rbp, rdi
0x02CDC9: 490FB6FF                         movzx   rdi, r15b
0x02CDCD: 48C1E708                         shl     rdi, 8
0x02CDD1: 4809FD                           or      rbp, rdi
0x02CEBD: 4D8B7128                         mov     r14, [r9+28h]
0x32D13E: 4D8BAEA0000000                   mov     r13, [r14+0A0h]
0x02CEC8: 4155                             push    r13
0x02CECA: 4889E3                           mov     rbx, rsp
0x32D1A4: 498BB6A0000000                   mov     rsi, [r14+0A0h]
0x02CFB7: 498B5928                         mov     rbx, [r9+28h]
0x32D279: 4C8B8390000000                   mov     r8, [rbx+90h]
0x32D2E6: 488BBBA8000000                   mov     rdi, [rbx+0A8h]
0x02CFC9: 4150                             push    r8
0x02CFCB: 683D3BC56D                       push    6DC53B3Dh
0x02CFD0: 687769F31D                       push    1DF36977h
0x02CFD5: 687725F70C                       push    0CF72577h
0x02CFDA: 683453D816                       push    16D85334h
0x02D0D9: 498B5128                         mov     rdx, [r9+28h]
0x32D3B7: 4C8BB2D0000000                   mov     r14, [rdx+0D0h]
0x32D423: 4C8BA2B0000000                   mov     r12, [rdx+0B0h]
0x02D0EB: 4D0FB6F6                         movzx   r14, r14b
0x02D1CC: 498B7128                         mov     rsi, [r9+28h]
0x32D4F3: 0FAE96E8000000                   ldmxcsr dword ptr [rsi+0E8h]
0x32D55D: 49BA19560CDF00000000             mov     r10, 0DF0C5619h
0x32D5C7: 4981C2A71CFD60                   add     r10, 60FD1CA7h
0x32D631: 4D8B92A0000000                   mov     r10, [r10+0A0h]
0x32D696: 4C0396E8000000                   add     r10, [rsi+0E8h]
0x02D1F6: 418A3A                           mov     dil, [r10]
0x02D1F9: 480FB6FF                         movzx   rdi, dil
0x02D1FD: 48C1E718                         shl     rdi, 18h
0x32D6FB: 4829BED8000000                   sub     [rsi+0D8h], rdi
0x32D768: 49BF2CEE402101000000             mov     r15, 12140EE2Ch
0x02D212: 4157                             push    r15
0x02D214: 68B07A5B73                       push    735B7AB0h
0x02D219: 686228AB1F                       push    1FAB2862h
0x02D21E: 68665C604D                       push    4D605C66h
0x32D7D5: 4881442418947CC81E               add     [rsp-8+arg_18], 1EC87C94h
0x02D22C: 498B6928                         mov     rbp, [r9+28h]
0x32D844: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x02D32C: 4D8B4928                         mov     r9, [r9+28h]
0x02D330: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x32D91A: 498BB190000000                   mov     rsi, [r9+90h]
0x32D988: 4D8BA9A8000000                   mov     r13, [r9+0A8h]
0x02D42F: 4D8B5928                         mov     r11, [r9+28h]
0x32DA5C: 4D8BB3E0000000                   mov     r14, [r11+0E0h]
0x02D43A: 458B7B34                         mov     r15d, [r11+34h]
0x32DAC7: 4D03BBA8000000                   add     r15, [r11+0A8h]
0x02D445: 418A07                           mov     al, [r15]
0x32DB2C: 48C7C2FF000000                   mov     rdx, 0FFh
0x02D44F: 48C1E210                         shl     rdx, 10h
0x02D453: 48F7D2                           not     rdx
0x02D456: 4921D6                           and     r14, rdx
0x02D459: 480FB6D0                         movzx   rdx, al
0x02D45D: 48C1E210                         shl     rdx, 10h
0x02D461: 4909D6                           or      r14, rdx
0x02D54F: 498B4928                         mov     rcx, [r9+28h]
0x32DC03: 4C8BB9E8000000                   mov     r15, [rcx+0E8h]
0x02D55A: 4157                             push    r15
0x02D55C: 4889E5                           mov     rbp, rsp
0x32DC6E: 488BB9E8000000                   mov     rdi, [rcx+0E8h]
0x02D64F: 4D8B5928                         mov     r11, [r9+28h]
0x32DD3A: 4D8BA3A0000000                   mov     r12, [r11+0A0h]
0x32DDA0: 498BB3B0000000                   mov     rsi, [r11+0B0h]
0x02D661: 4154                             push    r12
0x02D663: 68D23E534C                       push    4C533ED2h
0x02D668: 68D649EE20                       push    20EE49D6h
0x02D66D: 68AF277F3E                       push    3E7F27AFh
0x02D758: 498B4128                         mov     rax, [r9+28h]
0x32DE77: 4C8BB080000000                   mov     r14, [rax+80h]
0x32DEDE: 488BA8A8000000                   mov     rbp, [rax+0A8h]
0x02D76A: 4D0FB6F6                         movzx   r14, r14b
0x02D85B: 4D8B5928                         mov     r11, [r9+28h]
0x32DFA8: 410FAE93E8000000                 ldmxcsr dword ptr [r11+0E8h]
0x32E013: 49BEAF20BF0901000000             mov     r14, 109BF20AFh
0x32E07C: 4981C611524A36                   add     r14, 364A5211h
0x32E0E9: 4D8BB608070000                   mov     r14, [r14+708h]
0x32E153: 4D03B3E8000000                   add     r14, [r11+0E8h]
0x02D886: 458A3E                           mov     r15b, [r14]
0x02D889: 4D0FB6FF                         movzx   r15, r15b
0x02D88D: 49C1E720                         shl     r15, 20h
0x32E1BB: 4D29BBA0000000                   sub     [r11+0A0h], r15
0x02D898: 498B5128                         mov     rdx, [r9+28h]
0x32E224: 4C8BBAA0000000                   mov     r15, [rdx+0A0h]
0x32E28C: 48BFF612253801000000             mov     rdi, 1382512F6h
0x32E2F9: 4881C7CA57E407                   add     rdi, 7E457CAh
0x02D9AD: 498B7928                         mov     rdi, [r9+28h]
0x02D9B1: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x32E3C7: 488B9F80000000                   mov     rbx, [rdi+80h]
0x32E432: 4C8BB7F0000000                   mov     r14, [rdi+0F0h]
0x02DAAE: 4D8B7928                         mov     r15, [r9+28h]
0x32E4FD: 498BAFE8000000                   mov     rbp, [r15+0E8h]
0x02DAB9: 458B5F34                         mov     r11d, [r15+34h]
0x32E568: 4D039F90000000                   add     r11, [r15+90h]
0x02DAC4: 418A0B                           mov     cl, [r11]
0x32E5D0: 49C7C3FF000000                   mov     r11, 0FFh
0x02DACE: 49C1E318                         shl     r11, 18h
0x02DAD2: 49F7D3                           not     r11
0x02DAD5: 4C21DD                           and     rbp, r11
0x02DAD8: 4C0FB6D9                         movzx   r11, cl
0x02DADC: 49C1E318                         shl     r11, 18h
0x02DAE0: 4C09DD                           or      rbp, r11
0x02DBD4: 498B4128                         mov     rax, [r9+28h]
0x32E69D: 4C8B98A0000000                   mov     r11, [rax+0A0h]
0x02DBDF: 4153                             push    r11
0x02DBE1: 4989E7                           mov     r15, rsp
0x32E70B: 4C8BA8A0000000                   mov     r13, [rax+0A0h]
0x02DCCD: 498B4928                         mov     rcx, [r9+28h]
0x32E7DC: 4C8BB1A8000000                   mov     r14, [rcx+0A8h]
0x32E844: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x02DCDF: 4D0FB6F6                         movzx   r14, r14b
0x02DDB8: 4D8B6128                         mov     r12, [r9+28h]
0x32E918: 410FAE9424E8000000               ldmxcsr dword ptr [r12+0E8h]
0x32E986: 48BDBB19BCE700000000             mov     rbp, 0E7BC19BBh
0x32E9F5: 4881C505594D58                   add     rbp, 584D5905h
0x02DDD6: 488B6D00                         mov     rbp, [rbp+0]
0x32EA5C: 4903AC24E8000000                 add     rbp, [r12+0E8h]
0x02DDE2: 8A5500                           mov     dl, [rbp+0]
0x02DDE5: 480FB6D2                         movzx   rdx, dl
0x02DDE9: 48C1E228                         shl     rdx, 28h
0x32EAC9: 49299424A8000000                 sub     [r12+0A8h], rdx
0x32EB37: 49BB722ABB1401000000             mov     r11, 114BB2A72h
0x02DDFF: 4153                             push    r11
0x02DE01: 68734ACB6E                       push    6ECB4A73h
0x02DE06: 68DC550D58                       push    580D55DCh
0x02DE0B: 683D50953C                       push    3C95503Dh
0x02DE10: 68C41C9071                       push    71901CC4h
0x32EBA7: 48814424204E404E2B               add     qword ptr [rsp+20h], 2B4E404Eh
0x02DE1E: 498B5928                         mov     rbx, [r9+28h]
0x32EC17: 488BABA8000000                   mov     rbp, [rbx+0A8h]
0x02DF1A: 4D8B6928                         mov     r13, [r9+28h]
0x02DF1E: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x02DF23: 498B7578                         mov     rsi, [r13+78h]
0x32ECE8: 498B9DA0000000                   mov     rbx, [r13+0A0h]
0x02E007: 498B6928                         mov     rbp, [r9+28h]
0x32EDBA: 488BB590000000                   mov     rsi, [rbp+90h]
0x02E012: 8B4D34                           mov     ecx, [rbp+34h]
0x32EE21: 48038DA8000000                   add     rcx, [rbp+0A8h]
0x02E01C: 448A09                           mov     r9b, [rcx]
0x32EE87: 49C7C5FF000000                   mov     r13, 0FFh
0x02E026: 49C1E520                         shl     r13, 20h
0x02E02A: 49F7D5                           not     r13
0x02E02D: 4C21EE                           and     rsi, r13
0x02E030: 4D0FB6E9                         movzx   r13, r9b
0x02E034: 49C1E520                         shl     r13, 20h
0x02E038: 4C09EE                           or      rsi, r13
0x02E117: 498B7928                         mov     rdi, [r9+28h]
0x32EF5C: 4C8B9FA8000000                   mov     r11, [rdi+0A8h]
0x02E122: 4153                             push    r11
0x02E124: 4989E5                           mov     r13, rsp
0x32EFC7: 488BB7A8000000                   mov     rsi, [rdi+0A8h]
0x02E21E: 4D8B4928                         mov     r9, [r9+28h]
0x32F09E: 4D8B99E0000000                   mov     r11, [r9+0E0h]
0x32F108: 498B99A8000000                   mov     rbx, [r9+0A8h]
0x02E230: 4153                             push    r11
0x02E232: 68A4690E54                       push    540E69A4h
0x02E237: 68DC5CC060                       push    60C05CDCh
0x02E23C: 68D7563D19                       push    193D56D7h
0x02E241: 68287C6957                       push    57697C28h
0x02E32A: 498B5928                         mov     rbx, [r9+28h]
0x02E32E: 488B7378                         mov     rsi, [rbx+78h]
0x32F1D9: 488B9B90000000                   mov     rbx, [rbx+90h]
0x02E339: 480FB6F6                         movzx   rsi, sil
0x02E431: 498B7928                         mov     rdi, [r9+28h]
0x32F2A5: 0FAE97A8000000                   ldmxcsr dword ptr [rdi+0A8h]
0x02E43C: 4D8B6128                         mov     r12, [r9+28h]
0x32F30C: 4D8BB42490000000                 mov     r14, [r12+90h]
0x32F375: 49BCED280CE000000000             mov     r12, 0E00C28EDh
0x32F3DE: 4981C4D329FD5F                   add     r12, 5FFD29D3h
0x02E53F: 498B7128                         mov     rsi, [r9+28h]
0x02E543: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x32F4B2: 488B9E88000000                   mov     rbx, [rsi+88h]
0x32F520: 488BAEE8000000                   mov     rbp, [rsi+0E8h]
0x02E62E: 4D8B7928                         mov     r15, [r9+28h]
0x32F5F4: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x02E639: 458B5734                         mov     r10d, [r15+34h]
0x32F65E: 4D039790000000                   add     r10, [r15+90h]
0x02E644: 458A02                           mov     r8b, [r10]
0x02E647: 4588C6                           mov     r14b, r8b
0x02E735: 498B4128                         mov     rax, [r9+28h]
0x32F72A: 4C8BB0E8000000                   mov     r14, [rax+0E8h]
0x02E740: 4156                             push    r14
0x02E742: 4889E5                           mov     rbp, rsp
0x32F797: 488BB0E8000000                   mov     rsi, [rax+0E8h]
0x02E83F: 498B7928                         mov     rdi, [r9+28h]
0x32F866: 488B8FA0000000                   mov     rcx, [rdi+0A0h]
0x32F8CE: 4C8BB7A8000000                   mov     r14, [rdi+0A8h]
0x02E851: 51                               push    rcx
0x02E852: 68017EA029                       push    29A07E01h
0x02E857: 68405E1768                       push    68175E40h
0x02E85C: 68DE28540B                       push    0B5428DEh
0x02E861: 68803A5E66                       push    665E3A80h
0x02E944: 498B4128                         mov     rax, [r9+28h]
0x32F9A0: 488BB8A0000000                   mov     rdi, [rax+0A0h]
0x32FA08: 4C8BA8E8000000                   mov     r13, [rax+0E8h]
0x02E956: 480FB6FF                         movzx   rdi, dil
0x02EA3B: 498B5128                         mov     rdx, [r9+28h]
0x32FAD9: 0FAE92B0000000                   ldmxcsr dword ptr [rdx+0B0h]
0x32FB3E: 49BA50E25BDD00000000             mov     r10, 0DD5BE250h
0x02EA50: 4152                             push    r10
0x02EA52: 6853043E3B                       push    3B3E0453h
0x02EA57: 681D740D5D                       push    5D0D741Dh
0x02EA5C: 6842228862                       push    62882242h
0x32FBAF: 48814424187070AD62               add     [rsp-8+arg_18], 62AD7070h
0x02EA6A: 4D8B6928                         mov     r13, [r9+28h]
0x32FC1B: 498BBDE0000000                   mov     rdi, [r13+0E0h]
0x02EB51: 4D8B6928                         mov     r13, [r9+28h]
0x02EB55: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x32FCEB: 498BBDC0000000                   mov     rdi, [r13+0C0h]
0x32FD52: 498BB5B0000000                   mov     rsi, [r13+0B0h]
0x02EC55: 4D8B5128                         mov     r10, [r9+28h]
0x32FE20: 498BBAA8000000                   mov     rdi, [r10+0A8h]
0x02EC60: 458B6234                         mov     r12d, [r10+34h]
0x32FE88: 4D03A2B0000000                   add     r12, [r10+0B0h]
0x02EC6B: 418A3424                         mov     sil, [r12]
0x32FEEE: 49C7C0FF000000                   mov     r8, 0FFh
0x02EC76: 49C1E020                         shl     r8, 20h
0x02EC7A: 49F7D0                           not     r8
0x02EC7D: 4C21C7                           and     rdi, r8
0x02EC80: 4C0FB6C6                         movzx   r8, sil
0x02EC84: 49C1E020                         shl     r8, 20h
0x02EC88: 4C09C7                           or      rdi, r8
0x02ED6C: 498B4928                         mov     rcx, [r9+28h]
0x32FFBF: 488BB9B0000000                   mov     rdi, [rcx+0B0h]
0x02ED77: 57                               push    rdi
0x02ED78: 4989E5                           mov     r13, rsp
0x330028: 488B99B0000000                   mov     rbx, [rcx+0B0h]
0x02EE59: 4D8B6128                         mov     r12, [r9+28h]
0x3300FA: 4D8BAC24E0000000                 mov     r13, [r12+0E0h]
0x330161: 4D8BBC2490000000                 mov     r15, [r12+90h]
0x02EE6D: 4155                             push    r13
0x02EE6F: 685478B855                       push    55B87854h
0x02EE74: 689714C831                       push    31C81497h
0x02EE79: 68F76F934A                       push    4A936FF7h
0x02EF5D: 498B7128                         mov     rsi, [r9+28h]
0x33022E: 488BAEC8000000                   mov     rbp, [rsi+0C8h]
0x330299: 4C8BB6F0000000                   mov     r14, [rsi+0F0h]
0x02EF6F: 480FB6ED                         movzx   rbp, bpl
0x02F054: 498B4128                         mov     rax, [r9+28h]
0x33036F: 0FAE90A0000000                   ldmxcsr dword ptr [rax+0A0h]
0x02F05F: 4D8B5128                         mov     r10, [r9+28h]
0x3303DD: 498BBAE8000000                   mov     rdi, [r10+0E8h]
0x330442: 49BD2205A43601000000             mov     r13, 136A40522h
0x3304AB: 4981C59E4D6509                   add     r13, 9654D9Eh
0x02F16D: 4D8B6128                         mov     r12, [r9+28h]
0x33057F: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x3305E7: 498BBC24E8000000                 mov     rdi, [r12+0E8h]
0x330652: 4D8BBC24B0000000                 mov     r15, [r12+0B0h]
0x02F254: 4D8B6128                         mov     r12, [r9+28h]
0x330729: 498BB424F0000000                 mov     rsi, [r12+0F0h]
0x02F260: 418B442434                       mov     eax, [r12+34h]
0x330797: 49038424B0000000                 add     rax, [r12+0B0h]
0x02F26D: 8A00                             mov     al, [rax]
0x330806: 48C7C2FF000000                   mov     rdx, 0FFh
0x02F276: 48C1E228                         shl     rdx, 28h
0x02F27A: 48F7D2                           not     rdx
0x02F27D: 4821D6                           and     rsi, rdx
0x02F280: 480FB6D0                         movzx   rdx, al
0x02F284: 48C1E228                         shl     rdx, 28h
0x02F288: 4809D6                           or      rsi, rdx
0x02F36A: 498B7928                         mov     rdi, [r9+28h]
0x3308DF: 488B9FA8000000                   mov     rbx, [rdi+0A8h]
0x330947: 49BCCFEEC12901000000             mov     r12, 129C1EECFh
0x3309B6: 4981C421233E16                   add     r12, 163E2321h
0x02F386: 4885DB                           test    rbx, rbx
0x330A24: 488D2D6BE9CFFF                   lea     rbp, unk_6A4F396
0x02F390: 490F45EC                         cmovnz  rbp, r12
0x02F394: FFE5                             jmp     rbp
