0x2E4D49: 49BB497FDD0A01000000             mov     r11, 10ADD7F49h
0x0000A2: 4153                             push    r11
0x0000A4: 6836547773                       push    73775436h
0x0000A9: 68434CA068                       push    68A04C43h
0x0000AE: 68F97F9112                       push    12917FF9h
0x2E4DB8: 48814424189F39AC35               add     qword ptr [rsp+18h], 35AC399Fh
0x0001A7: 498B6928                         mov     rbp, [r9+28h]
0x2E4E8C: 488BBDE0000000                   mov     rdi, [rbp+0E0h]
0x0001B2: 480FB6FF                         movzx   rdi, dil
0x0002A2: 4D8B4128                         mov     r8, [r9+28h]
0x2E4F5E: 498B80B0000000                   mov     rax, [r8+0B0h]
0x2E4FC3: 49C7C2A77437B9                   mov     r10, 0FFFFFFFFB93774A7h
0x2E502F: 4981C2E505B847                   add     r10, 47B805E5h
0x0002BB: 4152                             push    r10
0x0002BD: 48F72424                         mul     qword ptr [rsp]
0x0002C1: 4889C5                           mov     rbp, rax
0x0003A8: 498B5128                         mov     rdx, [r9+28h]
0x2E5100: 4C8BBAA0000000                   mov     r15, [rdx+0A0h]
0x0003B3: 4157                             push    r15
0x0003B5: 4989E4                           mov     r12, rsp
0x2E5168: 488BB2A0000000                   mov     rsi, [rdx+0A0h]
0x0004A9: 4D8B5128                         mov     r10, [r9+28h]
0x2E5237: 4D8B8AD8000000                   mov     r9, [r10+0D8h]
0x2E52A2: 498BAAA8000000                   mov     rbp, [r10+0A8h]
0x0004BB: 4151                             push    r9
0x0004BD: 684435AE58                       push    58AE3544h
0x0004C2: 68E12FE57E                       push    7EE52FE1h
0x0004C7: 6836099B64                       push    649B0936h
0x00059F: 498B7928                         mov     rdi, [r9+28h]
0x0005A3: 488B5F78                         mov     rbx, [rdi+78h]
0x2E536C: 4C8BBFA0000000                   mov     r15, [rdi+0A0h]
0x0005AE: 480FB6DB                         movzx   rbx, bl
0x000691: 4D8B7928                         mov     r15, [r9+28h]
0x2E5440: 410FAE9790000000                 ldmxcsr dword ptr [r15+90h]
0x2E54AE: 49BE4B1F43D400000000             mov     r14, 0D4431F4Bh
0x2E5519: 4981C67543C66B                   add     r14, 6BC64375h
0x2E5585: 4D8BB668040000                   mov     r14, [r14+468h]
0x2E55EF: 4D03B790000000                   add     r14, [r15+90h]
0x0006BC: 418A36                           mov     sil, [r14]
0x0006BF: 480FB6F6                         movzx   rsi, sil
0x0006C3: 48C1E608                         shl     rsi, 8
0x2E565A: 4901B7F0000000                   add     [r15+0F0h], rsi
0x0006CE: 498B4128                         mov     rax, [r9+28h]
0x2E56C3: 4C8BA8F0000000                   mov     r13, [rax+0F0h]
0x2E572C: 48BBE32BE83301000000             mov     rbx, 133E82BE3h
0x2E579C: 4881C3DD2E210C                   add     rbx, 0C212EDDh
0x0007DE: 498B5128                         mov     rdx, [r9+28h]
0x0007E2: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x2E5865: 4C8BAAF0000000                   mov     r13, [rdx+0F0h]
0x2E58CA: 488BBAE0000000                   mov     rdi, [rdx+0E0h]
0x0008E0: 498B5928                         mov     rbx, [r9+28h]
0x2E599C: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x0008EB: 448B5B34                         mov     r11d, [rbx+34h]
0x2E5A03: 4C039BE0000000                   add     r11, [rbx+0E0h]
0x0008F6: 418A2B                           mov     bpl, [r11]
0x0008F9: 4088EF                           mov     dil, bpl
0x0009EB: 498B7128                         mov     rsi, [r9+28h]
0x2E5AD0: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x0009F6: 57                               push    rdi
0x0009F7: 4889E7                           mov     rdi, rsp
0x2E5B35: 4C8BA6B0000000                   mov     r12, [rsi+0B0h]
0x000AF1: 4D8B6928                         mov     r13, [r9+28h]
0x2E5BFD: 498BBDB0000000                   mov     rdi, [r13+0B0h]
0x2E5C6B: 4D8BBDD8000000                   mov     r15, [r13+0D8h]
0x000B03: 57                               push    rdi
0x000B04: 687558057A                       push    7A055875h
0x000B09: 686B58A817                       push    17A8586Bh
0x000B0E: 68901F2D78                       push    782D1F90h
0x000BFB: 498B7928                         mov     rdi, [r9+28h]
0x2E5D3C: 488B9FD0000000                   mov     rbx, [rdi+0D0h]
0x2E5DA7: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x000C0D: 480FB6DB                         movzx   rbx, bl
0x000CFB: 4D8B7128                         mov     r14, [r9+28h]
0x2E5E76: 410FAE9690000000                 ldmxcsr dword ptr [r14+90h]
0x2E5EE5: 48BEFFEB261101000000             mov     rsi, 11126EBFFh
0x2E5F55: 4881C6C176E22E                   add     rsi, 2EE276C1h
0x2E5FC1: 488BB6E8020000                   mov     rsi, [rsi+2E8h]
0x2E6028: 4903B690000000                   add     rsi, [r14+90h]
0x000D26: 408A2E                           mov     bpl, [rsi]
0x000D29: 480FB6ED                         movzx   rbp, bpl
0x000D2D: 48C1E510                         shl     rbp, 10h
0x2E6091: 4901AEB0000000                   add     [r14+0B0h], rbp
0x000D38: 498B4928                         mov     rcx, [r9+28h]
0x2E60F6: 4C8BB1B0000000                   mov     r14, [rcx+0B0h]
0x2E6160: 48BD55EED5E700000000             mov     rbp, 0E7D5EE55h
0x2E61CC: 4881C56B6C3358                   add     rbp, 58336C6Bh
0x000E3A: 4D8B4928                         mov     r9, [r9+28h]
0x000E3E: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x2E6297: 4D8BA9A0000000                   mov     r13, [r9+0A0h]
0x2E6301: 4D8BB9E8000000                   mov     r15, [r9+0E8h]
0x000F2D: 4D8B6928                         mov     r13, [r9+28h]
0x2E63DB: 498BADF0000000                   mov     rbp, [r13+0F0h]
0x000F38: 418B4534                         mov     eax, [r13+34h]
0x2E6446: 490385E0000000                   add     rax, [r13+0E0h]
0x000F43: 448A38                           mov     r15b, [rax]
0x2E64AD: 49C7C6FF000000                   mov     r14, 0FFh
0x000F4D: 49C1E608                         shl     r14, 8
0x000F51: 49F7D6                           not     r14
0x000F54: 4C21F5                           and     rbp, r14
0x000F57: 4D0FB6F7                         movzx   r14, r15b
0x000F5B: 49C1E608                         shl     r14, 8
0x000F5F: 4C09F5                           or      rbp, r14
0x001048: 498B6928                         mov     rbp, [r9+28h]
0x2E6576: 4C8B85A0000000                   mov     r8, [rbp+0A0h]
0x001053: 4150                             push    r8
0x001055: 4989E6                           mov     r14, rsp
0x2E65E4: 4C8BA5A0000000                   mov     r12, [rbp+0A0h]
0x001140: 498B7128                         mov     rsi, [r9+28h]
0x2E66B1: 4C8BBE80000000                   mov     r15, [rsi+80h]
0x2E671E: 488BBED8000000                   mov     rdi, [rsi+0D8h]
0x001152: 4D0FB6FF                         movzx   r15, r15b
0x001236: 4D8B7928                         mov     r15, [r9+28h]
0x2E67F2: 410FAE97F0000000                 ldmxcsr dword ptr [r15+0F0h]
0x2E6858: 48BD7CEAE2FF00000000             mov     rbp, 0FFE2EA7Ch
0x2E68C1: 4881C544782640                   add     rbp, 40267844h
0x2E6929: 488BAD30040000                   mov     rbp, [rbp+430h]
0x2E6991: 4903AFF0000000                   add     rbp, [r15+0F0h]
0x001261: 8A4D00                           mov     cl, [rbp+0]
0x001264: 480FB6C9                         movzx   rcx, cl
0x001268: 48C1E118                         shl     rcx, 18h
0x2E69F8: 49018FB0000000                   add     [r15+0B0h], rcx
0x001273: 4D8B4928                         mov     r9, [r9+28h]
0x2E6A65: 498B99B0000000                   mov     rbx, [r9+0B0h]
0x2E6ACB: 49BE3741280E01000000             mov     r14, 10E284137h
0x2E6B39: 4981C68919E131                   add     r14, 31E11989h
0x00137D: 498B7128                         mov     rsi, [r9+28h]
0x001381: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x2E6C06: 4C8BAEB0000000                   mov     r13, [rsi+0B0h]
0x2E6C71: 488BAE90000000                   mov     rbp, [rsi+90h]
0x001466: 498B7128                         mov     rsi, [r9+28h]
0x2E6D49: 488BAEA0000000                   mov     rbp, [rsi+0A0h]
0x001471: 448B5634                         mov     r10d, [rsi+34h]
0x2E6DB0: 4C0396E0000000                   add     r10, [rsi+0E0h]
0x00147C: 458A22                           mov     r12b, [r10]
0x2E6E1A: 48C7C3FF000000                   mov     rbx, 0FFh
0x001486: 48C1E310                         shl     rbx, 10h
0x00148A: 48F7D3                           not     rbx
0x00148D: 4821DD                           and     rbp, rbx
0x001490: 490FB6DC                         movzx   rbx, r12b
0x001494: 48C1E310                         shl     rbx, 10h
0x001498: 4809DD                           or      rbp, rbx
0x001574: 498B7928                         mov     rdi, [r9+28h]
0x2E6EEB: 488BAFA0000000                   mov     rbp, [rdi+0A0h]
0x00157F: 55                               push    rbp
0x001580: 4989E5                           mov     r13, rsp
0x2E6F52: 488BBFA0000000                   mov     rdi, [rdi+0A0h]
0x001677: 498B5128                         mov     rdx, [r9+28h]
0x2E702C: 488B9AE0000000                   mov     rbx, [rdx+0E0h]
0x2E709A: 4C8BB2B0000000                   mov     r14, [rdx+0B0h]
0x001689: 53                               push    rbx
0x00168A: 68501F8072                       push    72801F50h
0x00168F: 680A28095D                       push    5D09280Ah
0x001694: 686854A625                       push    25A65468h
0x001699: 6805065B75                       push    755B0605h
0x001786: 4D8B5128                         mov     r10, [r9+28h]
0x2E7165: 498BAAD8000000                   mov     rbp, [r10+0D8h]
0x2E71D0: 4D8BA2E8000000                   mov     r12, [r10+0E8h]
0x001798: 480FB6ED                         movzx   rbp, bpl
0x001884: 498B5128                         mov     rdx, [r9+28h]
0x2E72A2: 0FAE92A0000000                   ldmxcsr dword ptr [rdx+0A0h]
0x2E730F: 49BBF737CACA00000000             mov     r11, 0CACA37F7h
0x2E737B: 4981C3C92A3F75                   add     r11, 753F2AC9h
0x2E73E5: 4D8B9BE8040000                   mov     r11, [r11+4E8h]
0x2E744B: 4C039AA0000000                   add     r11, [rdx+0A0h]
0x0018AE: 418A3B                           mov     dil, [r11]
0x0018B1: 480FB6FF                         movzx   rdi, dil
0x0018B5: 48C1E720                         shl     rdi, 20h
0x2E74B8: 4801BAD8000000                   add     [rdx+0D8h], rdi
0x2E7526: 48BF1A4B811901000000             mov     rdi, 119814B1Ah
0x0018CA: 57                               push    rdi
0x0018CB: 68126ED610                       push    10D66E12h
0x0018D0: 688E22C80C                       push    0CC8228Eh
0x0018D5: 68A5076163                       push    636107A5h
0x0018DA: 683119023E                       push    3E021931h
0x2E7594: 4881442420A60F8826               add     qword ptr [rsp+20h], 26880FA6h
0x0018E8: 498B4128                         mov     rax, [r9+28h]
0x2E7604: 4C8BB8D8000000                   mov     r15, [rax+0D8h]
0x0019DA: 498B5128                         mov     rdx, [r9+28h]
0x0019DE: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x2E76D7: 488BBAC0000000                   mov     rdi, [rdx+0C0h]
0x2E773D: 488B9AF0000000                   mov     rbx, [rdx+0F0h]
0x001ACF: 4D8B4128                         mov     r8, [r9+28h]
0x2E7810: 4D8BB890000000                   mov     r15, [r8+90h]
0x001ADA: 418B4834                         mov     ecx, [r8+34h]
0x2E7878: 490388B0000000                   add     rcx, [r8+0B0h]
0x001AE5: 448A01                           mov     r8b, [rcx]
0x2E78E4: 49C7C4FF000000                   mov     r12, 0FFh
0x001AEF: 49C1E418                         shl     r12, 18h
0x001AF3: 49F7D4                           not     r12
0x001AF6: 4D21E7                           and     r15, r12
0x001AF9: 4D0FB6E0                         movzx   r12, r8b
0x001AFD: 49C1E418                         shl     r12, 18h
0x001B01: 4D09E7                           or      r15, r12
0x001BD9: 4D8B4128                         mov     r8, [r9+28h]
0x2E79B8: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x001BE4: 56                               push    rsi
0x001BE5: 4989E6                           mov     r14, rsp
0x2E7A24: 4D8BB8F0000000                   mov     r15, [r8+0F0h]
0x001CD3: 4D8B6928                         mov     r13, [r9+28h]
0x2E7AF5: 498B8DE8000000                   mov     rcx, [r13+0E8h]
0x2E7B5D: 498BBDF0000000                   mov     rdi, [r13+0F0h]
0x001CE5: 51                               push    rcx
0x001CE6: 689D59A42D                       push    2DA4599Dh
0x001CEB: 68FD5D9514                       push    14955DFDh
0x001CF0: 6811734705                       push    5477311h
0x001DEE: 498B4128                         mov     rax, [r9+28h]
0x2E7C2E: 4C8BA888000000                   mov     r13, [rax+88h]
0x2E7C95: 488BB0B0000000                   mov     rsi, [rax+0B0h]
0x001E00: 4D0FB6ED                         movzx   r13, r13b
0x001EF4: 498B6928                         mov     rbp, [r9+28h]
0x2E7D67: 0FAE95E0000000                   ldmxcsr dword ptr [rbp+0E0h]
0x2E7DD2: 48BE3F0B12FC00000000             mov     rsi, 0FC120B3Fh
0x2E7E3C: 4881C68157F743                   add     rsi, 43F75781h
0x001F10: 488B36                           mov     rsi, [rsi]
0x2E7EA2: 4803B5E0000000                   add     rsi, [rbp+0E0h]
0x001F1A: 8A1E                             mov     bl, [rsi]
0x001F1C: 480FB6DB                         movzx   rbx, bl
0x001F20: 48C1E328                         shl     rbx, 28h
0x2E7F0D: 48019DA8000000                   add     [rbp+0A8h], rbx
0x001F2B: 498B4928                         mov     rcx, [r9+28h]
0x2E7F75: 4C8BB9A8000000                   mov     r15, [rcx+0A8h]
0x2E7FE3: 48BEEE4904C400000000             mov     rsi, 0C40449EEh
0x2E804B: 4881C6D210057C                   add     rsi, 7C0510D2h
0x002027: 4D8B6128                         mov     r12, [r9+28h]
0x2E811D: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x2E8185: 4D8BAC24C8000000                 mov     r13, [r12+0C8h]
0x2E81F2: 498BB424F0000000                 mov     rsi, [r12+0F0h]
0x002120: 4D8B4128                         mov     r8, [r9+28h]
0x2E82BD: 4D8BA8A8000000                   mov     r13, [r8+0A8h]
0x00212B: 458B7034                         mov     r14d, [r8+34h]
0x2E832B: 4D03B0E0000000                   add     r14, [r8+0E0h]
0x002136: 458A26                           mov     r12b, [r14]
0x2E8392: 48C7C1FF000000                   mov     rcx, 0FFh
0x002140: 48C1E120                         shl     rcx, 20h
0x002144: 48F7D1                           not     rcx
0x002147: 4921CD                           and     r13, rcx
0x00214A: 490FB6CC                         movzx   rcx, r12b
0x00214E: 48C1E120                         shl     rcx, 20h
0x002152: 4909CD                           or      r13, rcx
0x00222F: 4D8B6928                         mov     r13, [r9+28h]
0x2E8463: 4D8B85E0000000                   mov     r8, [r13+0E0h]
0x00223A: 4150                             push    r8
0x00223C: 4889E3                           mov     rbx, rsp
0x2E84CF: 4D8BADE0000000                   mov     r13, [r13+0E0h]
0x002333: 4D8B5128                         mov     r10, [r9+28h]
0x2E85A2: 4D8B8290000000                   mov     r8, [r10+90h]
0x2E860D: 498BB2E0000000                   mov     rsi, [r10+0E0h]
0x002345: 4150                             push    r8
0x002347: 68366A160A                       push    0A166A36h
0x00234C: 68514F7D18                       push    187D4F51h
0x002351: 680C1C1437                       push    37141C0Ch
0x002443: 498B4128                         mov     rax, [r9+28h]
0x2E86E1: 4C8BB8B8000000                   mov     r15, [rax+0B8h]
0x2E874F: 488BB0A8000000                   mov     rsi, [rax+0A8h]
0x002455: 4D0FB6FF                         movzx   r15, r15b
0x002534: 498B7928                         mov     rdi, [r9+28h]
0x2E8820: 0FAE97F0000000                   ldmxcsr dword ptr [rdi+0F0h]
0x2E888D: 48B8C509213D01000000             mov     rax, 13D2109C5h
0x2E88F9: 4805FB58E802                     add     rax, 2E858FBh
0x00254F: 488B00                           mov     rax, [rax]
0x2E895F: 480387F0000000                   add     rax, [rdi+0F0h]
0x002559: 448A10                           mov     r10b, [rax]
0x00255C: 4D0FB6D2                         movzx   r10, r10b
0x002560: 49C1E238                         shl     r10, 38h
0x2E89C6: 4C0197A8000000                   add     [rdi+0A8h], r10
0x2E8A30: 49B80BE3632F01000000             mov     r8, 12F63E30Bh
0x002575: 4150                             push    r8
0x002577: 682D103B73                       push    733B102Dh
0x00257C: 680E23D14E                       push    4ED1230Eh
0x002581: 6841077322                       push    22730741h
0x002586: 68B5411979                       push    791941B5h
0x2E8AA1: 4881442420B577A510               add     [rsp-8+arg_20], 10A577B5h
0x002594: 498B7128                         mov     rsi, [r9+28h]
0x2E8B0C: 4C8BB6A8000000                   mov     r14, [rsi+0A8h]
0x00268E: 498B5928                         mov     rbx, [r9+28h]
0x002692: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x2E8BDC: 488BBB80000000                   mov     rdi, [rbx+80h]
0x2E8C44: 4C8BABE8000000                   mov     r13, [rbx+0E8h]
0x00278A: 4D8B4128                         mov     r8, [r9+28h]
0x2E8D15: 4D8BB8E0000000                   mov     r15, [r8+0E0h]
0x002795: 418B4834                         mov     ecx, [r8+34h]
0x2E8D7C: 490388B0000000                   add     rcx, [r8+0B0h]
0x0027A0: 448A31                           mov     r14b, [rcx]
0x2E8DE5: 48C7C5FF000000                   mov     rbp, 0FFh
0x0027AA: 48C1E530                         shl     rbp, 30h
0x0027AE: 48F7D5                           not     rbp
0x0027B1: 4921EF                           and     r15, rbp
0x0027B4: 490FB6EE                         movzx   rbp, r14b
0x0027B8: 48C1E530                         shl     rbp, 30h
0x0027BC: 4909EF                           or      r15, rbp
0x002892: 4D8B5128                         mov     r10, [r9+28h]
0x2E8EB8: 4D8BA2F0000000                   mov     r12, [r10+0F0h]
0x2E8F20: 49BED2A1F42901000000             mov     r14, 129F4A1D2h
0x2E8F89: 4981C616179516                   add     r14, 16951716h
0x002988: 498B7128                         mov     rsi, [r9+28h]
0x2E905A: 488BAEB0000000                   mov     rbp, [rsi+0B0h]
0x2E90C5: 4C8BA6D8000000                   mov     r12, [rsi+0D8h]
0x00299A: 480FB6ED                         movzx   rbp, bpl
0x002A86: 498B7928                         mov     rdi, [r9+28h]
0x2E9193: 488B87A0000000                   mov     rax, [rdi+0A0h]
0x2E91FB: 49C7C4177E649A                   mov     r12, 0FFFFFFFF9A647E17h
0x2E9262: 4981C42537E165                   add     r12, 65E13725h
0x002A9F: 4154                             push    r12
0x2E92CB: 488BAFD8000000                   mov     rbp, [rdi+0D8h]
0x002AA8: 48F72424                         mul     qword ptr [rsp]
0x002AAC: 4889C7                           mov     rdi, rax
0x002B88: 498B7128                         mov     rsi, [r9+28h]
0x2E9395: 488BBEA0000000                   mov     rdi, [rsi+0A0h]
0x2E93FF: 482BBEB0000000                   sub     rdi, [rsi+0B0h]
0x002C79: 498B4128                         mov     rax, [r9+28h]
0x2E94CC: 488B88B0000000                   mov     rcx, [rax+0B0h]
0x002C84: 51                               push    rcx
0x002C85: 4989E7                           mov     r15, rsp
0x2E9533: 4C8BA8B0000000                   mov     r13, [rax+0B0h]
0x002D6B: 4D8B4128                         mov     r8, [r9+28h]
0x2E9605: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x2E966B: 498B98E0000000                   mov     rbx, [r8+0E0h]
0x002D7D: 56                               push    rsi
0x002D7E: 680D782E19                       push    192E780Dh
0x002D83: 68AB7A0205                       push    5027AABh
0x002D88: 6843219F03                       push    39F2143h
0x002D8D: 681E23986A                       push    6A98231Eh
0x002E67: 4D8B4928                         mov     r9, [r9+28h]
0x2E9743: 498B99C8000000                   mov     rbx, [r9+0C8h]
0x2E97B1: 498BB190000000                   mov     rsi, [r9+90h]
0x002E79: 480FB6DB                         movzx   rbx, bl
0x002F5C: 4D8B7928                         mov     r15, [r9+28h]
0x2E9885: 410FAE9790000000                 ldmxcsr dword ptr [r15+90h]
0x2E98F4: 48BB3CECDE0501000000             mov     rbx, 105DEEC3Ch
0x2E9962: 4881C384762A3A                   add     rbx, 3A2A7684h
0x2E99C9: 488B9BB8020000                   mov     rbx, [rbx+2B8h]
0x2E9A32: 49039F90000000                   add     rbx, [r15+90h]
0x002F87: 8A0B                             mov     cl, [rbx]
0x002F89: 480FB6C9                         movzx   rcx, cl
0x002F8D: 48C1E108                         shl     rcx, 8
0x2E9AA0: 49018FA8000000                   add     [r15+0A8h], rcx
0x002F98: 498B4928                         mov     rcx, [r9+28h]
0x2E9B05: 488BB1A8000000                   mov     rsi, [rcx+0A8h]
0x2E9B6F: 49BC93FBC70801000000             mov     r12, 108C7FB93h
0x2E9BDF: 4981C42D5F4137                   add     r12, 37415F2Dh
0x0030B1: 4D8B6128                         mov     r12, [r9+28h]
0x2E9CAE: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x2E9D18: 498B9C24D8000000                 mov     rbx, [r12+0D8h]
0x2E9D83: 4D8BB424A8000000                 mov     r14, [r12+0A8h]
0x0031AF: 4D8B4928                         mov     r9, [r9+28h]
0x2E9E54: 4D8BA9E8000000                   mov     r13, [r9+0E8h]
0x0031BA: 458B4134                         mov     r8d, [r9+34h]
0x2E9EBC: 4D038190000000                   add     r8, [r9+90h]
0x0031C5: 418A18                           mov     bl, [r8]
0x0031C8: 4188DD                           mov     r13b, bl
0x003295: 4D8B4128                         mov     r8, [r9+28h]
0x2E9F94: 498B88E0000000                   mov     rcx, [r8+0E0h]
0x0032A0: 51                               push    rcx
0x0032A1: 4989E6                           mov     r14, rsp
0x2E9FFC: 498BB0E0000000                   mov     rsi, [r8+0E0h]
0x003389: 4D8B6128                         mov     r12, [r9+28h]
0x2EA0C7: 498BB424B8000000                 mov     rsi, [r12+0B8h]
0x2EA133: 4D8BBC24A8000000                 mov     r15, [r12+0A8h]
0x00339D: 480FB6F6                         movzx   rsi, sil
0x00347E: 4D8B6928                         mov     r13, [r9+28h]
0x2EA204: 410FAE95A8000000                 ldmxcsr dword ptr [r13+0A8h]
0x2EA26B: 48BBEA3DE41901000000             mov     rbx, 119E43DEAh
0x2EA2D7: 4881C3D6242526                   add     rbx, 262524D6h
0x2EA33E: 488B9B70070000                   mov     rbx, [rbx+770h]
0x2EA3A5: 49039DA8000000                   add     rbx, [r13+0A8h]
0x0034A9: 448A33                           mov     r14b, [rbx]
0x0034AC: 4D0FB6F6                         movzx   r14, r14b
0x0034B0: 49C1E610                         shl     r14, 10h
0x2EA413: 4D01B5F0000000                   add     [r13+0F0h], r14
0x2EA481: 49BBB21D571E01000000             mov     r11, 11E571DB2h
0x0034C5: 4153                             push    r11
0x0034C7: 68EF6FAD38                       push    38AD6FEFh
0x0034CC: 68460C706F                       push    6F700C46h
0x0034D1: 68C0355B36                       push    365B35C0h
0x0034D6: 68AF25310A                       push    0A3125AFh
0x2EA4EC: 48814424200E3DB221               add     [rsp-8+arg_20], 21B23D0Eh
0x0034E4: 4D8B5928                         mov     r11, [r9+28h]
0x2EA55A: 4D8BB3F0000000                   mov     r14, [r11+0F0h]
0x0035E1: 498B6928                         mov     rbp, [r9+28h]
0x0035E5: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x2EA627: 4C8BAD90000000                   mov     r13, [rbp+90h]
0x2EA692: 4C8BA5E8000000                   mov     r12, [rbp+0E8h]
0x0036E0: 4D8B4928                         mov     r9, [r9+28h]
0x2EA767: 4D8BB9D8000000                   mov     r15, [r9+0D8h]
0x0036EB: 458B5134                         mov     r10d, [r9+34h]
0x2EA7D1: 4D0391E0000000                   add     r10, [r9+0E0h]
0x0036F6: 418A0A                           mov     cl, [r10]
0x2EA83F: 49C7C3FF000000                   mov     r11, 0FFh
0x003700: 49C1E308                         shl     r11, 8
0x003704: 49F7D3                           not     r11
0x003707: 4D21DF                           and     r15, r11
0x00370A: 4C0FB6D9                         movzx   r11, cl
0x00370E: 49C1E308                         shl     r11, 8
0x003712: 4D09DF                           or      r15, r11
0x0037FC: 498B4128                         mov     rax, [r9+28h]
0x2EA911: 4C8BB0F0000000                   mov     r14, [rax+0F0h]
0x003807: 4156                             push    r14
0x003809: 4889E5                           mov     rbp, rsp
0x2EA97D: 4C8BA0F0000000                   mov     r12, [rax+0F0h]
0x0038F4: 498B4928                         mov     rcx, [r9+28h]
0x2EAA48: 488BA9A0000000                   mov     rbp, [rcx+0A0h]
0x2EAAAF: 4C8BB1D8000000                   mov     r14, [rcx+0D8h]
0x003906: 55                               push    rbp
0x003907: 68D7548F3B                       push    3B8F54D7h
0x00390C: 687D4C267B                       push    7B264C7Dh
0x003911: 68C2785519                       push    195578C2h
0x003916: 68662E766A                       push    6A762E66h
0x003A02: 4D8B6928                         mov     r13, [r9+28h]
0x003A06: 498B7D78                         mov     rdi, [r13+78h]
0x2EAB84: 4D8BB5E8000000                   mov     r14, [r13+0E8h]
0x003A11: 480FB6FF                         movzx   rdi, dil
0x003AFA: 4D8B5928                         mov     r11, [r9+28h]
0x2EAC51: 410FAE93B0000000                 ldmxcsr dword ptr [r11+0B0h]
0x2EACBD: 48BA725EC00301000000             mov     rdx, 103C05E72h
0x2EAD28: 4881C24E04493C                   add     rdx, 3C49044Eh
0x2EAD95: 488B92D0050000                   mov     rdx, [rdx+5D0h]
0x2EAE02: 490393B0000000                   add     rdx, [r11+0B0h]
0x003B25: 408A3A                           mov     dil, [rdx]
0x003B28: 480FB6FF                         movzx   rdi, dil
0x003B2C: 48C1E718                         shl     rdi, 18h
0x2EAE6A: 4901BBE8000000                   add     [r11+0E8h], rdi
0x2EAED0: 48BA09E90AF300000000             mov     rdx, 0F30AE909h
0x003B41: 52                               push    rdx
0x003B42: 689051132B                       push    2B135190h
0x003B47: 689129F50A                       push    0AF52991h
0x003B4C: 686416B252                       push    52B21664h
0x003B51: 68104A293E                       push    3E294A10h
0x2EAF3C: 4881442420B771FE4C               add     qword ptr [rsp+20h], 4CFE71B7h
0x003B5F: 498B7128                         mov     rsi, [r9+28h]
0x2EAFAC: 4C8BB6E8000000                   mov     r14, [rsi+0E8h]
0x003C69: 4D8B5928                         mov     r11, [r9+28h]
0x003C6D: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x2EB07C: 498BABE0000000                   mov     rbp, [r11+0E0h]
0x2EB0E4: 4D8BB3E8000000                   mov     r14, [r11+0E8h]
0x003D5F: 4D8B7928                         mov     r15, [r9+28h]
0x2EB1B5: 4D8BA7E8000000                   mov     r12, [r15+0E8h]
0x003D6A: 418B5F34                         mov     ebx, [r15+34h]
0x2EB223: 49039FA0000000                   add     rbx, [r15+0A0h]
0x003D75: 448A0B                           mov     r9b, [rbx]
0x2EB28D: 49C7C5FF000000                   mov     r13, 0FFh
0x003D7F: 49C1E510                         shl     r13, 10h
0x003D83: 49F7D5                           not     r13
0x003D86: 4D21EC                           and     r12, r13
0x003D89: 4D0FB6E9                         movzx   r13, r9b
0x003D8D: 49C1E510                         shl     r13, 10h
0x003D91: 4D09EC                           or      r12, r13
0x003E70: 4D8B6928                         mov     r13, [r9+28h]
0x2EB35D: 498BB5D8000000                   mov     rsi, [r13+0D8h]
0x003E7B: 56                               push    rsi
0x003E7C: 4889E6                           mov     rsi, rsp
0x2EB3C6: 4D8BBDD8000000                   mov     r15, [r13+0D8h]
0x003F70: 4D8B7128                         mov     r14, [r9+28h]
0x2EB491: 4D8BAEA8000000                   mov     r13, [r14+0A8h]
0x2EB4FE: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x003F82: 4155                             push    r13
0x003F84: 687A58D620                       push    20D6587Ah
0x003F89: 68656F4370                       push    70436F65h
0x003F8E: 68BA3D0C64                       push    640C3DBAh
0x003F93: 682C4DD246                       push    46D24D2Ch
0x004080: 4D8B4928                         mov     r9, [r9+28h]
0x2EB5CE: 498BA9A0000000                   mov     rbp, [r9+0A0h]
0x2EB634: 4D8BB1F0000000                   mov     r14, [r9+0F0h]
0x004092: 480FB6ED                         movzx   rbp, bpl
0x004182: 4D8B7928                         mov     r15, [r9+28h]
0x2EB707: 410FAE97A0000000                 ldmxcsr dword ptr [r15+0A0h]
0x2EB76D: 48B84A4D1B1601000000             mov     rax, 1161B4D4Ah
0x2EB7D6: 48057615EE29                     add     rax, 29EE1576h
0x2EB842: 488B80C0000000                   mov     rax, [rax+0C0h]
0x2EB8B0: 490387A0000000                   add     rax, [r15+0A0h]
0x0041AC: 448A28                           mov     r13b, [rax]
0x0041AF: 4D0FB6ED                         movzx   r13, r13b
0x0041B3: 49C1E520                         shl     r13, 20h
0x2EB91C: 4D01AFE8000000                   add     [r15+0E8h], r13
0x0041BE: 4D8B5928                         mov     r11, [r9+28h]
0x2EB986: 4D8BA3E8000000                   mov     r12, [r11+0E8h]
0x2EB9ED: 49BEF60D64F300000000             mov     r14, 0F3640DF6h
0x2EBA55: 4981C6CA4CA54C                   add     r14, 4CA54CCAh
0x0042B2: 498B7928                         mov     rdi, [r9+28h]
0x0042B6: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x2EBB25: 4C8BA7E0000000                   mov     r12, [rdi+0E0h]
0x2EBB92: 4C8BAFD8000000                   db  4Ch ; L
0x0043A8: 4D8B4928                         mov     r9, [r9+28h]
0x2EBC60: 4D8BA9E0000000                   mov     r13, [r9+0E0h]
0x0043B3: 458B7934                         mov     r15d, [r9+34h]
0x2EBCC6: 4D03B9D8000000                   add     r15, [r9+0D8h]
0x0043BE: 458A07                           mov     r8b, [r15]
0x2EBD2C: 49C7C3FF000000                   mov     r11, 0FFh
0x0043C8: 49C1E318                         shl     r11, 18h
0x0043CC: 49F7D3                           not     r11
0x0043CF: 4D21DD                           and     r13, r11
0x0043D2: 4D0FB6D8                         movzx   r11, r8b
0x0043D6: 49C1E318                         shl     r11, 18h
0x0043DA: 4D09DD                           or      r13, r11
0x0044CB: 498B4928                         mov     rcx, [r9+28h]
0x2EBDFC: 488BA9E0000000                   mov     rbp, [rcx+0E0h]
0x0044D6: 55                               push    rbp
0x0044D7: 4889E3                           mov     rbx, rsp
0x2EBE6A: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x0045CC: 4D8B4128                         mov     r8, [r9+28h]
0x2EBF3E: 498B9890000000                   mov     rbx, [r8+90h]
0x2EBFA3: 498BB8A8000000                   mov     rdi, [r8+0A8h]
0x0045DE: 53                               push    rbx
0x0045DF: 681F1B672C                       push    2C671B1Fh
0x0045E4: 680952E378                       push    78E35209h
0x0045E9: 688910A56A                       push    6AA51089h
0x0046CF: 498B5128                         mov     rdx, [r9+28h]
0x2EC06E: 488BB290000000                   mov     rsi, [rdx+90h]
0x2EC0D7: 488BAAB0000000                   mov     rbp, [rdx+0B0h]
0x0046E1: 480FB6F6                         movzx   rsi, sil
0x0047B2: 498B5928                         mov     rbx, [r9+28h]
0x2EC1A8: 0FAE93A8000000                   ldmxcsr dword ptr [rbx+0A8h]
0x2EC213: 49B84CF8E5F400000000             mov     r8, 0F4E5F84Ch
0x2EC281: 4981C0746A234B                   add     r8, 4B236A74h
0x0047CE: 4D8B00                           mov     r8, [r8]
0x2EC2E6: 4C0383A8000000                   add     r8, [rbx+0A8h]
0x0047D8: 418A00                           mov     al, [r8]
0x0047DB: 480FB6C0                         movzx   rax, al
0x0047DF: 48C1E028                         shl     rax, 28h
0x2EC34F: 480183A0000000                   add     [rbx+0A0h], rax
0x2EC3B5: 49BACAEA1E3501000000             mov     r10, 1351EEACAh
0x0047F4: 4152                             push    r10
0x0047F6: 680742701E                       push    1E704207h
0x0047FB: 68E676A40B                       push    0BA476E6h
0x004800: 687A7D7638                       push    38767D7Ah
0x2EC425: 4881442418F66FEA0A               add     qword ptr [rsp+18h], 0AEA6FF6h
0x00480E: 4D8B6128                         mov     r12, [r9+28h]
0x2EC492: 4D8BA424A0000000                 mov     r12, [r12+0A0h]
0x0048FE: 4D8B5928                         mov     r11, [r9+28h]
0x004902: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x2EC564: 4D8BBB90000000                   mov     r15, [r11+90h]
0x2EC5CF: 498B9BD8000000                   mov     rbx, [r11+0D8h]
0x0049E5: 4D8B5128                         mov     r10, [r9+28h]
0x2EC69A: 4D8BBA90000000                   mov     r15, [r10+90h]
0x0049F0: 418B7234                         mov     esi, [r10+34h]
0x2EC706: 4903B2F0000000                   add     rsi, [r10+0F0h]
0x0049FB: 408A2E                           mov     bpl, [rsi]
0x2EC76F: 48C7C2FF000000                   mov     rdx, 0FFh
0x004A05: 48C1E220                         shl     rdx, 20h
0x004A09: 48F7D2                           not     rdx
0x004A0C: 4921D7                           and     r15, rdx
0x004A0F: 480FB6D5                         movzx   rdx, bpl
0x004A13: 48C1E220                         shl     rdx, 20h
0x004A17: 4909D7                           or      r15, rdx
0x004AFE: 4D8B4128                         mov     r8, [r9+28h]
0x2EC847: 498B80F0000000                   mov     rax, [r8+0F0h]
0x004B09: 50                               push    rax
0x004B0A: 4889E5                           mov     rbp, rsp
0x2EC8B4: 498BB8F0000000                   mov     rdi, [r8+0F0h]
0x004C0A: 4D8B7128                         mov     r14, [r9+28h]
0x2EC982: 4D8BA680000000                   mov     r12, [r14+80h]
0x2EC9EC: 4D8BB6B0000000                   mov     r14, [r14+0B0h]
0x004C1C: 4D0FB6E4                         movzx   r12, r12b
0x004D05: 498B7928                         mov     rdi, [r9+28h]
0x2ECAC3: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x2ECB2E: 49BAA35E5EDB00000000             mov     r10, 0DB5E5EA3h
0x2ECB9A: 4981C21D04AB64                   add     r10, 64AB041Dh
0x004D21: 4D8B12                           mov     r10, [r10]
0x2ECC06: 4C0397D8000000                   add     r10, [rdi+0D8h]
0x004D2B: 458A32                           mov     r14b, [r10]
0x004D2E: 4D0FB6F6                         movzx   r14, r14b
0x004D32: 49C1E630                         shl     r14, 30h
0x2ECC73: 4C01B7E8000000                   add     [rdi+0E8h], r14
0x2ECCDB: 48BA7A43E8C600000000             mov     rdx, 0C6E8437Ah
0x004D47: 52                               push    rdx
0x004D48: 680F70F63A                       push    3AF6700Fh
0x004D4D: 689D7B4404                       push    4447B9Dh
0x004D52: 686B3ED437                       push    37D43E6Bh
0x004D57: 68D30A0439                       push    39040AD3h
0x2ECD4C: 488144242046172179               add     qword ptr [rsp+20h], 79211746h
0x004D65: 498B7128                         mov     rsi, [r9+28h]
0x2ECDB5: 4C8BA6E8000000                   mov     r12, [rsi+0E8h]
0x004E5B: 498B6928                         mov     rbp, [r9+28h]
0x004E5F: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x2ECE85: 4C8BA5C0000000                   mov     r12, [rbp+0C0h]
0x2ECEEC: 488BADD8000000                   mov     rbp, [rbp+0D8h]
0x004F63: 4D8B5128                         mov     r10, [r9+28h]
0x2ECFB5: 4D8BB2A0000000                   mov     r14, [r10+0A0h]
0x004F6E: 458B4234                         mov     r8d, [r10+34h]
0x2ED020: 4D0382D8000000                   add     r8, [r10+0D8h]
0x004F79: 418A38                           mov     dil, [r8]
0x2ED08A: 49C7C1FF000000                   mov     r9, 0FFh
0x004F83: 49C1E128                         shl     r9, 28h
0x004F87: 49F7D1                           not     r9
0x004F8A: 4D21CE                           and     r14, r9
0x004F8D: 4C0FB6CF                         movzx   r9, dil
0x004F91: 49C1E128                         shl     r9, 28h
0x004F95: 4D09CE                           or      r14, r9
0x2ED15B: 49BA246E532801000000             mov     r10, 128536E24h
0x005085: 4152                             push    r10
0x005087: 68A13D4E4B                       push    4B4E3DA1h
0x00508C: 68E872EA6A                       push    6AEA72E8h
0x005091: 6867549309                       push    9935467h
0x005096: 68C145A70A                       push    0AA745C1h
0x2ED1CC: 4881442420C44A3618               add     qword ptr [rsp+20h], 18364AC4h
0x0050A4: 4D8B4928                         mov     r9, [r9+28h]
0x2ED23A: 498BB1E8000000                   mov     rsi, [r9+0E8h]
0x0051A1: 498B7928                         mov     rdi, [r9+28h]
0x2ED30B: 488BB788000000                   mov     rsi, [rdi+88h]
0x2ED374: 488B9FA8000000                   mov     rbx, [rdi+0A8h]
0x0051B3: 480FB6F6                         movzx   rsi, sil
0x00528C: 4D8B5128                         mov     r10, [r9+28h]
0x2ED43D: 498B82A8000000                   mov     rax, [r10+0A8h]
0x2ED4A2: 48C7C58D5DDEE4                   mov     rbp, 0FFFFFFFFE4DE5D8Dh
0x2ED510: 4881C5FE71061C                   add     rbp, 1C0671FEh
0x0052A5: 55                               push    rbp
0x2ED577: 4D8BA290000000                   mov     r12, [r10+90h]
0x0052AD: 48F72424                         mul     qword ptr [rsp]
0x0052B1: 4989C7                           mov     r15, rax
0x0053A9: 498B7128                         mov     rsi, [r9+28h]
0x2ED64A: 488BBED8000000                   mov     rdi, [rsi+0D8h]
0x2ED6B0: 482BBEF0000000                   sub     rdi, [rsi+0F0h]
0x0054AC: 498B4928                         mov     rcx, [r9+28h]
0x2ED784: 488B81B0000000                   mov     rax, [rcx+0B0h]
0x0054B7: 50                               push    rax
0x0054B8: 4989E7                           mov     r15, rsp
0x2ED7ED: 4C8BA1B0000000                   mov     r12, [rcx+0B0h]
0x0055A0: 498B6928                         mov     rbp, [r9+28h]
0x2ED8C0: 488B9DE0000000                   mov     rbx, [rbp+0E0h]
0x2ED925: 4C8BA5D8000000                   mov     r12, [rbp+0D8h]
0x0055B2: 480FB6DB                         movzx   rbx, bl
0x0056A8: 498B6928                         mov     rbp, [r9+28h]
0x2ED9F8: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x2EDA5F: 49BC7B013B0901000000             mov     r12, 1093B017Bh
0x2EDAC8: 4981C44571CE36                   add     r12, 36CE7145h
0x2EDB2D: 4D8BA424F0060000                 mov     r12, [r12+6F0h]
0x2EDB99: 4C03A590000000                   add     r12, [rbp+90h]
0x0056D3: 458A3424                         mov     r14b, [r12]
0x0056D7: 4D0FB6F6                         movzx   r14, r14b
0x0056DB: 49C1E608                         shl     r14, 8
0x2EDBFE: 4C29B5D8000000                   sub     [rbp+0D8h], r14
0x0056E6: 498B5928                         mov     rbx, [r9+28h]
0x2EDC6B: 488BABD8000000                   mov     rbp, [rbx+0D8h]
0x2EDCD4: 49BED0216FDE00000000             mov     r14, 0DE6F21D0h
0x2EDD3C: 4981C6F0489A61                   add     r14, 619A48F0h
0x0057F6: 4D8B4928                         mov     r9, [r9+28h]
0x0057FA: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x2EDE07: 4D8BA1E8000000                   mov     r12, [r9+0E8h]
0x2EDE70: 498BB9A0000000                   mov     rdi, [r9+0A0h]
0x0058ED: 498B7928                         mov     rdi, [r9+28h]
0x2EDF3D: 488B9FB0000000                   mov     rbx, [rdi+0B0h]
0x0058F8: 8B5734                           mov     edx, [rdi+34h]
0x2EDFA4: 480397D8000000                   add     rdx, [rdi+0D8h]
0x005902: 408A2A                           mov     bpl, [rdx]
0x005905: 4088EB                           mov     bl, bpl
0x0059ED: 498B6928                         mov     rbp, [r9+28h]
0x2EE076: 4C8B9D90000000                   mov     r11, [rbp+90h]
0x0059F8: 4153                             push    r11
0x0059FA: 4889E7                           mov     rdi, rsp
0x2EE0DF: 488BB590000000                   mov     rsi, [rbp+90h]
0x005AE2: 4D8B5928                         mov     r11, [r9+28h]
0x2EE1AD: 498BBBB0000000                   mov     rdi, [r11+0B0h]
0x2EE215: 4D8BABA8000000                   mov     r13, [r11+0A8h]
0x005AF4: 57                               push    rdi
0x005AF5: 683D15B505                       push    5B5153Dh
0x005AFA: 68004EBA50                       push    50BA4E00h
0x005AFF: 68B17B894F                       push    4F897BB1h
0x005B04: 684552CC6F                       push    6FCC5245h
0x005BF6: 4D8B5128                         mov     r10, [r9+28h]
0x2EE2E8: 4D8BA2C8000000                   mov     r12, [r10+0C8h]
0x2EE352: 498B9AE0000000                   mov     rbx, [r10+0E0h]
0x005C08: 4D0FB6E4                         movzx   r12, r12b
0x005CE6: 498B7128                         mov     rsi, [r9+28h]
0x2EE425: 0FAE96D8000000                   ldmxcsr dword ptr [rsi+0D8h]
0x2EE48C: 49BADD17DDD400000000             mov     r10, 0D4DD17DDh
0x2EE4FA: 4981C2E35A2C6B                   add     r10, 6B2C5AE3h
0x2EE560: 4D8B92D8050000                   mov     r10, [r10+5D8h]
0x2EE5CB: 4C0396D8000000                   add     r10, [rsi+0D8h]
0x005D10: 458A32                           mov     r14b, [r10]
0x005D13: 4D0FB6F6                         movzx   r14, r14b
0x005D17: 49C1E610                         shl     r14, 10h
0x2EE632: 4C29B690000000                   sub     [rsi+90h], r14
0x005D22: 498B7128                         mov     rsi, [r9+28h]
0x2EE69B: 488BB690000000                   mov     rsi, [rsi+90h]
0x2EE707: 49BFBB00252101000000             mov     r15, 1212500BBh
0x2EE775: 4981C7056AE41E                   add     r15, 1EE46A05h
0x005E20: 4D8B7128                         mov     r14, [r9+28h]
0x005E24: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x2EE83F: 498B9EE0000000                   mov     rbx, [r14+0E0h]
0x2EE8A5: 4D8BA6A8000000                   mov     r12, [r14+0A8h]
0x005F15: 4D8B4128                         mov     r8, [r9+28h]
0x2EE971: 4D8BB8D8000000                   mov     r15, [r8+0D8h]
0x005F20: 418B7834                         mov     edi, [r8+34h]
0x2EE9DA: 4903B890000000                   add     rdi, [r8+90h]
0x005F2B: 8A17                             mov     dl, [rdi]
0x2EEA3F: 49C7C5FF000000                   mov     r13, 0FFh
0x005F34: 49C1E508                         shl     r13, 8
0x005F38: 49F7D5                           not     r13
0x005F3B: 4D21EF                           and     r15, r13
0x005F3E: 4C0FB6EA                         movzx   r13, dl
0x005F42: 49C1E508                         shl     r13, 8
0x005F46: 4D09EF                           or      r15, r13
0x006038: 498B4928                         mov     rcx, [r9+28h]
0x2EEB0B: 4C8BA9F0000000                   mov     r13, [rcx+0F0h]
0x006043: 4155                             push    r13
0x006045: 4989E4                           mov     r12, rsp
0x2EEB79: 488BB9F0000000                   mov     rdi, [rcx+0F0h]
0x00613C: 498B6928                         mov     rbp, [r9+28h]
0x2EEC48: 488BB5D8000000                   mov     rsi, [rbp+0D8h]
0x2EECB5: 4C8BA5B0000000                   mov     r12, [rbp+0B0h]
0x00614E: 56                               push    rsi
0x00614F: 682A67DB54                       push    54DB672Ah
0x006154: 689156C006                       push    6C05691h
0x006159: 682C553310                       push    1033552Ch
0x00615E: 683F3D7561                       push    61753D3Fh
0x006249: 498B5928                         mov     rbx, [r9+28h]
0x00624D: 4C8B6B78                         mov     r13, [rbx+78h]
0x2EED82: 488BBBD8000000                   mov     rdi, [rbx+0D8h]
0x006258: 4D0FB6ED                         movzx   r13, r13b
0x006332: 4D8B7928                         mov     r15, [r9+28h]
0x2EEE50: 410FAE97E0000000                 ldmxcsr dword ptr [r15+0E0h]
0x2EEEB8: 48B9D547210E01000000             mov     rcx, 10E2147D5h
0x2EEF25: 4881C1EB2AE831                   add     rcx, 31E82AEBh
0x2EEF8F: 488B89F8010000                   mov     rcx, [rcx+1F8h]
0x2EEFFB: 49038FE0000000                   add     rcx, [r15+0E0h]
0x00635D: 448A21                           mov     r12b, [rcx]
0x006360: 4D0FB6E4                         movzx   r12, r12b
0x006364: 49C1E418                         shl     r12, 18h
0x2EF062: 4D29A7B0000000                   sub     [r15+0B0h], r12
0x2EF0CB: 49B8EB63870401000000             mov     r8, 1048763EBh
0x006379: 4150                             push    r8
0x00637B: 680F629C34                       push    349C620Fh
0x006380: 68896E715F                       push    5F716E89h
0x006385: 6860568D63                       push    638D5660h
0x00638A: 68D206C01E                       push    1EC006D2h
0x2EF137: 4881442420D506823B               add     qword ptr [rsp+20h], 3B8206D5h
0x006398: 498B6928                         mov     rbp, [r9+28h]
0x2EF1A0: 488B9DB0000000                   mov     rbx, [rbp+0B0h]
0x006487: 498B5928                         mov     rbx, [r9+28h]
0x00648B: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x2EF273: 488BBBA0000000                   mov     rdi, [rbx+0A0h]
0x2EF2E1: 488BAB90000000                   mov     rbp, [rbx+90h]
0x006573: 498B4928                         mov     rcx, [r9+28h]
0x2EF3B1: 4C8BA1A0000000                   mov     r12, [rcx+0A0h]
0x00657E: 8B4134                           mov     eax, [rcx+34h]
0x2EF41B: 480381B0000000                   add     rax, [rcx+0B0h]
0x006588: 448A30                           mov     r14b, [rax]
0x2EF485: 48C7C1FF000000                   mov     rcx, 0FFh
0x006592: 48C1E110                         shl     rcx, 10h
0x006596: 48F7D1                           not     rcx
0x006599: 4921CC                           and     r12, rcx
0x00659C: 490FB6CE                         movzx   rcx, r14b
0x0065A0: 48C1E110                         shl     rcx, 10h
0x0065A4: 4909CC                           or      r12, rcx
0x006697: 498B7128                         mov     rsi, [r9+28h]
0x2EF555: 4C8BA6D8000000                   mov     r12, [rsi+0D8h]
0x0066A2: 4154                             push    r12
0x0066A4: 4889E5                           mov     rbp, rsp
0x2EF5BC: 4C8BAED8000000                   mov     r13, [rsi+0D8h]
0x006795: 4D8B6128                         mov     r12, [r9+28h]
0x2EF68E: 498B8C24A0000000                 mov     rcx, [r12+0A0h]
0x2EF6F6: 498BB424E0000000                 mov     rsi, [r12+0E0h]
0x0067A9: 51                               push    rcx
0x0067AA: 68BF7ACD6E                       push    6ECD7ABFh
0x0067AF: 68C10EB73F                       push    3FB70EC1h
0x0067B4: 68D22A3D1E                       push    1E3D2AD2h
0x0068A6: 4D8B5928                         mov     r11, [r9+28h]
0x2EF7C8: 498B9BC8000000                   mov     rbx, [r11+0C8h]
0x2EF831: 4D8BABA8000000                   mov     r13, [r11+0A8h]
0x0068B8: 480FB6DB                         movzx   rbx, bl
0x00699C: 498B6928                         mov     rbp, [r9+28h]
0x2EF902: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x2EF96A: 49B84C21C73301000000             mov     r8, 133C7214Ch
0x2EF9D6: 4981C07451420C                   add     r8, 0C425174h
0x2EFA41: 4D8B8088040000                   mov     r8, [r8+488h]
0x2EFAAD: 4C038590000000                   add     r8, [rbp+90h]
0x0069C6: 458A20                           mov     r12b, [r8]
0x0069C9: 4D0FB6E4                         movzx   r12, r12b
0x0069CD: 49C1E420                         shl     r12, 20h
0x2EFB14: 4C29A5E0000000                   sub     [rbp+0E0h], r12
0x0069D8: 4D8B7128                         mov     r14, [r9+28h]
0x2EFB81: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x2EFBEE: 48BB573BD3D900000000             mov     rbx, 0D9D33B57h
0x2EFC5E: 4881C3692F3666                   add     rbx, 66362F69h
0x006AE3: 498B5928                         mov     rbx, [r9+28h]
0x006AE7: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x006AEB: 4C8B6378                         mov     r12, [rbx+78h]
0x2EFD32: 4C8BB3B0000000                   mov     r14, [rbx+0B0h]
0x006BCD: 498B7128                         mov     rsi, [r9+28h]
0x2EFE08: 4C8BAEE8000000                   mov     r13, [rsi+0E8h]
0x006BD8: 448B4634                         mov     r8d, [rsi+34h]
0x2EFE71: 4C0386D8000000                   add     r8, [rsi+0D8h]
0x006BE3: 458A20                           mov     r12b, [r8]
0x2EFED7: 49C7C0FF000000                   mov     r8, 0FFh
0x006BED: 49C1E018                         shl     r8, 18h
0x006BF1: 49F7D0                           not     r8
0x006BF4: 4D21C5                           and     r13, r8
0x006BF7: 4D0FB6C4                         movzx   r8, r12b
0x006BFB: 49C1E018                         shl     r8, 18h
0x006BFF: 4D09C5                           or      r13, r8
0x006CE8: 498B5928                         mov     rbx, [r9+28h]
0x2EFFA0: 488B83E0000000                   mov     rax, [rbx+0E0h]
0x006CF3: 50                               push    rax
0x006CF4: 4889E6                           mov     rsi, rsp
0x2F0006: 4C8BBBE0000000                   mov     r15, [rbx+0E0h]
0x006DDE: 4D8B4928                         mov     r9, [r9+28h]
0x2F00DD: 498B81A8000000                   mov     rax, [r9+0A8h]
0x2F0147: 4D8BB9F0000000                   mov     r15, [r9+0F0h]
0x006DF0: 50                               push    rax
0x006DF1: 68C0418B56                       push    568B41C0h
0x006DF6: 687C552115                       push    1521557Ch
0x006DFB: 6875039A48                       push    489A0375h
0x006EED: 4D8B4928                         mov     r9, [r9+28h]
0x2F0215: 498B9988000000                   mov     rbx, [r9+88h]
0x2F027C: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x006EFF: 480FB6DB                         movzx   rbx, bl
0x006FE0: 498B6928                         mov     rbp, [r9+28h]
0x2F034E: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x2F03BA: 48B9CF4B91F400000000             mov     rcx, 0F4914BCFh
0x2F0423: 4881C1F126784B                   add     rcx, 4B7826F1h
0x006FFC: 488B09                           mov     rcx, [rcx]
0x2F048F: 48038D90000000                   add     rcx, [rbp+90h]
0x007006: 448A39                           mov     r15b, [rcx]
0x007009: 4D0FB6FF                         movzx   r15, r15b
0x00700D: 49C1E730                         shl     r15, 30h
0x2F04F8: 4C29BDB0000000                   sub     [rbp+0B0h], r15
0x007018: 4D8B7128                         mov     r14, [r9+28h]
0x2F0566: 4D8BAEB0000000                   mov     r13, [r14+0B0h]
0x2F05CB: 48BE06232D1401000000             mov     rsi, 1142D2306h
0x2F0635: 4881C6BA47DC2B                   add     rsi, 2BDC47BAh
0x007113: 498B7128                         mov     rsi, [r9+28h]
0x007117: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x2F0701: 4C8BB680000000                   mov     r14, [rsi+80h]
0x2F076A: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x00720D: 4D8B5128                         mov     r10, [r9+28h]
0x2F0834: 498BAAF0000000                   mov     rbp, [r10+0F0h]
0x007218: 458B4234                         mov     r8d, [r10+34h]
0x2F089C: 4D0382E8000000                   add     r8, [r10+0E8h]
0x007223: 418A30                           mov     sil, [r8]
0x2F0904: 49C7C6FF000000                   mov     r14, 0FFh
0x00722D: 49C1E628                         shl     r14, 28h
0x007231: 49F7D6                           not     r14
0x007234: 4C21F5                           and     rbp, r14
0x007237: 4C0FB6F6                         movzx   r14, sil
0x00723B: 49C1E628                         shl     r14, 28h
0x00723F: 4C09F5                           or      rbp, r14
0x00732C: 498B5128                         mov     rdx, [r9+28h]
0x2F09DE: 4C8B9AA0000000                   mov     r11, [rdx+0A0h]
0x007337: 4153                             push    r11
0x007339: 4889E6                           mov     rsi, rsp
0x2F0A46: 4C8BAAA0000000                   mov     r13, [rdx+0A0h]
0x00743F: 4D8B7128                         mov     r14, [r9+28h]
0x2F0B13: 4D8BBEB0000000                   mov     r15, [r14+0B0h]
0x2F0B7B: 498BB6E0000000                   mov     rsi, [r14+0E0h]
0x007451: 4D0FB6FF                         movzx   r15, r15b
0x007534: 4D8B5928                         mov     r11, [r9+28h]
0x2F0C48: 410FAE93F0000000                 ldmxcsr dword ptr [r11+0F0h]
0x2F0CB2: 48BE9F6DCD0301000000             mov     rsi, 103CD6D9Fh
0x2F0D23: 4881C621053C3C                   add     rsi, 3C3C0521h
0x007551: 488B36                           mov     rsi, [rsi]
0x2F0D88: 4903B3F0000000                   add     rsi, [r11+0F0h]
0x00755B: 8A16                             mov     dl, [rsi]
0x00755D: 480FB6D2                         movzx   rdx, dl
0x007561: 48C1E238                         shl     rdx, 38h
0x2F0DF0: 492993A8000000                   sub     [r11+0A8h], rdx
0x2F0E55: 48B90F26DFD300000000             mov     rcx, 0D3DF260Fh
0x007576: 51                               push    rcx
0x007577: 68234DFB48                       push    48FB4D23h
0x00757C: 685B4AF133                       push    33F14A5Bh
0x007581: 68BA08AE05                       push    5AE08BAh
0x007586: 68776B2A64                       push    642A6B77h
0x2F0EC5: 4881442420B1442A6C               add     qword ptr [rsp+20h], 6C2A44B1h
0x007594: 498B7928                         mov     rdi, [r9+28h]
0x2F0F35: 4C8BBFA8000000                   mov     r15, [rdi+0A8h]
0x00767E: 4D8B5928                         mov     r11, [r9+28h]
0x007682: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x2F100C: 498B9BA8000000                   mov     rbx, [r11+0A8h]
0x2F1076: 4D8BB3F0000000                   mov     r14, [r11+0F0h]
0x00776B: 498B4928                         mov     rcx, [r9+28h]
0x2F1142: 4C8BB9E8000000                   mov     r15, [rcx+0E8h]
0x007776: 8B4134                           mov     eax, [rcx+34h]
0x2F11AE: 48038190000000                   add     rax, [rcx+90h]
0x007780: 8A08                             mov     cl, [rax]
0x2F1218: 49C7C2FF000000                   mov     r10, 0FFh
0x007789: 49C1E230                         shl     r10, 30h
0x00778D: 49F7D2                           not     r10
0x007790: 4D21D7                           and     r15, r10
0x007793: 4C0FB6D1                         movzx   r10, cl
0x007797: 49C1E230                         shl     r10, 30h
0x00779B: 4D09D7                           or      r15, r10
0x2F12EE: 48BD97A92EE300000000             mov     rbp, 0E32EA997h
0x00788D: 55                               push    rbp
0x00788E: 682012130D                       push    0D131220h
0x007893: 68A52E2038                       push    38202EA5h
0x007898: 68CD205728                       push    285720CDh
0x00789D: 6899032341                       push    41230399h
0x2F135C: 4881442420510F5B5D               add     [rsp-8+arg_20], 5D5B0F51h
0x0078AB: 498B5928                         mov     rbx, [r9+28h]
0x2F13C7: 4C8BA3F0000000                   mov     r12, [rbx+0F0h]
0x0079A2: 498B7928                         mov     rdi, [r9+28h]
0x2F1498: 488BAF88000000                   mov     rbp, [rdi+88h]
0x2F1506: 4C8BB7D8000000                   mov     r14, [rdi+0D8h]
0x0079B4: 480FB6ED                         movzx   rbp, bpl
0x007A9C: 498B7128                         mov     rsi, [r9+28h]
0x2F15D6: 488B86A0000000                   mov     rax, [rsi+0A0h]
0x2F163B: 49C7C34275AAA0                   mov     r11, 0FFFFFFFFA0AA7542h
0x2F16A2: 4981C34E544B60                   add     r11, 604B544Eh
0x007AB5: 4153                             push    r11
0x2F1710: 4C8BB6E8000000                   mov     r14, [rsi+0E8h]
0x007ABE: 48F72424                         mul     qword ptr [rsp]
0x007AC2: 4889C5                           mov     rbp, rax
0x007BA4: 498B5128                         mov     rdx, [r9+28h]
0x2F17E3: 488BB2E8000000                   mov     rsi, [rdx+0E8h]
0x2F184A: 482BB2A0000000                   sub     rsi, [rdx+0A0h]
0x007C8F: 4D8B7928                         mov     r15, [r9+28h]
0x2F1914: 4D8BA7A8000000                   mov     r12, [r15+0A8h]
0x007C9A: 4154                             push    r12
0x007C9C: 4889E5                           mov     rbp, rsp
0x2F1980: 498BB7A8000000                   mov     rsi, [r15+0A8h]
0x007D8C: 4D8B5128                         mov     r10, [r9+28h]
0x2F1A4B: 4D8BBA88000000                   mov     r15, [r10+88h]
0x2F1AB8: 498B9AA8000000                   mov     rbx, [r10+0A8h]
0x007D9E: 4D0FB6FF                         movzx   r15, r15b
0x007E88: 4D8B7928                         mov     r15, [r9+28h]
0x2F1B8F: 410FAE97F0000000                 ldmxcsr dword ptr [r15+0F0h]
0x2F1BFA: 48BD9138D72B01000000             mov     rbp, 12BD73891h
0x2F1C6A: 4881C52F2A3214                   add     rbp, 14322A2Fh
0x2F1CD4: 488BADB0020000                   mov     rbp, [rbp+2B0h]
0x2F1D40: 4903AFF0000000                   add     rbp, [r15+0F0h]
0x007EB3: 408A7500                         mov     sil, [rbp+0]
0x007EB7: 480FB6F6                         movzx   rsi, sil
0x007EBB: 48C1E608                         shl     rsi, 8
0x2F1DAD: 4901B790000000                   add     [r15+90h], rsi
0x007EC6: 4D8B5928                         mov     r11, [r9+28h]
0x2F1E17: 498BBB90000000                   mov     rdi, [r11+90h]
0x2F1E7C: 49BD6B1ED31801000000             mov     r13, 118D31E6Bh
0x2F1EED: 4981C5553C3627                   add     r13, 27363C55h
0x007FD2: 4D8B6128                         mov     r12, [r9+28h]
0x2F1FC1: 410FAE542434                     ldmxcsr dword ptr [r12+34h]
0x2F2025: 498BB42480000000                 mov     rsi, [r12+80h]
0x2F208D: 4D8BBC24B0000000                 mov     r15, [r12+0B0h]
0x0080E4: 498B7128                         mov     rsi, [r9+28h]
0x2F2157: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x0080EF: 8B6E34                           mov     ebp, [rsi+34h]
0x2F21C4: 4803AEA8000000                   add     rbp, [rsi+0A8h]
0x0080F9: 448A5500                         mov     r10b, [rbp+0]
0x0080FD: 4588D5                           mov     r13b, r10b
0x0081F3: 498B4128                         mov     rax, [r9+28h]
0x2F2298: 488B90E0000000                   mov     rdx, [rax+0E0h]
0x0081FE: 52                               push    rdx
0x0081FF: 4889E3                           mov     rbx, rsp
0x2F2305: 4C8BB0E0000000                   mov     r14, [rax+0E0h]
0x0082FF: 498B5128                         mov     rdx, [r9+28h]
0x2F23D8: 4C8BBAC8000000                   mov     r15, [rdx+0C8h]
0x2F2444: 488BBAE8000000                   mov     rdi, [rdx+0E8h]
0x008311: 4D0FB6FF                         movzx   r15, r15b
0x008405: 498B4128                         mov     rax, [r9+28h]
0x2F251C: 0FAE90F0000000                   ldmxcsr dword ptr [rax+0F0h]
0x2F2587: 48BFA113F6FB00000000             mov     rdi, 0FBF613A1h
0x2F25EF: 4881C71F4F1344                   add     rdi, 44134F1Fh
0x2F265B: 488BBF30050000                   mov     rdi, [rdi+530h]
0x2F26C0: 4803B8F0000000                   add     rdi, [rax+0F0h]
0x00842F: 448A27                           mov     r12b, [rdi]
0x008432: 4D0FB6E4                         movzx   r12, r12b
0x008436: 49C1E410                         shl     r12, 10h
0x2F272A: 4C01A0B0000000                   add     [rax+0B0h], r12
0x2F2794: 49BAF92558E200000000             mov     r10, 0E25825F9h
0x00844B: 4152                             push    r10
0x00844D: 68ED6A4071                       push    71406AEDh
0x008452: 6863420F18                       push    180F4263h
0x008457: 68811BC024                       push    24C01B81h
0x2F2805: 4881442418C734B15D               add     qword ptr [rsp+18h], 5DB134C7h
0x008465: 498B5128                         mov     rdx, [r9+28h]
0x2F2875: 488B9AB0000000                   mov     rbx, [rdx+0B0h]
0x00855A: 498B5128                         mov     rdx, [r9+28h]
0x00855E: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x2F294A: 488BB2B0000000                   mov     rsi, [rdx+0B0h]
0x2F29B3: 488B9A90000000                   mov     rbx, [rdx+90h]
0x008646: 498B5128                         mov     rdx, [r9+28h]
0x2F2A89: 488B9A90000000                   mov     rbx, [rdx+90h]
0x008651: 8B4A34                           mov     ecx, [rdx+34h]
0x2F2AF1: 48038AA8000000                   add     rcx, [rdx+0A8h]
0x00865B: 448A11                           mov     r10b, [rcx]
0x2F2B5D: 48C7C6FF000000                   mov     rsi, 0FFh
0x008665: 48C1E608                         shl     rsi, 8
0x008669: 48F7D6                           not     rsi
0x00866C: 4821F3                           and     rbx, rsi
0x00866F: 490FB6F2                         movzx   rsi, r10b
0x008673: 48C1E608                         shl     rsi, 8
0x008677: 4809F3                           or      rbx, rsi
0x00875F: 4D8B5928                         mov     r11, [r9+28h]
0x2F2C2D: 4D8BAB90000000                   mov     r13, [r11+90h]
0x00876A: 4155                             push    r13
0x00876C: 4889E6                           mov     rsi, rsp
0x2F2C97: 498B9B90000000                   mov     rbx, [r11+90h]
0x008855: 4D8B5928                         mov     r11, [r9+28h]
0x2F2D68: 498BABF0000000                   mov     rbp, [r11+0F0h]
0x2F2DCD: 4D8BA390000000                   mov     r12, [r11+90h]
0x008867: 480FB6ED                         movzx   rbp, bpl
0x008956: 4D8B5128                         mov     r10, [r9+28h]
0x2F2E9C: 410FAE92A0000000                 ldmxcsr dword ptr [r10+0A0h]
0x2F2F04: 48BBB661C03201000000             mov     rbx, 132C061B6h
0x2F2F75: 4881C30A01490D                   add     rbx, 0D49010Ah
0x2F2FDC: 488B9BD0070000                   mov     rbx, [rbx+7D0h]
0x2F3044: 49039AA0000000                   add     rbx, [r10+0A0h]
0x008981: 448A33                           mov     r14b, [rbx]
0x008984: 4D0FB6F6                         movzx   r14, r14b
0x008988: 49C1E618                         shl     r14, 18h
0x2F30B2: 4D01B2D8000000                   add     [r10+0D8h], r14
0x2F311B: 49BBAD4BE62301000000             mov     r11, 123E64BADh
0x00899D: 4153                             push    r11
0x00899F: 6807374E68                       push    684E3707h
0x0089A4: 681236B231                       push    31B23612h
0x0089A9: 68FD32C629                       push    29C632FDh
0x2F3186: 4881442418130F231C               add     [rsp-8+arg_18], 1C230F13h
0x0089B7: 4D8B7128                         mov     r14, [r9+28h]
0x2F31F5: 498BBED8000000                   mov     rdi, [r14+0D8h]
0x008AAE: 4D8B6928                         mov     r13, [r9+28h]
0x008AB2: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x2F32C3: 498BBDA0000000                   mov     rdi, [r13+0A0h]
0x2F3328: 4D8BBDB0000000                   mov     r15, [r13+0B0h]
0x008B9D: 4D8B5928                         mov     r11, [r9+28h]
0x2F33FB: 4D8BABF0000000                   mov     r13, [r11+0F0h]
0x008BA8: 418B6B34                         mov     ebp, [r11+34h]
0x2F3469: 4903ABB0000000                   add     rbp, [r11+0B0h]
0x008BB3: 8A4500                           mov     al, [rbp+0]
0x2F34D4: 49C7C6FF000000                   mov     r14, 0FFh
0x008BBD: 49C1E610                         shl     r14, 10h
0x008BC1: 49F7D6                           not     r14
0x008BC4: 4D21F5                           and     r13, r14
0x008BC7: 4C0FB6F0                         movzx   r14, al
0x008BCB: 49C1E610                         shl     r14, 10h
0x008BCF: 4D09F5                           or      r13, r14
0x008CBF: 498B4928                         mov     rcx, [r9+28h]
0x2F35A6: 488B99E0000000                   mov     rbx, [rcx+0E0h]
0x008CCA: 53                               push    rbx
0x008CCB: 4989E4                           mov     r12, rsp
0x2F360C: 488BB1E0000000                   mov     rsi, [rcx+0E0h]
0x008DC6: 498B5928                         mov     rbx, [r9+28h]
0x2F36DF: 4C8BA3F0000000                   mov     r12, [rbx+0F0h]
0x2F374B: 488B9BA8000000                   mov     rbx, [rbx+0A8h]
0x008DD8: 4D0FB6E4                         movzx   r12, r12b
0x008EBB: 498B7928                         mov     rdi, [r9+28h]
0x2F3820: 0FAE97D8000000                   ldmxcsr dword ptr [rdi+0D8h]
0x2F388D: 49BE7F2BE8E700000000             mov     r14, 0E7E82B7Fh
0x2F38FD: 4981C641372158                   add     r14, 58213741h
0x2F396B: 4D8BB658030000                   mov     r14, [r14+358h]
0x2F39D7: 4C03B7D8000000                   add     r14, [rdi+0D8h]
0x008EE5: 458A36                           mov     r14b, [r14]
0x008EE8: 4D0FB6F6                         movzx   r14, r14b
0x008EEC: 49C1E620                         shl     r14, 20h
0x2F3A3D: 4C01B790000000                   add     [rdi+90h], r14
0x008EF7: 4D8B6928                         mov     r13, [r9+28h]
0x2F3AA6: 498BB590000000                   mov     rsi, [r13+90h]
0x2F3B12: 49BD7828D82201000000             mov     r13, 122D82878h
0x2F3B7F: 4981C54832311D                   add     r13, 1D313248h
0x008FEF: 498B5928                         mov     rbx, [r9+28h]
0x008FF3: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x2F3C56: 488BBB80000000                   mov     rdi, [rbx+80h]
0x2F3CBC: 488BABA8000000                   mov     rbp, [rbx+0A8h]
0x0090EA: 498B4928                         mov     rcx, [r9+28h]
0x2F3D8F: 4C8BA9A0000000                   mov     r13, [rcx+0A0h]
0x0090F5: 8B4134                           mov     eax, [rcx+34h]
0x2F3DFD: 480381B0000000                   add     rax, [rcx+0B0h]
0x0090FF: 448A10                           mov     r10b, [rax]
0x2F3E62: 48C7C6FF000000                   mov     rsi, 0FFh
0x009109: 48C1E618                         shl     rsi, 18h
0x00910D: 48F7D6                           not     rsi
0x009110: 4921F5                           and     r13, rsi
0x009113: 490FB6F2                         movzx   rsi, r10b
0x009117: 48C1E618                         shl     rsi, 18h
0x00911B: 4909F5                           or      r13, rsi
0x009201: 4D8B4128                         mov     r8, [r9+28h]
0x2F3F2B: 498BA8E0000000                   mov     rbp, [r8+0E0h]
0x00920C: 55                               push    rbp
0x00920D: 4889E7                           mov     rdi, rsp
0x2F3F94: 498B98E0000000                   mov     rbx, [r8+0E0h]
0x0092F2: 498B6928                         mov     rbp, [r9+28h]
0x2F4066: 4C8BBDA0000000                   mov     r15, [rbp+0A0h]
0x2F40D0: 488BB590000000                   mov     rsi, [rbp+90h]
0x009304: 4D0FB6FF                         movzx   r15, r15b
0x0093E4: 4D8B6928                         mov     r13, [r9+28h]
0x2F41A1: 410FAE95F0000000                 ldmxcsr dword ptr [r13+0F0h]
0x2F420A: 48B8BF618AE800000000             mov     rax, 0E88A61BFh
0x2F4277: 480501017F57                     add     rax, 577F0101h
0x009400: 488B00                           mov     rax, [rax]
0x2F42DE: 490385F0000000                   add     rax, [r13+0F0h]
0x00940A: 448A30                           mov     r14b, [rax]
0x00940D: 4D0FB6F6                         movzx   r14, r14b
0x009411: 49C1E628                         shl     r14, 28h
0x2F4348: 4D01B5A8000000                   add     [r13+0A8h], r14
0x00941C: 498B5928                         mov     rbx, [r9+28h]
0x2F43B0: 4C8BABA8000000                   mov     r13, [rbx+0A8h]
0x2F4415: 48BE10FF1A1601000000             mov     rsi, 1161AFF10h
0x2F447F: 4881C6B05BEE29                   add     rsi, 29EE5BB0h
0x00951C: 4D8B7128                         mov     r14, [r9+28h]
0x009520: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x2F4553: 498BB6E8000000                   mov     rsi, [r14+0E8h]
0x2F45BE: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x00961E: 4D8B7128                         mov     r14, [r9+28h]
0x2F4688: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x009629: 418B4E34                         mov     ecx, [r14+34h]
0x2F46F4: 49038EA8000000                   add     rcx, [r14+0A8h]
0x009634: 8A11                             mov     dl, [rcx]
0x2F475E: 49C7C5FF000000                   mov     r13, 0FFh
0x00963D: 49C1E520                         shl     r13, 20h
0x009641: 49F7D5                           not     r13
0x009644: 4C21ED                           and     rbp, r13
0x009647: 4C0FB6EA                         movzx   r13, dl
0x00964B: 49C1E520                         shl     r13, 20h
0x00964F: 4C09ED                           or      rbp, r13
0x009739: 498B5128                         mov     rdx, [r9+28h]
0x2F4828: 488BBAA0000000                   mov     rdi, [rdx+0A0h]
0x009744: 57                               push    rdi
0x009745: 4989E7                           mov     r15, rsp
0x2F4892: 488BBAA0000000                   mov     rdi, [rdx+0A0h]
0x00983C: 498B4928                         mov     rcx, [r9+28h]
0x2F4969: 488B91F0000000                   mov     rdx, [rcx+0F0h]
0x2F49D4: 4C8BA1B0000000                   mov     r12, [rcx+0B0h]
0x00984E: 52                               push    rdx
0x00984F: 683C335A6E                       push    6E5A333Ch
0x009854: 68F524F30E                       push    0EF324F5h
0x009859: 687B168B22                       push    228B167Bh
0x00985E: 68367F485E                       push    5E487F36h
0x009948: 498B7128                         mov     rsi, [r9+28h]
0x2F4AA3: 488BAEC8000000                   mov     rbp, [rsi+0C8h]
0x2F4B0C: 4C8BBED8000000                   mov     r15, [rsi+0D8h]
0x00995A: 480FB6ED                         movzx   rbp, bpl
0x009A39: 4D8B7128                         mov     r14, [r9+28h]
0x2F4BDC: 410FAE96A0000000                 ldmxcsr dword ptr [r14+0A0h]
0x2F4C4B: 48BA340C1B0B01000000             mov     rdx, 10B1B0C34h
0x2F4CBC: 4881C28C56EE34                   add     rdx, 34EE568Ch
0x009A56: 488B12                           mov     rdx, [rdx]
0x2F4D28: 490396A0000000                   add     rdx, [r14+0A0h]
0x009A60: 8A12                             mov     dl, [rdx]
0x009A62: 480FB6D2                         movzx   rdx, dl
0x009A66: 48C1E238                         shl     rdx, 38h
0x2F4D8E: 490196F0000000                   add     [r14+0F0h], rdx
0x009A71: 4D8B6128                         mov     r12, [r9+28h]
0x2F4DFB: 4D8BBC24F0000000                 mov     r15, [r12+0F0h]
0x2F4E65: 49BE90F088F700000000             mov     r14, 0F788F090h
0x2F4ECD: 4981C6306A8048                   add     r14, 48806A30h
0x009B6D: 498B5928                         mov     rbx, [r9+28h]
0x009B71: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x009B75: 488B6B78                         mov     rbp, [rbx+78h]
0x2F4F9F: 488BB3F0000000                   mov     rsi, [rbx+0F0h]
0x009C51: 4D8B4928                         mov     r9, [r9+28h]
0x2F506D: 498BB1A8000000                   mov     rsi, [r9+0A8h]
0x009C5C: 458B6934                         mov     r13d, [r9+34h]
0x2F50D7: 4D03A9A0000000                   add     r13, [r9+0A0h]
0x009C67: 458A6D00                         mov     r13b, [r13+0]
0x2F5144: 49C7C6FF000000                   mov     r14, 0FFh
0x009C72: 49C1E630                         shl     r14, 30h
0x009C76: 49F7D6                           not     r14
0x009C79: 4C21F6                           and     rsi, r14
0x009C7C: 4D0FB6F5                         movzx   r14, r13b
0x009C80: 49C1E630                         shl     r14, 30h
0x009C84: 4C09F6                           or      rsi, r14
0x009D51: 498B6928                         mov     rbp, [r9+28h]
0x2F521C: 488BB5A8000000                   mov     rsi, [rbp+0A8h]
0x2F5288: 49BEB47F8E1301000000             mov     r14, 1138E7FB4h
0x2F52F4: 4981C63439FB2C                   add     r14, 2CFB3934h
0x009E60: 498B7128                         mov     rsi, [r9+28h]
0x2F53C9: 4C8BB6D8000000                   mov     r14, [rsi+0D8h]
0x2F5437: 488BBEA8000000                   mov     rdi, [rsi+0A8h]
0x009E72: 4D0FB6F6                         movzx   r14, r14b
0x009F5E: 4D8B6928                         mov     r13, [r9+28h]
0x2F5507: 498B85E8000000                   mov     rax, [r13+0E8h]
0x2F5571: 49C7C1B210F9B9                   mov     r9, 0FFFFFFFFB9F910B2h
0x2F55DA: 4981C1C6207A46                   add     r9, 467A20C6h
0x009F77: 4151                             push    r9
0x2F5645: 498BADB0000000                   mov     rbp, [r13+0B0h]
0x009F80: 48F72424                         mul     qword ptr [rsp]
0x009F84: 4989C5                           mov     r13, rax
0x00A064: 498B4928                         mov     rcx, [r9+28h]
0x2F571A: 4C8BA9A0000000                   mov     r13, [rcx+0A0h]
0x2F5788: 4C33A9E0000000                   xor     r13, [rcx+0E0h]
0x00A153: 4D8B4128                         mov     r8, [r9+28h]
0x2F5858: 498BB0E0000000                   mov     rsi, [r8+0E0h]
0x00A15E: 56                               push    rsi
0x00A15F: 4989E4                           mov     r12, rsp
0x2F58C6: 4D8BB8E0000000                   mov     r15, [r8+0E0h]
0x00A256: 498B7128                         mov     rsi, [r9+28h]
0x2F599C: 4C8BB6A0000000                   mov     r14, [rsi+0A0h]
0x2F5A05: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x00A268: 4D0FB6F6                         movzx   r14, r14b
0x00A350: 498B7128                         mov     rsi, [r9+28h]
0x2F5AD8: 0FAE96E8000000                   ldmxcsr dword ptr [rsi+0E8h]
0x00A35B: 498B7928                         mov     rdi, [r9+28h]
0x2F5B3E: 4C8BB7E0000000                   mov     r14, [rdi+0E0h]
0x2F5BA6: 49BD49036B2D01000000             mov     r13, 12D6B0349h
0x2F5C16: 4981C577479E12                   add     r13, 129E4777h
0x00A46F: 498B4128                         mov     rax, [r9+28h]
0x00A473: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x2F5CF0: 4C8BA8D0000000                   mov     r13, [rax+0D0h]
0x2F5D5D: 4C8BB0E8000000                   mov     r14, [rax+0E8h]
0x00A56F: 4D8B6128                         mov     r12, [r9+28h]
0x2F5E31: 4D8BBC24E8000000                 mov     r15, [r12+0E8h]
0x00A57B: 458B442434                       mov     r8d, [r12+34h]
0x2F5E9C: 4D038424E0000000                 add     r8, [r12+0E0h]
0x00A588: 418A28                           mov     bpl, [r8]
0x00A58B: 4188EF                           mov     r15b, bpl
0x00A658: 4D8B4128                         mov     r8, [r9+28h]
0x2F5F6A: 498B98F0000000                   mov     rbx, [r8+0F0h]
0x00A663: 53                               push    rbx
0x00A664: 4989E6                           mov     r14, rsp
0x2F5FD1: 4D8BA8F0000000                   mov     r13, [r8+0F0h]
0x00A738: 498B4128                         mov     rax, [r9+28h]
0x2F60A6: 4C8BA8E8000000                   mov     r13, [rax+0E8h]
0x2F610D: 4C8BA0E0000000                   mov     r12, [rax+0E0h]
0x00A74A: 4155                             push    r13
0x00A74C: 68E72AD268                       push    68D22AE7h
0x00A751: 686742183C                       push    3C184267h
0x00A756: 68673A4A41                       push    414A3A67h
0x00A836: 4D8B4128                         mov     r8, [r9+28h]
0x2F61DF: 498BB0F0000000                   mov     rsi, [r8+0F0h]
0x2F624D: 4D8BB8D8000000                   mov     r15, [r8+0D8h]
0x00A848: 480FB6F6                         movzx   rsi, sil
0x00A937: 4D8B5128                         mov     r10, [r9+28h]
0x2F6315: 410FAE92A8000000                 ldmxcsr dword ptr [r10+0A8h]
0x2F6384: 48BAE2CAEDF900000000             mov     rdx, 0F9EDCAE2h
0x00A94D: 52                               push    rdx
0x00A94E: 68510F197B                       push    7B190F51h
0x00A953: 68F74F6D7D                       push    7D6D4FF7h
0x00A958: 68CC529D53                       push    539D52CCh
0x2F63F1: 4881442418DE7F1B46               add     qword ptr [rsp+18h], 461B7FDEh
0x00A966: 498B4928                         mov     rcx, [r9+28h]
0x2F645C: 488B99F0000000                   mov     rbx, [rcx+0F0h]
0x00AA62: 498B7928                         mov     rdi, [r9+28h]
0x00AA66: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x2F652C: 4C8BBFA8000000                   mov     r15, [rdi+0A8h]
0x2F659A: 488BBF90000000                   mov     rdi, [rdi+90h]
0x00AB4E: 4D8B7128                         mov     r14, [r9+28h]
0x2F6669: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x00AB59: 418B7634                         mov     esi, [r14+34h]
0x2F66CE: 4903B6F0000000                   add     rsi, [r14+0F0h]
0x00AB64: 8A16                             mov     dl, [rsi]
0x2F673C: 48C7C1FF000000                   mov     rcx, 0FFh
0x00AB6D: 48C1E108                         shl     rcx, 8
0x00AB71: 48F7D1                           not     rcx
0x00AB74: 4821CD                           and     rbp, rcx
0x00AB77: 480FB6CA                         movzx   rcx, dl
0x00AB7B: 48C1E108                         shl     rcx, 8
0x00AB7F: 4809CD                           or      rbp, rcx
0x00AC52: 498B5928                         mov     rbx, [r9+28h]
0x2F6810: 488BABA0000000                   mov     rbp, [rbx+0A0h]
0x00AC5D: 55                               push    rbp
0x00AC5E: 4989E4                           mov     r12, rsp
0x2F687A: 488BB3A0000000                   mov     rsi, [rbx+0A0h]
0x00AD52: 498B6928                         mov     rbp, [r9+28h]
0x2F6949: 4C8BB588000000                   mov     r14, [rbp+88h]
0x2F69AE: 4C8BA5A8000000                   mov     r12, [rbp+0A8h]
0x00AD64: 4D0FB6F6                         movzx   r14, r14b
0x00AE44: 498B5928                         mov     rbx, [r9+28h]
0x2F6A83: 0FAE93E8000000                   ldmxcsr dword ptr [rbx+0E8h]
0x2F6AEA: 49BE0A1DF0F300000000             mov     r14, 0F3F01D0Ah
0x00AE59: 4156                             push    r14
0x00AE5B: 680C130E62                       push    620E130Ch
0x00AE60: 68EB2A590A                       push    0A592AEBh
0x00AE65: 68EC6ACF05                       push    5CF6AECh
0x00AE6A: 68AF507A1D                       push    1D7A50AFh
0x2F6B56: 4881442420B62D194C               add     [rsp-8+arg_20], 4C192DB6h
0x00AE78: 498B4928                         mov     rcx, [r9+28h]
0x2F6BC5: 488B99D8000000                   mov     rbx, [rcx+0D8h]
0x00AF67: 4D8B6928                         mov     r13, [r9+28h]
0x00AF6B: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x2F6C98: 498B9DB0000000                   mov     rbx, [r13+0B0h]
0x2F6D04: 4D8BBD90000000                   mov     r15, [r13+90h]
0x00B064: 4D8B6928                         mov     r13, [r9+28h]
0x2F6DD8: 498B9DF0000000                   mov     rbx, [r13+0F0h]
0x00B06F: 458B7534                         mov     r14d, [r13+34h]
0x2F6E3F: 4D03B590000000                   add     r14, [r13+90h]
0x00B07A: 418A2E                           mov     bpl, [r14]
0x2F6EAA: 49C7C7FF000000                   mov     r15, 0FFh
0x00B084: 49C1E710                         shl     r15, 10h
0x00B088: 49F7D7                           not     r15
0x00B08B: 4C21FB                           and     rbx, r15
0x00B08E: 4C0FB6FD                         movzx   r15, bpl
0x00B092: 49C1E710                         shl     r15, 10h
0x00B096: 4C09FB                           or      rbx, r15
0x00B16E: 4D8B7128                         mov     r14, [r9+28h]
0x2F6F7A: 4D8B9690000000                   mov     r10, [r14+90h]
0x00B179: 4152                             push    r10
0x00B17B: 4889E7                           mov     rdi, rsp
0x2F6FE3: 498BB690000000                   mov     rsi, [r14+90h]
0x00B26B: 4D8B4928                         mov     r9, [r9+28h]
0x2F70AF: 498B89B0000000                   mov     rcx, [r9+0B0h]
0x2F7118: 4D8BA1A8000000                   mov     r12, [r9+0A8h]
0x00B27D: 51                               push    rcx
0x00B27E: 687750A676                       push    76A65077h
0x00B283: 68F6499E4C                       push    4C9E49F6h
0x00B288: 685224DF3D                       push    3DDF2452h
0x00B380: 498B5928                         mov     rbx, [r9+28h]
0x2F71E3: 488BB3C8000000                   mov     rsi, [rbx+0C8h]
0x2F7249: 4C8BABD8000000                   mov     r13, [rbx+0D8h]
0x00B392: 480FB6F6                         movzx   rsi, sil
0x00B477: 498B4128                         mov     rax, [r9+28h]
0x2F731A: 0FAE90A8000000                   ldmxcsr dword ptr [rax+0A8h]
0x00B482: 4D8B5928                         mov     r11, [r9+28h]
0x2F7386: 4D8BBBE0000000                   mov     r15, [r11+0E0h]
0x2F73EE: 49BD482CFE3701000000             mov     r13, 137FE2C48h
0x2F745A: 4981C5781E0B08                   add     r13, 80B1E78h
0x00B58A: 498B7128                         mov     rsi, [r9+28h]
0x00B58E: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x2F752D: 4C8BBEA8000000                   mov     r15, [rsi+0A8h]
0x2F759B: 4C8BAEF0000000                   mov     r13, [rsi+0F0h]
0x00B68D: 4D8B4128                         mov     r8, [r9+28h]
0x2F766D: 498BB0E0000000                   mov     rsi, [r8+0E0h]
0x00B698: 418B6834                         mov     ebp, [r8+34h]
0x2F76DA: 4903A8F0000000                   add     rbp, [r8+0F0h]
0x00B6A3: 8A4D00                           mov     cl, [rbp+0]
0x2F7747: 49C7C6FF000000                   mov     r14, 0FFh
0x00B6AD: 49C1E618                         shl     r14, 18h
0x00B6B1: 49F7D6                           not     r14
0x00B6B4: 4C21F6                           and     rsi, r14
0x00B6B7: 4C0FB6F1                         movzx   r14, cl
0x00B6BB: 49C1E618                         shl     r14, 18h
0x00B6BF: 4C09F6                           or      rsi, r14
0x00B79C: 4D8B4128                         mov     r8, [r9+28h]
0x2F7818: 4D8BB0A8000000                   mov     r14, [r8+0A8h]
0x00B7A7: 4156                             push    r14
0x00B7A9: 4889E6                           mov     rsi, rsp
0x2F787E: 498B98A8000000                   mov     rbx, [r8+0A8h]
0x00B898: 498B7128                         mov     rsi, [r9+28h]
0x2F7953: 4C8BBEE8000000                   mov     r15, [rsi+0E8h]
0x2F79BA: 488BAE90000000                   mov     rbp, [rsi+90h]
0x00B8AA: 4D0FB6FF                         movzx   r15, r15b
0x00B98C: 4D8B6928                         mov     r13, [r9+28h]
0x2F7A8C: 410FAE95F0000000                 ldmxcsr dword ptr [r13+0F0h]
0x00B998: 4D8B5928                         mov     r11, [r9+28h]
0x2F7AF2: 498BABA0000000                   mov     rbp, [r11+0A0h]
0x2F7B5A: 49BF340B703A01000000             mov     r15, 13A700B34h
0x2F7BC9: 4981C78C3F9905                   add     r15, 5993F8Ch
0x00BA9E: 4D8B4928                         mov     r9, [r9+28h]
0x00BAA2: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x2F7C97: 4D8BB9B8000000                   mov     r15, [r9+0B8h]
0x2F7CFF: 4D8BB1A0000000                   mov     r14, [r9+0A0h]
0x00BB8B: 498B4928                         mov     rcx, [r9+28h]
0x2F7DCE: 488BB1E8000000                   mov     rsi, [rcx+0E8h]
0x00BB96: 8B6934                           mov     ebp, [rcx+34h]
0x2F7E33: 4803A9F0000000                   add     rbp, [rcx+0F0h]
0x00BBA0: 448A5D00                         mov     r11b, [rbp+0]
0x2F7E9C: 49C7C6FF000000                   mov     r14, 0FFh
0x00BBAB: 49C1E620                         shl     r14, 20h
0x00BBAF: 49F7D6                           not     r14
0x00BBB2: 4C21F6                           and     rsi, r14
0x00BBB5: 4D0FB6F3                         movzx   r14, r11b
0x00BBB9: 49C1E620                         shl     r14, 20h
0x00BBBD: 4C09F6                           or      rsi, r14
0x00BC92: 498B7128                         mov     rsi, [r9+28h]
0x2F7F74: 4C8BAEA8000000                   mov     r13, [rsi+0A8h]
0x00BC9D: 4155                             push    r13
0x00BC9F: 4889E3                           mov     rbx, rsp
0x2F7FE1: 488BB6A8000000                   mov     rsi, [rsi+0A8h]
0x00BD9D: 4D8B5128                         mov     r10, [r9+28h]
0x2F80B1: 4D8BBA80000000                   mov     r15, [r10+80h]
0x2F8119: 4D8BAAA8000000                   mov     r13, [r10+0A8h]
0x00BDAF: 4D0FB6FF                         movzx   r15, r15b
0x00BE93: 4D8B7928                         mov     r15, [r9+28h]
0x2F81E7: 410FAE97F0000000                 ldmxcsr dword ptr [r15+0F0h]
0x2F824F: 49BA8AF8BFF100000000             mov     r10, 0F1BFF88Ah
0x00BEA9: 4152                             push    r10
0x00BEAB: 6880177A65                       push    657A1780h
0x00BEB0: 68D9184518                       push    184518D9h
0x00BEB5: 681C393676                       push    7636391Ch
0x2F82B7: 48814424183652494E               add     qword ptr [rsp+18h], 4E495236h
0x00BEC3: 4D8B5928                         mov     r11, [r9+28h]
0x2F8321: 4D8BABE0000000                   mov     r13, [r11+0E0h]
0x00BFB1: 4D8B7128                         mov     r14, [r9+28h]
0x00BFB5: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x2F83F0: 498B9EB8000000                   mov     rbx, [r14+0B8h]
0x2F8455: 4D8BAEE0000000                   mov     r13, [r14+0E0h]
0x00C09E: 4D8B4128                         mov     r8, [r9+28h]
0x2F8528: 498B98E0000000                   mov     rbx, [r8+0E0h]
0x00C0A9: 458B5834                         mov     r11d, [r8+34h]
0x2F8590: 4D039890000000                   add     r11, [r8+90h]
0x00C0B4: 458A23                           mov     r12b, [r11]
0x2F85F6: 49C7C6FF000000                   mov     r14, 0FFh
0x00C0BE: 49C1E638                         shl     r14, 38h
0x00C0C2: 49F7D6                           not     r14
0x00C0C5: 4C21F3                           and     rbx, r14
0x00C0C8: 4D0FB6F4                         movzx   r14, r12b
0x00C0CC: 49C1E638                         shl     r14, 38h
0x00C0D0: 4C09F3                           or      rbx, r14
0x00C1B2: 498B7928                         mov     rdi, [r9+28h]
0x2F86C6: 488BB790000000                   mov     rsi, [rdi+90h]
0x2F8733: 49BC1D49501301000000             mov     r12, 11350491Dh
0x2F879E: 4981C4CB6F392D                   add     r12, 2D396FCBh
0x00C2B0: 4D8B4928                         mov     r9, [r9+28h]
0x2F886A: 498BB990000000                   mov     rdi, [r9+90h]
0x2F88D3: 4D8BA9A8000000                   mov     r13, [r9+0A8h]
0x00C2C2: 480FB6FF                         movzx   rdi, dil
0x00C3A6: 4D8B5128                         mov     r10, [r9+28h]
0x2F89A2: 498B82B0000000                   mov     rax, [r10+0B0h]
0x2F8A0D: 48C7C3B6A274B2                   mov     rbx, 0FFFFFFFFB274A2B6h
0x2F8A77: 4881C30275254E                   add     rbx, 4E257502h
0x00C3BF: 53                               push    rbx
0x2F8ADD: 498BBAE0000000                   mov     rdi, [r10+0E0h]
0x00C3C7: 48F72424                         mul     qword ptr [rsp]
0x00C3CB: 4889C6                           mov     rsi, rax
0x00C4B4: 4D8B5928                         mov     r11, [r9+28h]
0x2F8BAC: 4D8BA3B0000000                   mov     r12, [r11+0B0h]
0x2F8C13: 4D33A3A8000000                   xor     r12, [r11+0A8h]
0x00C5B9: 4D8B6928                         mov     r13, [r9+28h]
0x2F8CE9: 498B85D8000000                   mov     rax, [r13+0D8h]
0x00C5C4: 50                               push    rax
0x00C5C5: 4989E7                           mov     r15, rsp
0x2F8D57: 4D8BADD8000000                   mov     r13, [r13+0D8h]
0x00C6A5: 4D8B4128                         mov     r8, [r9+28h]
0x2F8E22: 4D8B90F0000000                   mov     r10, [r8+0F0h]
0x2F8E8A: 4D8BA8E0000000                   mov     r13, [r8+0E0h]
0x00C6B7: 4152                             push    r10
0x00C6B9: 68DE79C201                       push    1C279DEh
0x00C6BE: 680F36EF75                       push    75EF360Fh
0x00C6C3: 68E91D5935                       push    35591DE9h
0x00C6C8: 68E57C6C3D                       push    3D6C7CE5h
0x00C7BC: 498B7928                         mov     rdi, [r9+28h]
0x2F8F5D: 4C8BA790000000                   mov     r12, [rdi+90h]
0x2F8FC6: 488BAFE0000000                   mov     rbp, [rdi+0E0h]
0x00C7CE: 4D0FB6E4                         movzx   r12, r12b
0x00C8AC: 498B7128                         mov     rsi, [r9+28h]
0x2F909B: 0FAE96D8000000                   ldmxcsr dword ptr [rsi+0D8h]
0x2F9102: 48BF383C241D01000000             mov     rdi, 11D243C38h
0x2F916C: 4881C78836E522                   add     rdi, 22E53688h
0x2F91D3: 488BBF88050000                   mov     rdi, [rdi+588h]
0x2F923F: 4803BED8000000                   add     rdi, [rsi+0D8h]
0x00C8D6: 408A3F                           mov     dil, [rdi]
0x00C8D9: 480FB6FF                         movzx   rdi, dil
0x00C8DD: 48C1E708                         shl     rdi, 8
0x2F92A4: 4829BEA0000000                   sub     [rsi+0A0h], rdi
0x2F9311: 49BBDB01B61001000000             mov     r11, 110B601DBh
0x00C8F2: 4153                             push    r11
0x00C8F4: 68B838EF19                       push    19EF38B8h
0x00C8F9: 68C903AE4C                       push    4CAE03C9h
0x00C8FE: 68D6114909                       push    94911D6h
0x00C903: 684858C27B                       push    7BC25848h
0x2F937C: 4881442420E568532F               add     [rsp-8+arg_20], 2F5368E5h
0x00C911: 498B4928                         mov     rcx, [r9+28h]
0x2F93EB: 4C8BB1A0000000                   mov     r14, [rcx+0A0h]
0x00CA16: 498B7128                         mov     rsi, [r9+28h]
0x00CA1A: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x2F94C0: 488BBEB0000000                   mov     rdi, [rsi+0B0h]
0x2F9528: 4C8BBEE8000000                   mov     r15, [rsi+0E8h]
0x00CB00: 498B6928                         mov     rbp, [r9+28h]
0x2F95F9: 4C8BADF0000000                   mov     r13, [rbp+0F0h]
0x00CB0B: 448B6534                         mov     r12d, [rbp+34h]
0x2F9660: 4C03A5B0000000                   add     r12, [rbp+0B0h]
0x00CB16: 418A1424                         mov     dl, [r12]
0x00CB1A: 4188D5                           mov     r13b, dl
0x00CBF7: 498B5128                         mov     rdx, [r9+28h]
0x2F9732: 4C8B92E0000000                   mov     r10, [rdx+0E0h]
0x00CC02: 4152                             push    r10
0x00CC04: 4989E5                           mov     r13, rsp
0x2F9798: 488B9AE0000000                   mov     rbx, [rdx+0E0h]
0x00CCF4: 498B4128                         mov     rax, [r9+28h]
0x2F9869: 4C8B88E0000000                   mov     r9, [rax+0E0h]
0x2F98CE: 488BA890000000                   mov     rbp, [rax+90h]
0x00CD06: 4151                             push    r9
0x00CD08: 68FB5B0A5D                       push    5D0A5BFBh
0x00CD0D: 68A86DDC47                       push    47DC6DA8h
0x00CD12: 68C67E6B0C                       push    0C6B7EC6h
0x00CDF5: 4D8B5928                         mov     r11, [r9+28h]
0x2F999C: 498B9BF0000000                   mov     rbx, [r11+0F0h]
0x2F9A02: 4D8BA3A0000000                   mov     r12, [r11+0A0h]
0x00CE07: 480FB6DB                         movzx   rbx, bl
0x00CEDE: 498B7928                         mov     rdi, [r9+28h]
0x2F9ACB: 0FAE9790000000                   ldmxcsr dword ptr [rdi+90h]
0x2F9B32: 49BEDD62D4E000000000             mov     r14, 0E0D462DDh
0x2F9B9E: 4981C6E30F355F                   add     r14, 5F350FE3h
0x00CEFA: 4D8B7620                         mov     r14, [r14+20h]
0x2F9C09: 4C03B790000000                   add     r14, [rdi+90h]
0x00CF05: 418A16                           mov     dl, [r14]
0x00CF08: 480FB6D2                         movzx   rdx, dl
0x00CF0C: 48C1E210                         shl     rdx, 10h
0x2F9C75: 482997D8000000                   sub     [rdi+0D8h], rdx
0x00CF17: 498B4128                         mov     rax, [r9+28h]
0x2F9CE0: 488BB8D8000000                   mov     rdi, [rax+0D8h]
0x2F9D4B: 49BFAE05F92401000000             mov     r15, 124F905AEh
0x2F9DB8: 4981C71265101B                   add     r15, 1B106512h
0x00D01E: 4D8B5128                         mov     r10, [r9+28h]
0x00D022: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x2F9E84: 4D8BB2E0000000                   mov     r14, [r10+0E0h]
0x2F9EF1: 498B9AB0000000                   mov     rbx, [r10+0B0h]
0x00D11B: 498B7928                         mov     rdi, [r9+28h]
0x2F9FC4: 4C8BAF90000000                   mov     r13, [rdi+90h]
0x00D126: 448B4F34                         mov     r9d, [rdi+34h]
0x2FA02F: 4C038FE8000000                   add     r9, [rdi+0E8h]
0x00D131: 418A11                           mov     dl, [r9]
0x2FA097: 49C7C1FF000000                   mov     r9, 0FFh
0x00D13B: 49C1E108                         shl     r9, 8
0x00D13F: 49F7D1                           not     r9
0x00D142: 4D21CD                           and     r13, r9
0x00D145: 4C0FB6CA                         movzx   r9, dl
0x00D149: 49C1E108                         shl     r9, 8
0x00D14D: 4D09CD                           or      r13, r9
0x00D236: 4D8B6928                         mov     r13, [r9+28h]
0x2FA165: 4D8B95E0000000                   mov     r10, [r13+0E0h]
0x00D241: 4152                             push    r10
0x00D243: 4889E7                           mov     rdi, rsp
0x2FA1D2: 498BB5E0000000                   mov     rsi, [r13+0E0h]
0x00D329: 4D8B4928                         mov     r9, [r9+28h]
0x2FA29F: 498BB1B0000000                   mov     rsi, [r9+0B0h]
0x2FA309: 498B99A8000000                   mov     rbx, [r9+0A8h]
0x00D33B: 56                               push    rsi
0x00D33C: 6821349347                       push    47933421h
0x00D341: 684E649653                       push    5396644Eh
0x00D346: 684615C841                       push    41C81546h
0x00D42A: 498B5928                         mov     rbx, [r9+28h]
0x2FA3E0: 488BABC8000000                   mov     rbp, [rbx+0C8h]
0x2FA44C: 4C8BAB90000000                   mov     r13, [rbx+90h]
0x00D43C: 480FB6ED                         movzx   rbp, bpl
0x00D52B: 498B7928                         mov     rdi, [r9+28h]
0x2FA516: 0FAE97A0000000                   ldmxcsr dword ptr [rdi+0A0h]
0x2FA57B: 49BB19F323C800000000             mov     r11, 0C823F319h
0x2FA5E3: 4981C3A77FE577                   add     r11, 77E57FA7h
0x2FA64C: 4D8B9B40010000                   mov     r11, [r11+140h]
0x2FA6B1: 4C039FA0000000                   add     r11, [rdi+0A0h]
0x00D555: 458A03                           mov     r8b, [r11]
0x00D558: 4D0FB6C0                         movzx   r8, r8b
0x00D55C: 49C1E018                         shl     r8, 18h
0x2FA716: 4C2987E0000000                   sub     [rdi+0E0h], r8
0x2FA77E: 48B9CDEC083501000000             mov     rcx, 13508ECCDh
0x00D571: 51                               push    rcx
0x00D572: 68DF1ADB02                       push    2DB1ADFh
0x00D577: 680A0E4545                       push    45450E0Ah
0x00D57C: 68AE6ED738                       push    38D76EAEh
0x00D581: 68342EA660                       push    60A62E34h
0x2FA7ED: 4881442420F37D000B               add     [rsp-8+arg_20], 0B007DF3h
0x00D58F: 4D8B6128                         mov     r12, [r9+28h]
0x2FA858: 498BAC24E0000000                 mov     rbp, [r12+0E0h]
0x00D681: 498B7128                         mov     rsi, [r9+28h]
0x00D685: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x2FA928: 4C8BBEE0000000                   mov     r15, [rsi+0E0h]
0x2FA992: 488BB6A0000000                   mov     rsi, [rsi+0A0h]
0x00D788: 4D8B5128                         mov     r10, [r9+28h]
0x2FAA61: 498BBAA8000000                   mov     rdi, [r10+0A8h]
0x00D793: 418B4234                         mov     eax, [r10+34h]
0x2FAACB: 490382F0000000                   add     rax, [r10+0F0h]
0x00D79E: 448A28                           mov     r13b, [rax]
0x2FAB36: 48C7C3FF000000                   mov     rbx, 0FFh
0x00D7A8: 48C1E310                         shl     rbx, 10h
0x00D7AC: 48F7D3                           not     rbx
0x00D7AF: 4821DF                           and     rdi, rbx
0x00D7B2: 490FB6DD                         movzx   rbx, r13b
0x00D7B6: 48C1E310                         shl     rbx, 10h
0x00D7BA: 4809DF                           or      rdi, rbx
0x00D89D: 498B5928                         mov     rbx, [r9+28h]
0x2FAC0B: 488BBBB0000000                   mov     rdi, [rbx+0B0h]
0x00D8A8: 57                               push    rdi
0x00D8A9: 4989E6                           mov     r14, rsp
0x2FAC72: 4C8BABB0000000                   mov     r13, [rbx+0B0h]
0x00D995: 4D8B4928                         mov     r9, [r9+28h]
0x2FAD3F: 498BB990000000                   mov     rdi, [r9+90h]
0x2FADA5: 498B99E0000000                   mov     rbx, [r9+0E0h]
0x00D9A7: 480FB6FF                         movzx   rdi, dil
0x00DA95: 498B6928                         mov     rbp, [r9+28h]
0x2FAE76: 0FAE95B0000000                   ldmxcsr dword ptr [rbp+0B0h]
0x2FAEDF: 49BB333C8C1501000000             mov     r11, 1158C3C33h
0x2FAF4F: 4981C38D367D2A                   add     r11, 2A7D368Dh
0x2FAFB8: 4D8B9B50060000                   mov     r11, [r11+650h]
0x2FB026: 4C039DB0000000                   add     r11, [rbp+0B0h]
0x00DABF: 418A13                           mov     dl, [r11]
0x00DAC2: 480FB6D2                         movzx   rdx, dl
0x00DAC6: 48C1E220                         shl     rdx, 20h
0x2FB093: 48299590000000                   sub     [rbp+90h], rdx
0x00DAD1: 498B4928                         mov     rcx, [r9+28h]
0x2FB0F8: 488BB190000000                   mov     rsi, [rcx+90h]
0x2FB162: 48BDDEF1DFF500000000             mov     rbp, 0F5DFF1DEh
0x2FB1CB: 4881C5E278294A                   add     rbp, 4A2978E2h
0x00DBDC: 4D8B6928                         mov     r13, [r9+28h]
0x00DBE0: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x2FB298: 498BAD88000000                   mov     rbp, [r13+88h]
0x2FB2FD: 4D8BA5A8000000                   mov     r12, [r13+0A8h]
0x00DCC8: 498B7128                         mov     rsi, [r9+28h]
0x2FB3CE: 4C8BBED8000000                   mov     r15, [rsi+0D8h]
0x00DCD3: 448B4E34                         mov     r9d, [rsi+34h]
0x2FB437: 4C038EA0000000                   add     r9, [rsi+0A0h]
0x00DCDE: 418A01                           mov     al, [r9]
0x2FB4A4: 48C7C2FF000000                   mov     rdx, 0FFh
0x00DCE8: 48C1E218                         shl     rdx, 18h
0x00DCEC: 48F7D2                           not     rdx
0x00DCEF: 4921D7                           and     r15, rdx
0x00DCF2: 480FB6D0                         movzx   rdx, al
0x00DCF6: 48C1E218                         shl     rdx, 18h
0x00DCFA: 4909D7                           or      r15, rdx
0x00DDDC: 498B5928                         mov     rbx, [r9+28h]
0x2FB570: 4C8B93F0000000                   mov     r10, [rbx+0F0h]
0x00DDE7: 4152                             push    r10
0x00DDE9: 4889E6                           mov     rsi, rsp
0x2FB5D8: 488BBBF0000000                   mov     rdi, [rbx+0F0h]
0x00DEE4: 498B7128                         mov     rsi, [r9+28h]
0x2FB6AD: 488BAEE0000000                   mov     rbp, [rsi+0E0h]
0x2FB71B: 4C8BAEB0000000                   mov     r13, [rsi+0B0h]
0x00DEF6: 480FB6ED                         movzx   rbp, bpl
0x00DFD0: 4D8B4128                         mov     r8, [r9+28h]
0x2FB7ED: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x2FB853: 49BDAA5F362D01000000             mov     r13, 12D365FAAh
0x2FB8C4: 4981C51613D312                   add     r13, 12D31316h
0x00DFED: 4D8B6D00                         mov     r13, [r13+0]
0x2FB931: 4D03A8A0000000                   add     r13, [r8+0A0h]
0x00DFF8: 418A4500                         mov     al, [r13+0]
0x00DFFC: 480FB6C0                         movzx   rax, al
0x00E000: 48C1E028                         shl     rax, 28h
0x2FB99C: 492980E0000000                   sub     [r8+0E0h], rax
0x2FBA01: 48BB6F2FB60D01000000             mov     rbx, 10DB62F6Fh
0x00E015: 53                               push    rbx
0x00E016: 68CA58E176                       push    76E158CAh
0x00E01B: 68590C2650                       push    50260C59h
0x00E020: 68CF3D9738                       push    38973DCFh
0x00E025: 6833388C20                       push    208C3833h
0x2FBA70: 4881442420513B5332               add     qword ptr [rsp+20h], 32533B51h
0x00E033: 498B7928                         mov     rdi, [r9+28h]
0x2FBAD9: 488BAFE0000000                   mov     rbp, [rdi+0E0h]
0x00E122: 4D8B5128                         mov     r10, [r9+28h]
0x00E126: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x2FBBAC: 498BB2A8000000                   mov     rsi, [r10+0A8h]
0x2FBC14: 4D8BBAA0000000                   mov     r15, [r10+0A0h]
0x00E223: 498B5128                         mov     rdx, [r9+28h]
0x2FBCEB: 4C8BBAF0000000                   mov     r15, [rdx+0F0h]
0x00E22E: 448B4A34                         mov     r9d, [rdx+34h]
0x2FBD50: 4C038AA8000000                   add     r9, [rdx+0A8h]
0x00E239: 458A31                           mov     r14b, [r9]
0x2FBDBE: 48C7C2FF000000                   mov     rdx, 0FFh
0x00E243: 48C1E220                         shl     rdx, 20h
0x00E247: 48F7D2                           not     rdx
0x00E24A: 4921D7                           and     r15, rdx
0x00E24D: 490FB6D6                         movzx   rdx, r14b
0x00E251: 48C1E220                         shl     rdx, 20h
0x00E255: 4909D7                           or      r15, rdx
0x00E339: 498B5928                         mov     rbx, [r9+28h]
0x2FBE8E: 4C8B93F0000000                   mov     r10, [rbx+0F0h]
0x00E344: 4152                             push    r10
0x00E346: 4989E7                           mov     r15, rsp
0x2FBEF9: 4C8BABF0000000                   mov     r13, [rbx+0F0h]
0x00E442: 4D8B4928                         mov     r9, [r9+28h]
0x2FBFCA: 4D8BA1C0000000                   mov     r12, [r9+0C0h]
0x2FC030: 498B99E0000000                   mov     rbx, [r9+0E0h]
0x00E454: 4D0FB6E4                         movzx   r12, r12b
0x00E542: 4D8B5128                         mov     r10, [r9+28h]
0x2FC106: 410FAE92D8000000                 ldmxcsr dword ptr [r10+0D8h]
0x2FC174: 48BDD503460701000000             mov     rbp, 1074603D5h
0x2FC1E4: 4881C5EB6EC338                   add     rbp, 38C36EEBh
0x00E55F: 488B6D00                         mov     rbp, [rbp+0]
0x2FC251: 4903AAD8000000                   add     rbp, [r10+0D8h]
0x00E56A: 408A7D00                         mov     dil, [rbp+0]
0x00E56E: 480FB6FF                         movzx   rdi, dil
0x00E572: 48C1E730                         shl     rdi, 30h
0x2FC2BC: 4929BA90000000                   sub     [r10+90h], rdi
0x2FC322: 48BAA815F33C01000000             mov     rdx, 13CF315A8h
0x00E587: 52                               push    rdx
0x00E588: 687B0B1A72                       push    721A0B7Bh
0x00E58D: 68055A5A3D                       push    3D5A5A05h
0x00E592: 68CD361542                       push    421536CDh
0x00E597: 68B0765B72                       push    725B76B0h
0x2FC38C: 488144242018551603               add     [rsp-8+arg_20], 3165518h
0x00E5A5: 4D8B5128                         mov     r10, [r9+28h]
0x2FC3F8: 498BB290000000                   mov     rsi, [r10+90h]
0x00E6A0: 498B7928                         mov     rdi, [r9+28h]
0x00E6A4: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x2FC4CD: 488B9FD8000000                   mov     rbx, [rdi+0D8h]
0x2FC537: 4C8BA7A8000000                   mov     r12, [rdi+0A8h]
0x00E790: 498B5928                         mov     rbx, [r9+28h]
0x2FC609: 488BB3D8000000                   mov     rsi, [rbx+0D8h]
0x00E79B: 448B4B34                         mov     r9d, [rbx+34h]
0x2FC677: 4C038B90000000                   add     r9, [rbx+90h]
0x00E7A6: 418A19                           mov     bl, [r9]
0x2FC6E3: 48C7C5FF000000                   mov     rbp, 0FFh
0x00E7B0: 48C1E528                         shl     rbp, 28h
0x00E7B4: 48F7D5                           not     rbp
0x00E7B7: 4821EE                           and     rsi, rbp
0x00E7BA: 480FB6EB                         movzx   rbp, bl
0x00E7BE: 48C1E528                         shl     rbp, 28h
0x00E7C2: 4809EE                           or      rsi, rbp
0x2FC7AC: 49BBAB90310001000000             mov     r11, 1003190ABh
0x00E8A7: 4153                             push    r11
0x00E8A9: 68BF33D44C                       push    4CD433BFh
0x00E8AE: 6864743A7F                       push    7F3A7464h
0x00E8B3: 68540CA505                       push    5A50C54h
0x2FC817: 48814424183D285840               add     [rsp-8+arg_18], 4058283Dh
0x00E8C1: 498B5128                         mov     rdx, [r9+28h]
0x2FC87F: 4C8BAAA8000000                   mov     r13, [rdx+0A8h]
0x00E9BE: 4D8B6928                         mov     r13, [r9+28h]
0x2FC94E: 498BB5B0000000                   mov     rsi, [r13+0B0h]
0x2FC9BC: 4D8BA5E0000000                   mov     r12, [r13+0E0h]
0x00E9D0: 480FB6F6                         movzx   rsi, sil
0x00EABB: 4D8B4128                         mov     r8, [r9+28h]
0x2FCA92: 498B80A8000000                   mov     rax, [r8+0A8h]
0x2FCAFC: 48C7C3792537CC                   mov     rbx, 0FFFFFFFFCC372579h
0x2FCB65: 4881C3D7124034                   add     rbx, 344012D7h
0x00EAD4: 53                               push    rbx
0x2FCBD0: 4D8BA0D8000000                   mov     r12, [r8+0D8h]
0x00EADC: 48F72424                         mul     qword ptr [rsp]
0x00EAE0: 4989C6                           mov     r14, rax
0x00EBC4: 4D8B6128                         mov     r12, [r9+28h]
0x2FCCA1: 498BBC24D8000000                 mov     rdi, [r12+0D8h]
0x2FCD0F: 4933BC24E8000000                 xor     rdi, [r12+0E8h]
0x00ECB0: 4D8B5928                         mov     r11, [r9+28h]
0x2FCDE6: 4D8BB3B0000000                   mov     r14, [r11+0B0h]
0x00ECBB: 4156                             push    r14
0x00ECBD: 4989E4                           mov     r12, rsp
0x2FCE50: 498BABB0000000                   mov     rbp, [r11+0B0h]
0x00EDA4: 498B7928                         mov     rdi, [r9+28h]
0x2FCF20: 488BAFD8000000                   mov     rbp, [rdi+0D8h]
0x2FCF8E: 4C8BBFA0000000                   mov     r15, [rdi+0A0h]
0x00EDB6: 55                               push    rbp
0x00EDB7: 682E423272                       push    7232422Eh
0x00EDBC: 688D4C356F                       push    6F354C8Dh
0x00EDC1: 68405F857F                       push    7F855F40h
0x00EEA3: 498B4128                         mov     rax, [r9+28h]
0x2FD060: 4C8BB088000000                   mov     r14, [rax+88h]
0x2FD0CD: 4C8BA0F0000000                   mov     r12, [rax+0F0h]
0x00EEB5: 4D0FB6F6                         movzx   r14, r14b
0x00EFA9: 4D8B7128                         mov     r14, [r9+28h]
0x2FD1A0: 410FAE96E8000000                 ldmxcsr dword ptr [r14+0E8h]
0x00EFB5: 4D8B7128                         mov     r14, [r9+28h]
0x2FD20B: 4D8BB6D8000000                   mov     r14, [r14+0D8h]
0x2FD278: 48BF68E951EE00000000             mov     rdi, 0EE51E968h
0x2FD2E1: 4881C75861B751                   add     rdi, 51B76158h
0x00F0AD: 498B4128                         mov     rax, [r9+28h]
0x00F0B1: 0FAE5034                         ldmxcsr dword ptr [rax+34h]
0x2FD3AB: 488BA8B8000000                   mov     rbp, [rax+0B8h]
0x2FD416: 4C8BA0E8000000                   mov     r12, [rax+0E8h]
0x00F1A2: 498B4128                         mov     rax, [r9+28h]
0x2FD4EE: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x00F1AD: 8B4834                           mov     ecx, [rax+34h]
0x2FD554: 480388A0000000                   add     rcx, [rax+0A0h]
0x00F1B7: 8A11                             mov     dl, [rcx]
0x00F1B9: 4188D4                           mov     r12b, dl
0x00F2A0: 4D8B5928                         mov     r11, [r9+28h]
0x2FD622: 4D8BB3D8000000                   mov     r14, [r11+0D8h]
0x00F2AB: 4156                             push    r14
0x00F2AD: 4989E5                           mov     r13, rsp
0x2FD68D: 4D8BBBD8000000                   mov     r15, [r11+0D8h]
0x00F3AB: 4D8B4128                         mov     r8, [r9+28h]
0x2FD761: 4D8BB0B8000000                   mov     r14, [r8+0B8h]
0x2FD7CD: 498BB8F0000000                   mov     rdi, [r8+0F0h]
0x00F3BD: 4D0FB6F6                         movzx   r14, r14b
0x00F4A3: 4D8B6928                         mov     r13, [r9+28h]
0x2FD8A0: 410FAE95E8000000                 ldmxcsr dword ptr [r13+0E8h]
0x00F4AF: 4D8B5128                         mov     r10, [r9+28h]
0x2FD90F: 4D8BBAB0000000                   mov     r15, [r10+0B0h]
0x2FD97C: 49BD29E9791D01000000             mov     r13, 11D79E929h
0x2FD9EA: 4981C597618F22                   add     r13, 228F6197h
0x00F5B6: 4D8B7128                         mov     r14, [r9+28h]
0x00F5BA: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x2FDABC: 4D8BBEB8000000                   mov     r15, [r14+0B8h]
0x2FDB27: 498BAEF0000000                   mov     rbp, [r14+0F0h]
0x00F6B3: 498B5128                         mov     rdx, [r9+28h]
0x2FDBFC: 488BBAA0000000                   mov     rdi, [rdx+0A0h]
0x00F6BE: 448B5234                         mov     r10d, [rdx+34h]
0x2FDC6A: 4C0392F0000000                   add     r10, [rdx+0F0h]
0x00F6C9: 418A32                           mov     sil, [r10]
0x2FDCD4: 49C7C3FF000000                   mov     r11, 0FFh
0x00F6D3: 49C1E308                         shl     r11, 8
0x00F6D7: 49F7D3                           not     r11
0x00F6DA: 4C21DF                           and     rdi, r11
0x00F6DD: 4C0FB6DE                         movzx   r11, sil
0x00F6E1: 49C1E308                         shl     r11, 8
0x00F6E5: 4C09DF                           or      rdi, r11
0x00F7C9: 498B6928                         mov     rbp, [r9+28h]
0x2FDDA3: 488B85B0000000                   mov     rax, [rbp+0B0h]
0x00F7D4: 50                               push    rax
0x00F7D5: 4989E7                           mov     r15, rsp
0x2FDE08: 4C8BB5B0000000                   mov     r14, [rbp+0B0h]
0x00F8C2: 4D8B4128                         mov     r8, [r9+28h]
0x2FDEDB: 498B98F0000000                   mov     rbx, [r8+0F0h]
0x2FDF45: 498BA8E8000000                   mov     rbp, [r8+0E8h]
0x00F8D4: 53                               push    rbx
0x00F8D5: 6873690B1E                       push    1E0B6973h
0x00F8DA: 68AA570B47                       push    470B57AAh
0x00F8DF: 68DE7C7705                       push    5777CDEh
0x00F9D4: 498B7928                         mov     rdi, [r9+28h]
0x2FE01C: 488B9FC8000000                   mov     rbx, [rdi+0C8h]
0x2FE083: 4C8BAFA0000000                   mov     r13, [rdi+0A0h]
0x00F9E6: 480FB6DB                         movzx   rbx, bl
0x00FACF: 498B5128                         mov     rdx, [r9+28h]
0x2FE15C: 0FAE9290000000                   ldmxcsr dword ptr [rdx+90h]
0x2FE1C3: 48BBCECF682301000000             mov     rbx, 12368CFCEh
0x00FAE4: 53                               push    rbx
0x00FAE5: 68871F2C4E                       push    4E2C1F87h
0x00FAEA: 689F0ECE50                       push    50CE0E9Fh
0x00FAEF: 6899056723                       push    23670599h
0x00FAF4: 687B718E07                       push    78E717Bh
0x2FE233: 4881442420F27AA01C               add     qword ptr [rsp+20h], 1CA07AF2h
0x00FB02: 498B5128                         mov     rdx, [r9+28h]
0x2FE2A1: 488B9AE0000000                   mov     rbx, [rdx+0E0h]
0x00FBF8: 498B6928                         mov     rbp, [r9+28h]
0x00FBFC: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x2FE377: 488BBDC8000000                   mov     rdi, [rbp+0C8h]
0x2FE3E3: 488BAD90000000                   mov     rbp, [rbp+90h]
0x00FCF4: 4D8B5128                         mov     r10, [r9+28h]
0x2FE4B7: 498BBAA0000000                   mov     rdi, [r10+0A0h]
0x00FCFF: 458B7A34                         mov     r15d, [r10+34h]
0x2FE522: 4D03BAB0000000                   add     r15, [r10+0B0h]
0x00FD0A: 458A0F                           mov     r9b, [r15]
0x2FE589: 48C7C5FF000000                   mov     rbp, 0FFh
0x00FD14: 48C1E510                         shl     rbp, 10h
0x00FD18: 48F7D5                           not     rbp
0x00FD1B: 4821EF                           and     rdi, rbp
0x00FD1E: 490FB6E9                         movzx   rbp, r9b
0x00FD22: 48C1E510                         shl     rbp, 10h
0x00FD26: 4809EF                           or      rdi, rbp
0x00FE02: 4D8B6128                         mov     r12, [r9+28h]
0x2FE653: 498BBC24B0000000                 mov     rdi, [r12+0B0h]
0x00FE0E: 57                               push    rdi
0x00FE0F: 4989E6                           mov     r14, rsp
0x2FE6BB: 498BBC24B0000000                 mov     rdi, [r12+0B0h]
0x00FF04: 4D8B4928                         mov     r9, [r9+28h]
0x2FE78D: 498BB9E8000000                   mov     rdi, [r9+0E8h]
0x2FE7F8: 4D8BB9B0000000                   mov     r15, [r9+0B0h]
0x00FF16: 57                               push    rdi
0x00FF17: 68317C1B25                       push    251B7C31h
0x00FF1C: 68097BEF0F                       push    0FEF7B09h
0x00FF21: 681A333172                       push    7231331Ah
0x00FF26: 680D629E68                       push    689E620Dh
0x01000A: 4D8B6128                         mov     r12, [r9+28h]
0x2FE8C8: 4D8BAC24A8000000                 mov     r13, [r12+0A8h]
0x2FE936: 4D8BBC24F0000000                 mov     r15, [r12+0F0h]
0x01001E: 4D0FB6ED                         movzx   r13, r13b
0x010100: 498B5128                         mov     rdx, [r9+28h]
0x2FEA0B: 0FAE92E0000000                   ldmxcsr dword ptr [rdx+0E0h]
0x01010B: 4D8B5128                         mov     r10, [r9+28h]
0x2FEA75: 498BB2F0000000                   mov     rsi, [r10+0F0h]
0x2FEADE: 48BB51CB0AF400000000             mov     rbx, 0F40ACB51h
0x2FEB46: 4881C36F7FFE4B                   add     rbx, 4BFE7F6Fh
0x010205: 4D8B7128                         mov     r14, [r9+28h]
0x010209: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x2FEC1F: 498BBED0000000                   mov     rdi, [r14+0D0h]
0x2FEC8D: 4D8BB6A8000000                   mov     r14, [r14+0A8h]
0x0102EF: 4D8B6928                         mov     r13, [r9+28h]
0x2FED62: 498BB5E8000000                   mov     rsi, [r13+0E8h]
0x0102FA: 458B4D34                         mov     r9d, [r13+34h]
0x2FEDCB: 4D038DB0000000                   add     r9, [r13+0B0h]
0x010305: 418A19                           mov     bl, [r9]
0x2FEE39: 48C7C7FF000000                   mov     rdi, 0FFh
0x01030F: 48C1E718                         shl     rdi, 18h
0x010313: 48F7D7                           not     rdi
0x010316: 4821FE                           and     rsi, rdi
0x010319: 480FB6FB                         movzx   rdi, bl
0x01031D: 48C1E718                         shl     rdi, 18h
0x010321: 4809FE                           or      rsi, rdi
0x010411: 4D8B7928                         mov     r15, [r9+28h]
0x2FEF0A: 498BAFA8000000                   mov     rbp, [r15+0A8h]
0x01041C: 55                               push    rbp
0x01041D: 4889E7                           mov     rdi, rsp
0x2FEF6F: 4D8BA7A8000000                   mov     r12, [r15+0A8h]
0x010506: 498B5128                         mov     rdx, [r9+28h]
0x2FF047: 4C8BAAB0000000                   mov     r13, [rdx+0B0h]
0x2FF0AC: 4C8BB2D8000000                   mov     r14, [rdx+0D8h]
0x010518: 4D0FB6ED                         movzx   r13, r13b
0x0105F3: 4D8B6128                         mov     r12, [r9+28h]
0x2FF176: 410FAE9424E0000000               ldmxcsr dword ptr [r12+0E0h]
0x010600: 498B6928                         mov     rbp, [r9+28h]
0x2FF1E3: 4C8BA5E8000000                   mov     r12, [rbp+0E8h]
0x2FF250: 48BF61D59ED500000000             mov     rdi, 0D59ED561h
0x2FF2BA: 4881C75F756A6A                   add     rdi, 6A6A755Fh
0x0106FB: 4D8B4128                         mov     r8, [r9+28h]
0x0106FF: 410FAE5034                       ldmxcsr dword ptr [r8+34h]
0x2FF38B: 498B9888000000                   mov     rbx, [r8+88h]
0x2FF3F9: 4D8BA0D8000000                   mov     r12, [r8+0D8h]
0x010801: 4D8B5928                         mov     r11, [r9+28h]
0x2FF4C8: 498BABD8000000                   mov     rbp, [r11+0D8h]
0x01080C: 458B7B34                         mov     r15d, [r11+34h]
0x2FF52F: 4D03BB90000000                   add     r15, [r11+90h]
0x010817: 458A17                           mov     r10b, [r15]
0x2FF599: 48C7C6FF000000                   mov     rsi, 0FFh
0x010821: 48C1E620                         shl     rsi, 20h
0x010825: 48F7D6                           not     rsi
0x010828: 4821F5                           and     rbp, rsi
0x01082B: 490FB6F2                         movzx   rsi, r10b
0x01082F: 48C1E620                         shl     rsi, 20h
0x010833: 4809F5                           or      rbp, rsi
0x01092F: 4D8B6128                         mov     r12, [r9+28h]
0x2FF669: 4D8BBC24A0000000                 mov     r15, [r12+0A0h]
0x01093B: 4157                             push    r15
0x01093D: 4989E7                           mov     r15, rsp
0x2FF6D7: 498BB424A0000000                 mov     rsi, [r12+0A0h]
0x010A2E: 4D8B6928                         mov     r13, [r9+28h]
0x2FF7A6: 4D8B85F0000000                   mov     r8, [r13+0F0h]
0x2FF80D: 498BADA8000000                   mov     rbp, [r13+0A8h]
0x010A40: 4150                             push    r8
0x010A42: 685624DA7F                       push    7FDA2456h
0x010A47: 68F474A438                       push    38A474F4h
0x010A4C: 68C816330A                       push    0A3316C8h
0x010A51: 68B5300D2B                       push    2B0D30B5h
0x010B48: 4D8B7128                         mov     r14, [r9+28h]
0x2FF8E5: 4D8BAEC0000000                   mov     r13, [r14+0C0h]
0x2FF951: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x010B5A: 4D0FB6ED                         movzx   r13, r13b
0x010C3B: 4D8B5928                         mov     r11, [r9+28h]
0x2FFA22: 410FAE93E0000000                 ldmxcsr dword ptr [r11+0E0h]
0x010C47: 4D8B5928                         mov     r11, [r9+28h]
0x2FFA8F: 498BB3E8000000                   mov     rsi, [r11+0E8h]
0x2FFAFA: 48BFE5E161F500000000             mov     rdi, 0F561E1E5h
0x2FFB6A: 4881C7DB68A74A                   add     rdi, 4AA768DBh
0x010D4D: 498B6928                         mov     rbp, [r9+28h]
0x010D51: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x2FFC41: 4C8BAD80000000                   mov     r13, [rbp+80h]
0x2FFCA8: 488B9DA8000000                   mov     rbx, [rbp+0A8h]
0x010E49: 498B5128                         mov     rdx, [r9+28h]
0x2FFD79: 488B9A90000000                   mov     rbx, [rdx+90h]
0x010E54: 448B4234                         mov     r8d, [rdx+34h]
0x2FFDE7: 4C0382E0000000                   add     r8, [rdx+0E0h]
0x010E5F: 458A38                           mov     r15b, [r8]
0x2FFE55: 48C7C5FF000000                   mov     rbp, 0FFh
0x010E69: 48C1E528                         shl     rbp, 28h
0x010E6D: 48F7D5                           not     rbp
0x010E70: 4821EB                           and     rbx, rbp
0x010E73: 490FB6EF                         movzx   rbp, r15b
0x010E77: 48C1E528                         shl     rbp, 28h
0x010E7B: 4809EB                           or      rbx, rbp
0x010F59: 498B7128                         mov     rsi, [r9+28h]
0x2FFF26: 488B8E90000000                   mov     rcx, [rsi+90h]
0x010F64: 51                               push    rcx
0x010F65: 4989E6                           mov     r14, rsp
0x2FFF93: 4C8BAE90000000                   mov     r13, [rsi+90h]
0x011064: 498B6928                         mov     rbp, [r9+28h]
0x300066: 488BB5C8000000                   mov     rsi, [rbp+0C8h]
0x3000CD: 488BBDE0000000                   mov     rdi, [rbp+0E0h]
0x011076: 480FB6F6                         movzx   rsi, sil
0x011159: 498B7128                         mov     rsi, [r9+28h]
0x3001A1: 0FAE96A8000000                   ldmxcsr dword ptr [rsi+0A8h]
0x300208: 48B9BF3175F300000000             mov     rcx, 0F37531BFh
0x01116E: 51                               push    rcx
0x01116F: 681445DF01                       push    1DF4514h
0x011174: 68CE787F6B                       push    6B7F78CEh
0x011179: 68A52E746E                       push    6E742EA5h
0x300270: 48814424180119944C               add     qword ptr [rsp+18h], 4C941901h
0x011187: 4D8B5928                         mov     r11, [r9+28h]
0x3002DE: 498B9BB0000000                   mov     rbx, [r11+0B0h]
0x01127E: 4D8B7128                         mov     r14, [r9+28h]
0x011282: 410FAE5634                       ldmxcsr dword ptr [r14+34h]
0x3003B4: 4D8BA6A8000000                   mov     r12, [r14+0A8h]
0x30041C: 498BBE90000000                   mov     rdi, [r14+90h]
0x011382: 498B4928                         mov     rcx, [r9+28h]
0x3004EE: 4C8BA1B0000000                   mov     r12, [rcx+0B0h]
0x01138D: 8B5134                           mov     edx, [rcx+34h]
0x300553: 480391D8000000                   add     rdx, [rcx+0D8h]
0x011397: 448A32                           mov     r14b, [rdx]
0x3005C1: 49C7C7FF000000                   mov     r15, 0FFh
0x0113A1: 49C1E730                         shl     r15, 30h
0x0113A5: 49F7D7                           not     r15
0x0113A8: 4D21FC                           and     r12, r15
0x0113AB: 4D0FB6FE                         movzx   r15, r14b
0x0113AF: 49C1E730                         shl     r15, 30h
0x0113B3: 4D09FC                           or      r12, r15
0x01149A: 498B6928                         mov     rbp, [r9+28h]
0x30068B: 4C8BB5D8000000                   mov     r14, [rbp+0D8h]
0x3006F4: 48BD015A86FA00000000             mov     rbp, 0FA865A01h
0x30075E: 4881C5E75E0346                   add     rbp, 46035EE7h
0x0115A9: 498B5928                         mov     rbx, [r9+28h]
0x300832: 4C8BBBD0000000                   mov     r15, [rbx+0D0h]
0x30089B: 4C8BABE8000000                   mov     r13, [rbx+0E8h]
0x0115BB: 4D0FB6FF                         movzx   r15, r15b
0x01169F: 4D8B5128                         mov     r10, [r9+28h]
0x30096C: 498B82F0000000                   mov     rax, [r10+0F0h]
0x3009D4: 49C7C553AA84F0                   mov     r13, 0FFFFFFFFF084AA53h
0x300A41: 4981C5EA725D10                   add     r13, 105D72EAh
0x0116B8: 4155                             push    r13
0x300AA8: 498BAAE0000000                   mov     rbp, [r10+0E0h]
0x0116C1: 48F72424                         mul     qword ptr [rsp]
0x0116C5: 4989C4                           mov     r12, rax
0x0117B6: 498B7928                         mov     rdi, [r9+28h]
0x300B82: 4C8BA7A0000000                   mov     r12, [rdi+0A0h]
0x300BEC: 4C33A7D8000000                   xor     r12, [rdi+0D8h]
0x0118A7: 498B4128                         mov     rax, [r9+28h]
0x300CBC: 488BB8D8000000                   mov     rdi, [rax+0D8h]
0x0118B2: 57                               push    rdi
0x0118B3: 4889E6                           mov     rsi, rsp
0x300D29: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x011995: 4D8B5928                         mov     r11, [r9+28h]
0x300DF5: 498BBBA8000000                   mov     rdi, [r11+0A8h]
0x300E5B: 498B9BD8000000                   mov     rbx, [r11+0D8h]
0x0119A7: 57                               push    rdi
0x0119A8: 6889206B72                       push    726B2089h
0x0119AD: 68243C4C09                       push    94C3C24h
0x0119B2: 688E29875D                       push    5D87298Eh
0x0119B7: 68312BE650                       push    50E62B31h
0x011A92: 4D8B6928                         mov     r13, [r9+28h]
0x011A96: 498B6D78                         mov     rbp, [r13+78h]
0x300F30: 498BB590000000                   mov     rsi, [r13+90h]
0x011AA1: 480FB6ED                         movzx   rbp, bpl
0x011B9A: 4D8B7928                         mov     r15, [r9+28h]
0x301009: 410FAE97A0000000                 ldmxcsr dword ptr [r15+0A0h]
0x011BA6: 4D8B7928                         mov     r15, [r9+28h]
0x301074: 4D8BB7A8000000                   mov     r14, [r15+0A8h]
0x3010D9: 48BB6621580301000000             mov     rbx, 103582166h
0x301143: 4881C35A29B13C                   add     rbx, 3CB1295Ah
0x011CB0: 498B5928                         mov     rbx, [r9+28h]
0x011CB4: 0FAE5334                         ldmxcsr dword ptr [rbx+34h]
0x301212: 4C8BBBC0000000                   mov     r15, [rbx+0C0h]
0x30127A: 488BB3E8000000                   mov     rsi, [rbx+0E8h]
0x011DA1: 4D8B6128                         mov     r12, [r9+28h]
0x30134B: 4D8BB424A8000000                 mov     r14, [r12+0A8h]
0x011DAD: 458B442434                       mov     r8d, [r12+34h]
0x3013B6: 4D038424F0000000                 add     r8, [r12+0F0h]
0x011DBA: 418A38                           mov     dil, [r8]
0x011DBD: 4188FE                           mov     r14b, dil
0x011E9E: 4D8B5128                         mov     r10, [r9+28h]
0x30148B: 4D8BA2E8000000                   mov     r12, [r10+0E8h]
0x011EA9: 4154                             push    r12
0x011EAB: 4889E6                           mov     rsi, rsp
0x3014F4: 4D8BBAE8000000                   mov     r15, [r10+0E8h]
0x011F8A: 4D8B6928                         mov     r13, [r9+28h]
0x3015C7: 498B9DE8000000                   mov     rbx, [r13+0E8h]
0x30162D: 4D8BB5F0000000                   mov     r14, [r13+0F0h]
0x011F9C: 480FB6DB                         movzx   rbx, bl
0x012075: 4D8B7128                         mov     r14, [r9+28h]
0x3016FE: 410FAE9690000000                 ldmxcsr dword ptr [r14+90h]
0x30176A: 49BF05EBECC900000000             mov     r15, 0C9ECEB05h
0x01208B: 4157                             push    r15
0x01208D: 684C56F34F                       push    4FF3564Ch
0x012092: 68CA478D57                       push    578D47CAh
0x012097: 686011C57B                       push    7BC51160h
0x3017D8: 4881442418BB5F1C76               add     [rsp-8+arg_18], 761C5FBBh
0x0120A5: 498B4928                         mov     rcx, [r9+28h]
0x301843: 488BA9E8000000                   mov     rbp, [rcx+0E8h]
0x0121A0: 4D8B5128                         mov     r10, [r9+28h]
0x0121A4: 410FAE5234                       ldmxcsr dword ptr [r10+34h]
0x30191B: 4D8BBAE0000000                   mov     r15, [r10+0E0h]
0x301980: 498BAAA0000000                   mov     rbp, [r10+0A0h]
0x012295: 4D8B7128                         mov     r14, [r9+28h]
0x301A50: 498B9EA0000000                   mov     rbx, [r14+0A0h]
0x0122A0: 418B7E34                         mov     edi, [r14+34h]
0x301AB6: 4903BEF0000000                   add     rdi, [r14+0F0h]
0x0122AB: 408A3F                           mov     dil, [rdi]
0x301B1B: 49C7C6FF000000                   mov     r14, 0FFh
0x0122B5: 49C1E608                         shl     r14, 8
0x0122B9: 49F7D6                           not     r14
0x0122BC: 4C21F3                           and     rbx, r14
0x0122BF: 4C0FB6F7                         movzx   r14, dil
0x0122C3: 49C1E608                         shl     r14, 8
0x0122C7: 4C09F3                           or      rbx, r14
0x01239C: 498B4928                         mov     rcx, [r9+28h]
0x301BE9: 4C8BA190000000                   mov     r12, [rcx+90h]
0x0123A7: 4154                             push    r12
0x0123A9: 4989E6                           mov     r14, rsp
0x301C56: 4C8BA990000000                   mov     r13, [rcx+90h]
0x01248B: 4D8B7128                         mov     r14, [r9+28h]
0x301D21: 4D8B8EE8000000                   mov     r9, [r14+0E8h]
0x301D8F: 498BAEE0000000                   mov     rbp, [r14+0E0h]
0x01249D: 4151                             push    r9
0x01249F: 68E3225235                       push    355222E3h
0x0124A4: 68152C094C                       push    4C092C15h
0x0124A9: 682574D965                       push    65D97425h
0x012594: 4D8B7128                         mov     r14, [r9+28h]
0x301E5F: 498BBEE0000000                   mov     rdi, [r14+0E0h]
0x301EC6: 4D8BB6A0000000                   mov     r14, [r14+0A0h]
0x0125A6: 480FB6FF                         movzx   rdi, dil
0x01268C: 4D8B4128                         mov     r8, [r9+28h]
0x301F94: 410FAE90B0000000                 ldmxcsr dword ptr [r8+0B0h]
0x012698: 4D8B6128                         mov     r12, [r9+28h]
0x301FFD: 4D8BA424E8000000                 mov     r12, [r12+0E8h]
0x302069: 48BEAF41592101000000             mov     rsi, 1215941AFh
0x3020DA: 4881C61109B01E                   add     rsi, 1EB00911h
0x012793: 498B5128                         mov     rdx, [r9+28h]
0x012797: 0FAE5234                         ldmxcsr dword ptr [rdx+34h]
0x3021AF: 4C8BA2E8000000                   mov     r12, [rdx+0E8h]
0x302219: 488BAAD8000000                   mov     rbp, [rdx+0D8h]
0x012890: 4D8B5928                         mov     r11, [r9+28h]
0x3022E5: 498B9BA0000000                   mov     rbx, [r11+0A0h]
0x01289B: 418B5334                         mov     edx, [r11+34h]
0x30234E: 490393D8000000                   add     rdx, [r11+0D8h]
0x0128A6: 408A3A                           mov     dil, [rdx]
0x3023B6: 49C7C3FF000000                   mov     r11, 0FFh
0x0128B0: 49C1E310                         shl     r11, 10h
0x0128B4: 49F7D3                           not     r11
0x0128B7: 4C21DB                           and     rbx, r11
0x0128BA: 4C0FB6DF                         movzx   r11, dil
0x0128BE: 49C1E310                         shl     r11, 10h
0x0128C2: 4C09DB                           or      rbx, r11
0x01299B: 498B5128                         mov     rdx, [r9+28h]
0x302489: 488BAA90000000                   mov     rbp, [rdx+90h]
0x0129A6: 55                               push    rbp
0x0129A7: 4989E5                           mov     r13, rsp
0x3024F1: 4C8BBA90000000                   mov     r15, [rdx+90h]
0x012A9D: 4D8B4928                         mov     r9, [r9+28h]
0x3025C1: 4D8BA1B8000000                   mov     r12, [r9+0B8h]
0x302626: 498BA9F0000000                   mov     rbp, [r9+0F0h]
0x012AAF: 4D0FB6E4                         movzx   r12, r12b
0x012B84: 4D8B5128                         mov     r10, [r9+28h]
0x3026FF: 410FAE92D8000000                 ldmxcsr dword ptr [r10+0D8h]
0x012B90: 498B5928                         mov     rbx, [r9+28h]
0x302769: 4C8BB3A0000000                   mov     r14, [rbx+0A0h]
0x3027D4: 48BFE925F4FA00000000             mov     rdi, 0FAF425E9h
0x302843: 4881C7D7241545                   add     rdi, 451524D7h
0x012C8D: 4D8B4928                         mov     r9, [r9+28h]
0x012C91: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x302914: 498BB1A0000000                   mov     rsi, [r9+0A0h]
0x302980: 498BA9E8000000                   mov     rbp, [r9+0E8h]
0x012D83: 4D8B7928                         mov     r15, [r9+28h]
0x302A53: 4D8BB7A0000000                   mov     r14, [r15+0A0h]
0x012D8E: 458B6734                         mov     r12d, [r15+34h]
0x302ABE: 4D03A7A8000000                   add     r12, [r15+0A8h]
0x012D99: 458A1424                         mov     r10b, [r12]
0x302B26: 48C7C7FF000000                   mov     rdi, 0FFh
0x012DA4: 48C1E718                         shl     rdi, 18h
0x012DA8: 48F7D7                           not     rdi
0x012DAB: 4921FE                           and     r14, rdi
0x012DAE: 490FB6FA                         movzx   rdi, r10b
0x012DB2: 48C1E718                         shl     rdi, 18h
0x012DB6: 4909FE                           or      r14, rdi
0x012EA6: 4D8B6128                         mov     r12, [r9+28h]
0x302BFD: 4D8B9424E8000000                 mov     r10, [r12+0E8h]
0x012EB2: 4152                             push    r10
0x012EB4: 4889E3                           mov     rbx, rsp
0x302C6B: 498BBC24E8000000                 mov     rdi, [r12+0E8h]
0x012FA7: 4D8B5928                         mov     r11, [r9+28h]
0x302D3B: 498BB3D0000000                   mov     rsi, [r11+0D0h]
0x302DA6: 4D8BBBB0000000                   mov     r15, [r11+0B0h]
0x012FB9: 480FB6F6                         movzx   rsi, sil
0x013092: 4D8B6128                         mov     r12, [r9+28h]
0x302E70: 410FAE9424A8000000               ldmxcsr dword ptr [r12+0A8h]
0x302EDE: 48BD8DEFB23101000000             mov     rbp, 131B2EF8Dh
0x0130A9: 55                               push    rbp
0x0130AA: 689A0A7865                       push    65780A9Ah
0x0130AF: 68CD733002                       push    23073CDh
0x0130B4: 685328B009                       push    9B02853h
0x0130B9: 68F032470F                       push    0F4732F0h
0x302F4E: 4881442420335B560E               add     qword ptr [rsp+20h], 0E565B33h
0x0130C7: 4D8B7128                         mov     r14, [r9+28h]
0x302FB5: 4D8BA6F0000000                   mov     r12, [r14+0F0h]
0x0131BB: 4D8B6928                         mov     r13, [r9+28h]
0x0131BF: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x303087: 4D8BA5C8000000                   mov     r12, [r13+0C8h]
0x3030F1: 4D8BB5D8000000                   mov     r14, [r13+0D8h]
0x0132BD: 498B6928                         mov     rbp, [r9+28h]
0x3031C5: 4C8BB5E8000000                   mov     r14, [rbp+0E8h]
0x0132C8: 448B6534                         mov     r12d, [rbp+34h]
0x30322F: 4C03A5D8000000                   add     r12, [rbp+0D8h]
0x0132D3: 458A1C24                         mov     r11b, [r12]
0x303296: 48C7C6FF000000                   mov     rsi, 0FFh
0x0132DE: 48C1E620                         shl     rsi, 20h
0x0132E2: 48F7D6                           not     rsi
0x0132E5: 4921F6                           and     r14, rsi
0x0132E8: 490FB6F3                         movzx   rsi, r11b
0x0132EC: 48C1E620                         shl     rsi, 20h
0x0132F0: 4909F6                           or      r14, rsi
0x0133D0: 4D8B4128                         mov     r8, [r9+28h]
0x303361: 4D8B90E8000000                   mov     r10, [r8+0E8h]
0x0133DB: 4152                             push    r10
0x0133DD: 4889E3                           mov     rbx, rsp
0x3033CA: 4D8BA0E8000000                   mov     r12, [r8+0E8h]
0x0134BB: 4D8B5128                         mov     r10, [r9+28h]
0x3034A1: 4D8B8A90000000                   mov     r9, [r10+90h]
0x30350F: 498B9AD8000000                   mov     rbx, [r10+0D8h]
0x0134CD: 4151                             push    r9
0x0134CF: 688363716B                       push    6B716383h
0x0134D4: 681563CF56                       push    56CF6315h
0x0134D9: 68DB107C73                       push    737C10DBh
0x0134DE: 683C09656D                       push    6D65093Ch
0x0135BD: 4D8B5928                         mov     r11, [r9+28h]
0x3035E0: 4D8BABE0000000                   mov     r13, [r11+0E0h]
0x30364A: 498B9B90000000                   mov     rbx, [r11+90h]
0x0135CF: 4D0FB6ED                         movzx   r13, r13b
0x0136B9: 498B7128                         mov     rsi, [r9+28h]
0x30371B: 0FAE96E0000000                   ldmxcsr dword ptr [rsi+0E0h]
0x0136C4: 4D8B5928                         mov     r11, [r9+28h]
0x303785: 498BBB90000000                   mov     rdi, [r11+90h]
0x3037F3: 48BDFAEA68EA00000000             mov     rbp, 0EA68EAFAh
0x303861: 4881C5C65FA055                   add     rbp, 55A05FC6h
0x0137D3: 498B7928                         mov     rdi, [r9+28h]
0x0137D7: 0FAE5734                         ldmxcsr dword ptr [rdi+34h]
0x303930: 4C8BB7A0000000                   mov     r14, [rdi+0A0h]
0x303998: 488BAFB0000000                   mov     rbp, [rdi+0B0h]
0x0138D0: 4D8B7128                         mov     r14, [r9+28h]
0x303A6A: 498BBEA0000000                   mov     rdi, [r14+0A0h]
0x0138DB: 418B5634                         mov     edx, [r14+34h]
0x303AD6: 490396E8000000                   add     rdx, [r14+0E8h]
0x0138E6: 448A32                           mov     r14b, [rdx]
0x303B3E: 48C7C3FF000000                   mov     rbx, 0FFh
0x0138F0: 48C1E328                         shl     rbx, 28h
0x0138F4: 48F7D3                           not     rbx
0x0138F7: 4821DF                           and     rdi, rbx
0x0138FA: 490FB6DE                         movzx   rbx, r14b
0x0138FE: 48C1E328                         shl     rbx, 28h
0x013902: 4809DF                           or      rdi, rbx
0x0139DE: 4D8B7128                         mov     r14, [r9+28h]
0x303C0F: 498BAEB0000000                   mov     rbp, [r14+0B0h]
0x0139E9: 55                               push    rbp
0x0139EA: 4989E5                           mov     r13, rsp
0x303C7B: 4D8BBEB0000000                   mov     r15, [r14+0B0h]
0x013AC7: 4D8B7928                         mov     r15, [r9+28h]
0x303D4D: 498B9FA0000000                   mov     rbx, [r15+0A0h]
0x303DB5: 4D8BBFF0000000                   mov     r15, [r15+0F0h]
0x013AD9: 480FB6DB                         movzx   rbx, bl
0x013BBA: 498B6928                         mov     rbp, [r9+28h]
0x303E8A: 0FAE9590000000                   ldmxcsr dword ptr [rbp+90h]
0x303EF7: 48BB8B64BBC600000000             mov     rbx, 0C6BB648Bh
0x303F64: 4881C3350E4E79                   add     rbx, 794E0E35h
0x303FD2: 488B9BC8030000                   mov     rbx, [rbx+3C8h]
0x30403A: 48039D90000000                   add     rbx, [rbp+90h]
0x013BE4: 8A1B                             mov     bl, [rbx]
0x013BE6: 480FB6DB                         movzx   rbx, bl
0x013BEA: 48C1E308                         shl     rbx, 8
0x3040A8: 48299DF0000000                   sub     [rbp+0F0h], rbx
0x304110: 49BE2C5D051301000000             mov     r14, 113055D2Ch
0x013BFF: 4156                             push    r14
0x013C01: 6831389D7E                       push    7E9D3831h
0x013C06: 682B46FD66                       push    66FD462Bh
0x013C0B: 684306AF2A                       push    2AAF0643h
0x304179: 4881442418940D042D               add     qword ptr [rsp+18h], 2D040D94h
0x013C19: 498B5128                         mov     rdx, [r9+28h]
0x3041E0: 4C8BB2F0000000                   mov     r14, [rdx+0F0h]
0x013D13: 498B7128                         mov     rsi, [r9+28h]
0x013D17: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x3042B2: 4C8BB6D0000000                   mov     r14, [rsi+0D0h]
0x304318: 4C8BA6E8000000                   mov     r12, [rsi+0E8h]
0x013E0A: 498B4128                         mov     rax, [r9+28h]
0x3043E4: 4C8BA0D8000000                   mov     r12, [rax+0D8h]
0x013E15: 8B4834                           mov     ecx, [rax+34h]
0x30444F: 480388E8000000                   add     rcx, [rax+0E8h]
0x013E1F: 8A09                             mov     cl, [rcx]
0x013E21: 4188CC                           mov     r12b, cl
0x013EFF: 498B7928                         mov     rdi, [r9+28h]
0x304526: 4C8B87D8000000                   mov     r8, [rdi+0D8h]
0x013F0A: 4150                             push    r8
0x013F0C: 4889E3                           mov     rbx, rsp
0x304592: 488BB7D8000000                   mov     rsi, [rdi+0D8h]
0x013FF6: 4D8B5128                         mov     r10, [r9+28h]
0x30465D: 498B9A90000000                   mov     rbx, [r10+90h]
0x3046C5: 4D8BBAA8000000                   mov     r15, [r10+0A8h]
0x014008: 53                               push    rbx
0x014009: 6843147D53                       push    537D1443h
0x01400E: 68AE2AE934                       push    34E92AAEh
0x014013: 68803BD379                       push    79D33B80h
0x0140FD: 4D8B7128                         mov     r14, [r9+28h]
0x304796: 498BB6B0000000                   mov     rsi, [r14+0B0h]
0x304802: 4D8BBEF0000000                   mov     r15, [r14+0F0h]
0x01410F: 480FB6F6                         movzx   rsi, sil
0x0141F6: 498B5928                         mov     rbx, [r9+28h]
0x3048CC: 0FAE93A8000000                   ldmxcsr dword ptr [rbx+0A8h]
0x304939: 49BD3858021C01000000             mov     r13, 11C025838h
0x3049A3: 4981C5881A0724                   add     r13, 24071A88h
0x304A11: 4D8BADD0030000                   mov     r13, [r13+3D0h]
0x304A7A: 4C03ABA8000000                   add     r13, [rbx+0A8h]
0x014220: 418A7D00                         mov     dil, [r13+0]
0x014224: 480FB6FF                         movzx   rdi, dil
0x014228: 48C1E710                         shl     rdi, 10h
0x304AE5: 4829BBF0000000                   sub     [rbx+0F0h], rdi
0x304B52: 49BA574B122601000000             mov     r10, 126124B57h
0x01423D: 4152                             push    r10
0x01423F: 685A79FA54                       push    54FA795Ah
0x014244: 68EE5F0404                       push    4045FEEh
0x014249: 689E2D2D01                       push    12D2D9Eh
0x304BBB: 4881442418691FF719               add     qword ptr [rsp+18h], 19F71F69h
0x014257: 498B7128                         mov     rsi, [r9+28h]
0x304C29: 488B9EF0000000                   mov     rbx, [rsi+0F0h]
0x014351: 498B4928                         mov     rcx, [r9+28h]
0x014355: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x304CFC: 488B99C0000000                   mov     rbx, [rcx+0C0h]
0x304D6A: 488BA990000000                   mov     rbp, [rcx+90h]
0x01443D: 498B4128                         mov     rax, [r9+28h]
0x304E3A: 488BB0A0000000                   mov     rsi, [rax+0A0h]
0x014448: 448B5834                         mov     r11d, [rax+34h]
0x304EA4: 4C039890000000                   add     r11, [rax+90h]
0x014453: 458A3B                           mov     r15b, [r11]
0x304F0D: 49C7C0FF000000                   mov     r8, 0FFh
0x01445D: 49C1E008                         shl     r8, 8
0x014461: 49F7D0                           not     r8
0x014464: 4C21C6                           and     rsi, r8
0x014467: 4D0FB6C7                         movzx   r8, r15b
0x01446B: 49C1E008                         shl     r8, 8
0x01446F: 4C09C6                           or      rsi, r8
0x01454E: 4D8B6928                         mov     r13, [r9+28h]
0x304FE1: 4D8B9DA8000000                   mov     r11, [r13+0A8h]
0x014559: 4153                             push    r11
0x01455B: 4889E3                           mov     rbx, rsp
0x305049: 498BBDA8000000                   mov     rdi, [r13+0A8h]
0x014641: 498B4928                         mov     rcx, [r9+28h]
0x30511B: 488B8190000000                   mov     rax, [rcx+90h]
0x305183: 4C8BB1B0000000                   mov     r14, [rcx+0B0h]
0x014653: 50                               push    rax
0x014654: 68C32BCC63                       push    63CC2BC3h
0x014659: 68A810602C                       push    2C6010A8h
0x01465E: 68C24EAA31                       push    31AA4EC2h
0x014754: 498B7128                         mov     rsi, [r9+28h]
0x305259: 4C8BA6D8000000                   mov     r12, [rsi+0D8h]
0x3052C6: 488BAEE8000000                   mov     rbp, [rsi+0E8h]
0x014766: 4D0FB6E4                         movzx   r12, r12b
0x01484E: 498B5128                         mov     rdx, [r9+28h]
0x30539B: 0FAE92D8000000                   ldmxcsr dword ptr [rdx+0D8h]
0x305403: 49BDD837ADF200000000             mov     r13, 0F2AD37D8h
0x30546F: 4981C5E83A5C4D                   add     r13, 4D5C3AE8h
0x3054DD: 4D8BAD20030000                   mov     r13, [r13+320h]
0x305545: 4C03AAD8000000                   add     r13, [rdx+0D8h]
0x014878: 418A4D00                         mov     cl, [r13+0]
0x01487C: 480FB6C9                         movzx   rcx, cl
0x014880: 48C1E118                         shl     rcx, 18h
0x3055AC: 48298AA0000000                   sub     [rdx+0A0h], rcx
0x01488B: 498B7928                         mov     rdi, [r9+28h]
0x305615: 4C8BB7A0000000                   mov     r14, [rdi+0A0h]
0x305681: 49BC0AFD7FF300000000             mov     r12, 0F37FFD0Ah
0x3056F2: 4981C4B66D894C                   add     r12, 4C896DB6h
0x014998: 4D8B5928                         mov     r11, [r9+28h]
0x01499C: 410FAE5334                       ldmxcsr dword ptr [r11+34h]
0x3057C1: 498B9B80000000                   mov     rbx, [r11+80h]
0x305828: 498BABE8000000                   mov     rbp, [r11+0E8h]
0x014A98: 4D8B7128                         mov     r14, [r9+28h]
0x3058F6: 498BAEA0000000                   mov     rbp, [r14+0A0h]
0x014AA3: 418B7E34                         mov     edi, [r14+34h]
0x305962: 4903BE90000000                   add     rdi, [r14+90h]
0x014AAE: 408A37                           mov     sil, [rdi]
0x3059CB: 49C7C7FF000000                   mov     r15, 0FFh
0x014AB8: 49C1E710                         shl     r15, 10h
0x014ABC: 49F7D7                           not     r15
0x014ABF: 4C21FD                           and     rbp, r15
0x014AC2: 4C0FB6FE                         movzx   r15, sil
0x014AC6: 49C1E710                         shl     r15, 10h
0x014ACA: 4C09FD                           or      rbp, r15
0x014BA8: 4D8B6128                         mov     r12, [r9+28h]
0x305A96: 498B8424A0000000                 mov     rax, [r12+0A0h]
0x014BB4: 50                               push    rax
0x014BB5: 4989E6                           mov     r14, rsp
0x305B00: 498BAC24A0000000                 mov     rbp, [r12+0A0h]
0x014CA9: 4D8B7128                         mov     r14, [r9+28h]
0x305BCB: 498B9EE8000000                   mov     rbx, [r14+0E8h]
0x305C33: 498BAEA0000000                   mov     rbp, [r14+0A0h]
0x014CBB: 53                               push    rbx
0x014CBC: 68285EA428                       push    28A45E28h
0x014CC1: 68A87FE631                       push    31E67FA8h
0x014CC6: 683B25415D                       push    5D41253Bh
0x014DA9: 4D8B6128                         mov     r12, [r9+28h]
0x305D07: 498BAC2488000000                 mov     rbp, [r12+88h]
0x305D72: 4D8BAC24A0000000                 mov     r13, [r12+0A0h]
0x014DBD: 480FB6ED                         movzx   rbp, bpl
0x014E8D: 498B6928                         mov     rbp, [r9+28h]
0x305E3F: 0FAE95A0000000                   ldmxcsr dword ptr [rbp+0A0h]
0x305EAD: 49BA94FE992D01000000             mov     r10, 12D99FE94h
0x305F17: 4981C22C746F12                   add     r10, 126F742Ch
0x305F81: 4D8B9208040000                   mov     r10, [r10+408h]
0x305FEC: 4C0395A0000000                   add     r10, [rbp+0A0h]
0x014EB7: 458A12                           mov     r10b, [r10]
0x014EBA: 4D0FB6D2                         movzx   r10, r10b
0x014EBE: 49C1E220                         shl     r10, 20h
0x306051: 4C2995E0000000                   sub     [rbp+0E0h], r10
0x014EC9: 498B4928                         mov     rcx, [r9+28h]
0x3060B9: 4C8BB9E0000000                   mov     r15, [rcx+0E0h]
0x306121: 48BD68541AFE00000000             mov     rbp, 0FE1A5468h
0x30618C: 4881C55816EF41                   add     rbp, 41EF1658h
0x014FD3: 498B6928                         mov     rbp, [r9+28h]
0x014FD7: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x306258: 4C8BA5B0000000                   mov     r12, [rbp+0B0h]
0x3062C5: 4C8BADF0000000                   mov     r13, [rbp+0F0h]
0x0150D2: 4D8B5128                         mov     r10, [r9+28h]
0x306392: 498BBAE0000000                   mov     rdi, [r10+0E0h]
0x0150DD: 418B6A34                         mov     ebp, [r10+34h]
0x3063F7: 4903AAD8000000                   add     rbp, [r10+0D8h]
0x0150E8: 8A5500                           mov     dl, [rbp+0]
0x30645E: 49C7C3FF000000                   mov     r11, 0FFh
0x0150F2: 49C1E318                         shl     r11, 18h
0x0150F6: 49F7D3                           not     r11
0x0150F9: 4C21DF                           and     rdi, r11
0x0150FC: 4C0FB6DA                         movzx   r11, dl
0x015100: 49C1E318                         shl     r11, 18h
0x015104: 4C09DF                           or      rdi, r11
0x0151E4: 4D8B5128                         mov     r10, [r9+28h]
0x30652F: 498B82B0000000                   mov     rax, [r10+0B0h]
0x0151EF: 50                               push    rax
0x0151F0: 4889E3                           mov     rbx, rsp
0x30659A: 4D8BB2B0000000                   mov     r14, [r10+0B0h]
0x0152FE: 498B4128                         mov     rax, [r9+28h]
0x30666A: 488BA8C0000000                   mov     rbp, [rax+0C0h]
0x3066D6: 4C8BA0E8000000                   mov     r12, [rax+0E8h]
0x015310: 480FB6ED                         movzx   rbp, bpl
0x0153F1: 4D8B4128                         mov     r8, [r9+28h]
0x3067A6: 410FAE90A0000000                 ldmxcsr dword ptr [r8+0A0h]
0x30680D: 48BA5E65653E01000000             mov     rdx, 13E65655Eh
0x306878: 4881C2620DA401                   add     rdx, 1A40D62h
0x3068E6: 488B92F8070000                   mov     rdx, [rdx+7F8h]
0x30694E: 490390A0000000                   add     rdx, [r8+0A0h]
0x01541C: 408A32                           mov     sil, [rdx]
0x01541F: 480FB6F6                         movzx   rsi, sil
0x015423: 48C1E628                         shl     rsi, 28h
0x3069B5: 4929B0D8000000                   sub     [r8+0D8h], rsi
0x306A1D: 48BFCA44E02901000000             mov     rdi, 129E044CAh
0x015438: 57                               push    rdi
0x015439: 683D64E848                       push    48E8643Dh
0x01543E: 68646DE70A                       push    0AE76D64h
0x015443: 68294AEE5A                       push    5AEE4A29h
0x306A89: 4881442418F6252916               add     [rsp-8+arg_18], 162925F6h
0x015451: 4D8B7128                         mov     r14, [r9+28h]
0x306AF4: 498B9ED8000000                   mov     rbx, [r14+0D8h]
0x01554F: 4D8B6928                         mov     r13, [r9+28h]
0x015553: 410FAE5534                       ldmxcsr dword ptr [r13+34h]
0x306BC5: 498BBDA8000000                   mov     rdi, [r13+0A8h]
0x306C2E: 4D8BBD90000000                   mov     r15, [r13+90h]
0x015656: 4D8B5128                         mov     r10, [r9+28h]
0x306CFC: 498BB2F0000000                   mov     rsi, [r10+0F0h]
0x015661: 458B7A34                         mov     r15d, [r10+34h]
0x306D69: 4D03BAB0000000                   add     r15, [r10+0B0h]
0x01566C: 418A2F                           mov     bpl, [r15]
0x306DD0: 48C7C3FF000000                   mov     rbx, 0FFh
0x015676: 48C1E320                         shl     rbx, 20h
0x01567A: 48F7D3                           not     rbx
0x01567D: 4821DE                           and     rsi, rbx
0x015680: 480FB6DD                         movzx   rbx, bpl
0x015684: 48C1E320                         shl     rbx, 20h
0x015688: 4809DE                           or      rsi, rbx
0x015767: 498B6928                         mov     rbp, [r9+28h]
0x306E9F: 4C8B85A8000000                   mov     r8, [rbp+0A8h]
0x015772: 4150                             push    r8
0x015774: 4889E7                           mov     rdi, rsp
0x306F04: 4C8BADA8000000                   mov     r13, [rbp+0A8h]
0x015861: 4D8B7128                         mov     r14, [r9+28h]
0x306FD2: 498BBEB0000000                   mov     rdi, [r14+0B0h]
0x307037: 498BB6E0000000                   mov     rsi, [r14+0E0h]
0x015873: 57                               push    rdi
0x015874: 68CF579D3F                       push    3F9D57CFh
0x015879: 68714FE922                       push    22E94F71h
0x01587E: 6894558E54                       push    548E5594h
0x01595E: 4D8B6928                         mov     r13, [r9+28h]
0x30710E: 4D8BB5C8000000                   mov     r14, [r13+0C8h]
0x307179: 498B9DA8000000                   mov     rbx, [r13+0A8h]
0x015970: 4D0FB6F6                         movzx   r14, r14b
0x015A5B: 498B4928                         mov     rcx, [r9+28h]
0x307252: 0FAE91E8000000                   ldmxcsr dword ptr [rcx+0E8h]
0x3072B9: 49BDBB5E6C2601000000             mov     r13, 1266C5EBBh
0x307326: 4981C505149D19                   add     r13, 199D1405h
0x307394: 4D8BADF8070000                   mov     r13, [r13+7F8h]
0x3073FF: 4C03A9E8000000                   add     r13, [rcx+0E8h]
0x015A85: 418A4500                         mov     al, [r13+0]
0x015A89: 480FB6C0                         movzx   rax, al
0x015A8D: 48C1E030                         shl     rax, 30h
0x30746A: 48298190000000                   sub     [rcx+90h], rax
0x3074D7: 49BB040C40DC00000000             mov     r11, 0DC400C04h
0x015AA2: 4153                             push    r11
0x015AA4: 68E74B3177                       push    77314BE7h
0x015AA9: 68142E1A74                       push    741A2E14h
0x015AAE: 682C63F70E                       push    0EF7632Ch
0x307548: 4881442418BC5EC963               add     qword ptr [rsp+18h], 63C95EBCh
0x015ABC: 498B4928                         mov     rcx, [r9+28h]
0x3075B8: 488B9990000000                   mov     rbx, [rcx+90h]
0x015BAC: 498B4928                         mov     rcx, [r9+28h]
0x015BB0: 0FAE5134                         ldmxcsr dword ptr [rcx+34h]
0x307688: 4C8BA9A8000000                   mov     r13, [rcx+0A8h]
0x3076ED: 4C8BB190000000                   mov     r14, [rcx+90h]
0x015C93: 4D8B5928                         mov     r11, [r9+28h]
0x3077B9: 498B9BE8000000                   mov     rbx, [r11+0E8h]
0x015C9E: 418B7B34                         mov     edi, [r11+34h]
0x30781F: 4903BBE0000000                   add     rdi, [r11+0E0h]
0x015CA9: 408A3F                           mov     dil, [rdi]
0x30788B: 49C7C7FF000000                   mov     r15, 0FFh
0x015CB3: 49C1E728                         shl     r15, 28h
0x015CB7: 49F7D7                           not     r15
0x015CBA: 4C21FB                           and     rbx, r15
0x015CBD: 4C0FB6FF                         movzx   r15, dil
0x015CC1: 49C1E728                         shl     r15, 28h
0x015CC5: 4C09FB                           or      rbx, r15
0x015DA6: 498B4928                         mov     rcx, [r9+28h]
0x307962: 4C8BB990000000                   mov     r15, [rcx+90h]
0x015DB1: 4157                             push    r15
0x015DB3: 4889E3                           mov     rbx, rsp
0x3079CB: 4C8BB190000000                   mov     r14, [rcx+90h]
0x015E99: 4D8B5928                         mov     r11, [r9+28h]
0x015E9D: 498B5B78                         mov     rbx, [r11+78h]
0x307A98: 4D8BBBE8000000                   mov     r15, [r11+0E8h]
0x015EA8: 480FB6DB                         movzx   rbx, bl
0x015F8D: 4D8B5928                         mov     r11, [r9+28h]
0x307B70: 410FAE9390000000                 ldmxcsr dword ptr [r11+90h]
0x307BD7: 49BDCF3D06C300000000             mov     r13, 0C3063DCFh
0x307C41: 4981C5F134037D                   add     r13, 7D0334F1h
0x307CAA: 4D8BADF8070000                   mov     r13, [r13+7F8h]
0x307D0F: 4D03AB90000000                   add     r13, [r11+90h]
0x015FB8: 458A6500                         mov     r12b, [r13+0]
0x015FBC: 4D0FB6E4                         movzx   r12, r12b
0x015FC0: 49C1E438                         shl     r12, 38h
0x307D79: 4D29A3F0000000                   sub     [r11+0F0h], r12
0x307DE2: 48BBA7560FEC00000000             mov     rbx, 0EC0F56A7h
0x015FD5: 53                               push    rbx
0x015FD6: 680D1CE06F                       push    6FE01C0Dh
0x015FDB: 68B566F907                       push    7F966B5h
0x015FE0: 68D83C6916                       push    16693CD8h
0x307E52: 48814424181914FA53               add     qword ptr [rsp+18h], 53FA1419h
0x015FEE: 498B7128                         mov     rsi, [r9+28h]
0x307EBB: 4C8BBEF0000000                   mov     r15, [rsi+0F0h]
0x0160DB: 4D8B4928                         mov     r9, [r9+28h]
0x0160DF: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x307F92: 498BA9C8000000                   mov     rbp, [r9+0C8h]
0x307FFE: 498BB9F0000000                   mov     rdi, [r9+0F0h]
0x0161DC: 4D8B7128                         mov     r14, [r9+28h]
0x3080D3: 4D8BAEB0000000                   mov     r13, [r14+0B0h]
0x0161E7: 458B6634                         mov     r12d, [r14+34h]
0x308141: 4D03A6A0000000                   add     r12, [r14+0A0h]
0x0161F2: 458A0424                         mov     r8b, [r12]
0x3081A7: 49C7C1FF000000                   mov     r9, 0FFh
0x0161FD: 49C1E130                         shl     r9, 30h
0x016201: 49F7D1                           not     r9
0x016204: 4D21CD                           and     r13, r9
0x016207: 4D0FB6C8                         movzx   r9, r8b
0x01620B: 49C1E130                         shl     r9, 30h
0x01620F: 4D09CD                           or      r13, r9
0x0162F5: 498B7928                         mov     rdi, [r9+28h]
0x308279: 4C8BBFE0000000                   mov     r15, [rdi+0E0h]
0x016300: 4157                             push    r15
0x016302: 4889E5                           mov     rbp, rsp
0x3082DE: 488B9FE0000000                   mov     rbx, [rdi+0E0h]
0x0163F8: 4D8B4928                         mov     r9, [r9+28h]
0x3083AC: 498B99A0000000                   mov     rbx, [r9+0A0h]
0x308418: 4D8BB990000000                   mov     r15, [r9+90h]
0x01640A: 53                               push    rbx
0x01640B: 68F35F1755                       push    55175FF3h
0x016410: 68862F9662                       push    62962F86h
0x016415: 687C72FA36                       push    36FA727Ch
0x01641A: 684A53B151                       push    51B1534Ah
0x016511: 498B7928                         mov     rdi, [r9+28h]
0x3084E9: 4C8BB7E8000000                   mov     r14, [rdi+0E8h]
0x30854E: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x016523: 4D0FB6F6                         movzx   r14, r14b
0x016613: 498B4128                         mov     rax, [r9+28h]
0x308622: 0FAE90E8000000                   ldmxcsr dword ptr [rax+0E8h]
0x01661E: 4D8B7928                         mov     r15, [r9+28h]
0x30868D: 498BAFB0000000                   mov     rbp, [r15+0B0h]
0x3086F6: 48BF9A27D7E200000000             mov     rdi, 0E2D7279Ah
0x308765: 4881C72643325D                   add     rdi, 5D324326h
0x016730: 498B7128                         mov     rsi, [r9+28h]
0x016734: 0FAE5634                         ldmxcsr dword ptr [rsi+34h]
0x308835: 488BAEB0000000                   mov     rbp, [rsi+0B0h]
0x3088A3: 488BBEA0000000                   mov     rdi, [rsi+0A0h]
0x01681C: 498B4128                         mov     rax, [r9+28h]
0x308972: 4C8BA0B0000000                   mov     r12, [rax+0B0h]
0x016827: 448B4834                         mov     r9d, [rax+34h]
0x3089E0: 4C0388A0000000                   add     r9, [rax+0A0h]
0x016832: 458A09                           mov     r9b, [r9]
0x308A4E: 49C7C3FF000000                   mov     r11, 0FFh
0x01683C: 49C1E338                         shl     r11, 38h
0x016840: 49F7D3                           not     r11
0x016843: 4D21DC                           and     r12, r11
0x016846: 4D0FB6D9                         movzx   r11, r9b
0x01684A: 49C1E338                         shl     r11, 38h
0x01684E: 4D09DC                           or      r12, r11
0x01693F: 4D8B6928                         mov     r13, [r9+28h]
0x308B23: 498B9DD8000000                   mov     rbx, [r13+0D8h]
0x01694A: 53                               push    rbx
0x01694B: 4989E7                           mov     r15, rsp
0x308B8D: 498BADD8000000                   mov     rbp, [r13+0D8h]
0x016A56: 498B4928                         mov     rcx, [r9+28h]
0x308C5F: 4C8BA1A8000000                   mov     r12, [rcx+0A8h]
0x308CC5: 4C8BB1A0000000                   mov     r14, [rcx+0A0h]
0x016A68: 4D0FB6E4                         movzx   r12, r12b
0x016B4A: 498B5128                         mov     rdx, [r9+28h]
0x308D97: 0FAE92D8000000                   ldmxcsr dword ptr [rdx+0D8h]
0x308E02: 49BE23EE493801000000             mov     r14, 13849EE23h
0x016B5F: 4156                             push    r14
0x016B61: 683C1F8B1F                       push    1F8B1F3Ch
0x016B66: 68FE2D7269                       push    69722DFEh
0x016B6B: 68DA03C60A                       push    0AC603DAh
0x308E70: 48814424189D64BF07               add     qword ptr [rsp+18h], 7BF649Dh
0x016B79: 4D8B7128                         mov     r14, [r9+28h]
0x308EDF: 4D8BB6E8000000                   mov     r14, [r14+0E8h]
0x016C50: 4D8B4928                         mov     r9, [r9+28h]
0x016C54: 410FAE5134                       ldmxcsr dword ptr [r9+34h]
0x308FAC: 4D8BA1B8000000                   mov     r12, [r9+0B8h]
0x309014: 4D8BA9E8000000                   mov     r13, [r9+0E8h]
0x016D4B: 4D8B4928                         mov     r9, [r9+28h]
0x3090E8: 498BB9E0000000                   mov     rdi, [r9+0E0h]
0x016D56: 458B4134                         mov     r8d, [r9+34h]
0x309150: 4D0381D8000000                   add     r8, [r9+0D8h]
0x016D61: 418A28                           mov     bpl, [r8]
0x3091B5: 49C7C1FF000000                   mov     r9, 0FFh
0x016D6B: 49C1E108                         shl     r9, 8
0x016D6F: 49F7D1                           not     r9
0x016D72: 4C21CF                           and     rdi, r9
0x016D75: 4C0FB6CD                         movzx   r9, bpl
0x016D79: 49C1E108                         shl     r9, 8
0x016D7D: 4C09CF                           or      rdi, r9
0x016E55: 4D8B7928                         mov     r15, [r9+28h]
0x309283: 4D8BA7B0000000                   mov     r12, [r15+0B0h]
0x016E60: 4154                             push    r12
0x016E62: 4989E4                           mov     r12, rsp
0x3092EB: 498BBFB0000000                   mov     rdi, [r15+0B0h]
0x016F5C: 498B5128                         mov     rdx, [r9+28h]
0x3093BB: 488BBAD0000000                   mov     rdi, [rdx+0D0h]
0x309423: 4C8BB2B0000000                   mov     r14, [rdx+0B0h]
0x016F6E: 480FB6FF                         movzx   rdi, dil
0x01705A: 498B7128                         mov     rsi, [r9+28h]
0x3094F1: 0FAE96B0000000                   ldmxcsr dword ptr [rsi+0B0h]
0x30955A: 48BD0B51693301000000             mov     rbp, 13369510Bh
0x01706F: 55                               push    rbp
0x017070: 684D07A721                       push    21A7074Dh
0x017075: 68655DFC4B                       push    4BFC5D65h
0x01707A: 6838142F53                       push    532F1438h
0x3095C7: 4881442418B501A00C               add     qword ptr [rsp+18h], 0CA001B5h
0x017088: 498B4928                         mov     rcx, [r9+28h]
0x309637: 4C8BB1E8000000                   mov     r14, [rcx+0E8h]
0x017181: 4D8B7928                         mov     r15, [r9+28h]
0x017185: 410FAE5734                       ldmxcsr dword ptr [r15+34h]
0x3096FF: 4D8BA7E0000000                   mov     r12, [r15+0E0h]
0x30976B: 4D8BB7E8000000                   mov     r14, [r15+0E8h]
0x017285: 498B7928                         mov     rdi, [r9+28h]
0x30983C: 488B9FE8000000                   mov     rbx, [rdi+0E8h]
0x017290: 448B5734                         mov     r10d, [rdi+34h]
0x3098A2: 4C0397D8000000                   add     r10, [rdi+0D8h]
0x01729B: 458A3A                           mov     r15b, [r10]
0x309907: 48C7C1FF000000                   mov     rcx, 0FFh
0x0172A5: 48C1E120                         shl     rcx, 20h
0x0172A9: 48F7D1                           not     rcx
0x0172AC: 4821CB                           and     rbx, rcx
0x0172AF: 490FB6CF                         movzx   rcx, r15b
0x0172B3: 48C1E120                         shl     rcx, 20h
0x0172B7: 4809CB                           or      rbx, rcx
0x0173A6: 498B7128                         mov     rsi, [r9+28h]
0x3099DA: 488B9E90000000                   mov     rbx, [rsi+90h]
0x0173B1: 53                               push    rbx
0x0173B2: 4989E7                           mov     r15, rsp
0x309A43: 488B9E90000000                   mov     rbx, [rsi+90h]
0x0174AA: 498B6928                         mov     rbp, [r9+28h]
0x309B17: 488BBDF0000000                   mov     rdi, [rbp+0F0h]
0x309B7C: 4C8BBD90000000                   mov     r15, [rbp+90h]
0x0174BC: 57                               push    rdi
0x0174BD: 686427210E                       push    0E212764h
0x0174C2: 686B5B7D4A                       push    4A7D5B6Bh
0x0174C7: 682726774F                       push    4F772627h
0x0175C7: 498B7928                         mov     rdi, [r9+28h]
0x309C54: 4C8BAF80000000                   mov     r13, [rdi+80h]
0x309CBD: 488BBFF0000000                   mov     rdi, [rdi+0F0h]
0x0175D9: 4D0FB6ED                         movzx   r13, r13b
0x0176C7: 498B4928                         mov     rcx, [r9+28h]
0x309D8E: 0FAE91E0000000                   ldmxcsr dword ptr [rcx+0E0h]
0x309DF5: 48BB3621C7C800000000             mov     rbx, 0C8C72136h
0x0176DC: 53                               push    rbx
0x0176DD: 6842227464                       push    64742242h
0x0176E2: 68396D085A                       push    5A086D39h
0x0176E7: 68B55E150E                       push    0E155EB5h
0x309E5F: 48814424188A314277               add     qword ptr [rsp+18h], 7742318Ah
0x0176F5: 498B4928                         mov     rcx, [r9+28h]
0x309EC9: 4C8BA1B0000000                   mov     r12, [rcx+0B0h]
0x0177DE: 498B6928                         mov     rbp, [r9+28h]
0x0177E2: 0FAE5534                         ldmxcsr dword ptr [rbp+34h]
0x309F97: 4C8BADA8000000                   mov     r13, [rbp+0A8h]
0x309FFD: 4C8BA5D8000000                   mov     r12, [rbp+0D8h]
0x0178DF: 498B5128                         mov     rdx, [r9+28h]
0x30A0CC: 4C8BA2D8000000                   mov     r12, [rdx+0D8h]
0x0178EA: 448B5234                         mov     r10d, [rdx+34h]
0x30A132: 4C0392E0000000                   add     r10, [rdx+0E0h]
0x0178F5: 458A2A                           mov     r13b, [r10]
0x30A197: 49C7C7FF000000                   mov     r15, 0FFh
0x0178FF: 49C1E730                         shl     r15, 30h
0x017903: 49F7D7                           not     r15
0x017906: 4D21FC                           and     r12, r15
0x017909: 4D0FB6FD                         movzx   r15, r13b
0x01790D: 49C1E730                         shl     r15, 30h
0x017911: 4D09FC                           or      r12, r15
0x0179E1: 498B5928                         mov     rbx, [r9+28h]
0x30A26D: 4C8BB3D8000000                   mov     r14, [rbx+0D8h]
0x30A2D7: 49BFA1D1F50B01000000             mov     r15, 10BF5D1A1h
0x30A348: 4981C74F400A34                   add     r15, 340A404Fh
0x0179FD: 4D85F6                           test    r14, r14
0x30A3AF: 4C8D2558D6D0FF                   lea     r12, unk_6A37A0E
0x017A07: 4D0F45E7                         cmovnz  r12, r15
0x017A0B: 41FFE4                           jmp     r12
