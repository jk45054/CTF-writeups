# Flare-On 10, Challenge 13, y0da
#
# Custom base32 alphabet used by base32 function 0x18002BDDF
# Alphabet mapping is done in function 0x1800559B0

#  v3[0] = 'g';
#  v3[1] = '\x95';
#  v3[2] = '\xC8';
#  v3[3] = '\x8D';
#  v3[4] = '\x91';
#  v3[5] = '1';
#  v3[6] = '\xC3';
#  qmemcpy(&v3[7], "!~J:MVU\x7FX]-", 11);
#  v3[18] = '\xB7';
#  v3[19] = '\xCD';
#  v3[20] = '%';
#  v3[21] = '\xFF';
#  qmemcpy(&v3[22], "&dm", 3);
#  v3[25] = '\xBD';
#  v3[26] = '\xCC';
#  v3[27] = '\xDD';
#  qmemcpy(&v3[28], ":P", 2);
#  v3[30] = '\xC6';
#  v3[31] = '\x9C';
#  v4 = '\xBB';
#  v5 = '\xF9';
#  for ( i = 0; i < 34ui64; ++i )
#    v3[i] = (i ^ -(((-(~(~((((32 * (((8 * (i + (i ^ v3[i]))) | ((i + (i ^ v3[i])) >> 5)) - 107)) | ((((8 * (i + (i ^ v3[i]))) | ((i + (i ^ v3[i])) >> 5)) - 107) >> 3))
#                          - i) ^ 0xC3)
#                       - i) ^ 0xA9)
#                   - 60) ^ 0x1C)
#                 + 73))
#          - 30;
#  return v3[c];
#
#
# custom_alpha = b"g\x95\xC8\x8D\x911\xC3!~J:MVU\x7FX]-\xB7\xCD%\xFF&dm\xBD\xCC\xDD:P\xC6\x9C\xBB\xF9"
# alpha = b"Q4T23aSwLnUgHPOIfyKBJVM5+DXZC/Re=" # with 33rd char = as padding
