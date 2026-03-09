from base64 import b64decode

target_b64_str = "cQoFRQErX1YAVw1zVQdFUSxfAQNRBXUNAxBSe15QCVRVJ1pQEwd/WFBUAlElCFBFUnlaB1ULByRdBEFdfVtWVA=="
target_bytes = b64decode(target_b64_str)
# print(target_bytes)

flarestr = b"FlareOn2024"
i = 0
for cur_target_byte in target_bytes:
    calc_str_idx = i - 11 * (((i * 0x5D1745D1745D1746) >> 64) >> 2)
    print(calc_str_idx)
    i = i + 1