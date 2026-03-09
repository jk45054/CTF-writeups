#    if (a !== Object["keys"](a0e)[0x5]) return; // working on picture index 5?
a = "boy_friend0.jpg"

a0c = ["When you find a buffer overflow in legacy\x20code", "Reverse Engineer", "When you\x20decompile the obfuscated\x20code and it makes\x20perfect sense", "Me after\x20a\x20week of reverse engineering", "When\x20your decompiler\x20crashes", "It's not a bug, it'a a feature", "Security\x20\x27Expert", "AI", "That's great,\x20but\x20can\x20you hack\x20it?", "When your code compiles for the\x20first time", "If it ain't broke, break it", "Reading\x20someone else's code", "EDR", "This\x20is\x20fine", "FLARE On", "It's always DNS", "strings.exe", "Don't click on that.", "When\x20you find the perfect 0-day exploit", "Security\x20through\x20obscurity", "Instant\x20Coffee", "H@x0r", "Malware", "$1,000,000", "IDA\x20Pro", "Security Expert"]

#    const b = a0l["textContent"], c = a0m["textContent"], d = a0n["textContent"];
#    if (a0c["indexOf"](b) == 0xe
#        && a0c["indexOf"](c) == a0c["length"] - 0x1
#        && a0c["indexOf"](d) == 0x16) {
b = a0c[0xe]
c = a0c[len(a0c) - 1]
d = a0c[0x16]

# d[0x3] + "h" + a[0xa] + b[0x2] + a[0x3] + c[0x5] + c[c["length"] - 0x1] + "5" + a[0x3] + "4" + a[0x3] + c[0x2] + c[0x4] + c[0x3] + "3" + d[0x2] + a[0x3] + "j4" + a0c[0x1][0x2] + d[0x4] + "5" + c[0x2] + d[0x5] + "1" + c[0xb] + "7" + a0c[0x15][0x1] + b["replace"]("\x20", "-") + a[0xb] + a0c[0x4]["substring"](0xc, 0xf);

flag = d[0x3] + "h" + a[0xa] + b[0x2] + a[0x3] + c[0x5] + c[-1] + "5" + a[0x3] + "4" + a[0x3] + c[0x2] + c[0x4] + c[0x3] + "3" + d[0x2] + a[0x3] + "j4" + a0c[0x1][0x2] + d[0x4] + "5" + c[0x2] + d[0x5] + "1" + c[0xb] + "7" + a0c[0x15][0x1]

# b["replace"]("\x20", "-") + a[0xb] + a0c[0x4]["substring"](0xc, 0xf)

#             f = f["toLowerCase"](), alert(atob("Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog") + f);

from base64 import b64decode
prefix = "Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog"
print(f"{b64decode(prefix).decode('utf-8')}", end="")

print(flag.lower()) # wh0a_it5_4_cru3l_j4va5cr1p7@
# we know it ends with flare-on.com
