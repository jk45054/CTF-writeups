from z3 import *
from code import interact

x = BitVec("x", 192)

s = Solver()
s.add(Extract(143, 128, x) + Extract(191, 176, x) - Extract(79, 64, x) - Extract(127, 112, x) == 7380)
s.add(Extract(175, 160, x) + Extract(63, 48, x) + Extract(31, 16, x) - Extract(95, 80, x) == 55449)
s.add(Extract(191, 128, x) ^ Extract(63, 0, x) == 721740573498481522)
s.add(Extract(127, 64, x) ^ Extract(191, 128, x) == 2530753753466602581)
s.add(Extract(191, 160, x) + 2*Extract(31, 0, x) - 4*Extract(95, 64, x) - (Extract(159, 128, x) >> 3) - (Extract(63, 32, x) >> 3) == 78988956)
for i in range(24):
    s.add(Extract((i+1)*8-1, i*8, x) >= 0x20)
    s.add(Extract((i+1)*8-1, i*8, x) <= 0x7f)

if (s.check()):
    m = s.model()
    pw = m[x].as_long().to_bytes(24)[::-1]
    print(pw)
else:
    print("The model didn't check out!")
    