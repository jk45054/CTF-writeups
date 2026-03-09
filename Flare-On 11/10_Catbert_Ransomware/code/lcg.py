# flareon11 challenge 10
#
# lcg keystream for catmeme2 vm


class LCG:
    def __init__(self, a=0x343FD, b=0x269EC3, c=0x80000000, x0=0x1337):
        # a * x + b % c
        self.a = a
        self.b = b
        self.c = c
        self.x = x0  # seed value
        self.i = -1  # char index

    def __next__(self):
        self.x = (self.a * self.x + self.b) % self.c
        self.i = (self.i + 1) % 4
        result = (self.x >> (self.i * 8)) & 0xFF
        return result


if __name__ == "__main__":
    static1 = "24c0de236a4da059"
    static2 = "7f5c720759b164e2"
    # both are reversed byte order
    static = bytes.fromhex(static1)[::-1] + bytes.fromhex(static2)[::-1]
    print(static.hex())

    lcg = LCG()
    input = "".join(chr(static[i] ^ next(lcg)) for i in range(16))
    print(input)
