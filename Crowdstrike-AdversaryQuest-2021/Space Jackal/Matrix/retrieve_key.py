#!/usr/bin/env python3
from z3 import *

A = BitVec("A", 8)
B = BitVec("B", 8)
C = BitVec("C", 8)
s = Solver()
s.add(0x25 == (A * 83 + B * 80 + C * 65) & 0xFF)
s.add(0x01 == (A * 67 + B * 69 + C * 65) & 0xFF)
s.add(0xC2 == (A * 82 + B * 77 + C * 89) & 0xFF)

D = BitVec("D", 8)
E = BitVec("E", 8)
F = BitVec("F", 8)
s.add(0x9F == (D * 83 + E * 80 + F * 65) & 0xFF)
s.add(0x4A == (D * 67 + E * 69 + F * 65) & 0xFF)
s.add(0xBE == (D * 82 + E * 77 + F * 89) & 0xFF)

G = BitVec("G", 8)
H = BitVec("H", 8)
I = BitVec("I", 8)
s.add(0x8D == (G * 83 + H * 80 + I * 65) & 0xFF)
s.add(0x44 == (G * 67 + H * 69 + I * 65) & 0xFF)
s.add(0x8F == (G * 82 + H * 77 + I * 89) & 0xFF)
s.check()
print(s.model())

T=lambda A,B,C,D,E,F,G,H,I:A*E*I+B*F*G+C*D*H-G*E*C-H*F*A-I*D*B&255
def U(K):
    R=pow(T(*K),-1,256)
    A,B,C,D,E,F,G,H,I=K
    return [R*V%256 for V in
     [E*I-F*H,C*H-B*I,B*F-C*E,F*G-D*I,A*I-C*G,C*D-A*F,D*H-E*G,B*G-A*H,A*E-B*D]]

inv_key_matrix = bytearray(9)
inv_key_matrix[0] = s.model()[A].as_long()
inv_key_matrix[1] = s.model()[B].as_long()
inv_key_matrix[2] = s.model()[C].as_long()
inv_key_matrix[3] = s.model()[D].as_long()
inv_key_matrix[4] = s.model()[E].as_long()
inv_key_matrix[5] = s.model()[F].as_long()
inv_key_matrix[6] = s.model()[G].as_long()
inv_key_matrix[7] = s.model()[H].as_long()
inv_key_matrix[8] = s.model()[I].as_long()
print("inverted key matrix U(K) = " + str(bytes(inv_key_matrix)))
key_matrix = U(inv_key_matrix)
print("key matrix K = " + str(bytes(key_matrix)))
