# Flare-On 10, Challenge 11, over_the_rainbow
#
# Different implementations of the (futile) attempt to calculate the cuberoot
# of m
#
# With c = m^e mod N and e = 3
# If m^3 < N, that might be a valid attempt
# As a small exponent attack
# But unfortunately, m^3 > N
#

# Using module gmpy2
from gmpy2 import iroot
from binascii import unhexlify, hexlify

c_bytes = unhexlify("1336e28042804094b2bf03051257aaaaba7eba3e3dd6facff7e3abdd571e9d2e2d2c84f512c0143b27207a3eac0ef965a23f4f4864c7a1ceb913ce1803dba02feb1b56cd8ebe16656abab222e8edca8e9c0dda17c370fce72fe7f6909eed1e6b02e92ebf720ba6051fd7f669cf309ba5467c1fb5d7bb2b7aeca07f11a575746c1047ea35cc3ce246ac0861f0778880d18b71fb2a8d7a736a646cf99b3dcec362d413414beb9f01815db7f72f6e081aee91f191572a28b9576f6c532349f8235b6daf31b39b5add7ade0cfbd30f704eb83d983c215de3261f73565843539f6bb46c9457df16e807449f99f3dabdddd5764fd63d09bc9c4e6844ec3410dc821ab4")
c_int = int.from_bytes(c_bytes, "little")
e = 3
m_int, is_correct = iroot(c_int, e)
print(m_int)

m_i = 13436080979675028122935301543113703697615443075746079867488997357623100609471115548221425860430842465489902991900639117335059378153631761247543353356018070319481734671831025531264996436398326875540555797804
print(m_int)
m_bytes = m_i.to_bytes(256, "little")
print(hexlify(m_bytes))


# Using module decimal
from decimal import *
from binascii import unhexlify

e = 3
c = 24169313728564942442211774792718133649505303766122840641824238947925887523809659286479788261358160947897827563877730687191196979635981766007541262794064747436339518434662376001187909548541032912960261470378632234919864504416430112988325282635602076675727609986764939035311005911495050936123288502045541159782290557092166459385730265169804173086982862520503253166994397834568988061050489364671603850794860660038045636906752404250094067941258320535890143754097216
i = 100

while i < 2000:
	# set precision
	getcontext().prec = i

	# calculate cube root with values wrapped in decimal
	# it is then rounded off using Decimal.to_integral_exact()
	cube_root = int((Decimal(c) ** (Decimal(1) / Decimal(3))).to_integral_exact())

	# remove 0x from start of string
	hex_str = hex(cube_root)[2:]
	try:
		dehex = bytes.fromhex(hex_str).decode()
		flag = bytes.fromhex(dehex).decode()
		if flag.startswith('twc{') and flag.endswith('}'):
			print('Precision :', i)
			print('FLAG      :', flag)
			break
	except UnicodeDecodeError:
		pass
	except ValueError:
		pass
	i += 1

# With m^3 > N, we could try to naively solve m = cuberoot(c + k * N)
#
# from Crypto.Util.number import long_to_bytes
# import gmpy2
# import math
#
# for k in range(0, 100000):
#    m, t = gmpy2.iroot(c_int_le + k * N_int_le, e)
#    if t:
#        print(long_to_bytes(m))
