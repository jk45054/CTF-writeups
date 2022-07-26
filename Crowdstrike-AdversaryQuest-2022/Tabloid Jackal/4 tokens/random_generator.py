#!/usr/bin/env python3

class Random(object):
	def __init__(self, seed):
		self.seed = seed

		self.multiplier = 0x5DEECE66D
		self.addend = 0xB
		self.mask = (1 << 48) - 1

	def _next(self):
		newseed = (self.seed * self.multiplier + self.addend) & self.mask
		self.seed = newseed
		#print(f"newseed: {newseed}")
		return newseed >> 22

	def next(self):
		return self._next() + self._next()  * 2**21 + self._next()  * 2**42

	def next_limit(self, limit):
		return self.next() % limit

if __name__ == "__main__":
	random = Random(241445724851231)
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))
	print(random.next_limit(281474976710656))

