from utils import is_prime
import random

def generate_random_prime(bits):
	n = random.randint(2 ** (bits - 1) + 1, 2 ** bits - 1)
	while not is_prime(n, 100):
		n = random.randint(2 ** (bits - 1) + 1, 2 ** bits - 1)
	return n 

def find_prim_root(p):
	if p == 2:
		return 1
	p_ = (p - 1) // 2
	while True:
		g = random.randint(2, p - 1)
		if not (pow(g, p_, p) == 1 or pow(g, (p - 1) // p_, p) == 1):
			return g

def gen_keys(bits):
	p = generate_random_prime(bits)
	g = find_prim_root(p)
	g = pow(g, 2, p)
	x = random.randint(1, (p - 1) // 2)
	h = pow(g, x, p)
	pub_k = (p, g, h)
	prv_k = (p, g, x)
	return pub_k, prv_k


def encode(m, p, g, h):
	k = random.randint(1, p)
	s = pow(h, k, p) 
	q = pow(g, k, p) 
	c = m * s
	return c, q
      
def decode(c, p, q, x):
	h = pow(q, x, p)
	return c // h
