import random
from rsa import generate_random_prime

def ext_euc(a, b):
	s = 0 
	s_ = 1
	t = 1
	t_ = 0
	r = b
	r_ = a
	while r != 0:
		q = r_ // r
		r_, r = r, r_ - q * r
		s_, s = s, s_ - q * s
		t_, t = t, t_ - q * t
	return s_, t_		

def get_primes_for_rabin(bits):
	primes = []
	while len(primes) != 2:
		p = generate_random_prime(bits)
		if (p % 4) == 3:
                        primes.append(p)
	return primes[0], primes[1]

def get_rabin_key(bits):
	p, q = get_primes_for_rabin(bits)
	n = p * q
	return n, p, q

def encode_rabin(m, n):
	return pow(m, 2, n)

def decode_rabin(c, p, q):
	n = p * q
	m_p = pow(c, (p + 1) // 4, p)
	m_q = pow(c, (q + 1) // 4, q)

	y_p, y_q = ext_euc(p, q)

	r1 = (y_p * p * m_q + y_q * q * m_p) % n
	r2 = n - r1
	r3 = (y_p * p * m_q - y_q * q * m_p) % n
	r4 = n - r3

	return r1, r2, r3, r4
