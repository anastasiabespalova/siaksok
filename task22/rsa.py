import random
from utils import is_prime, ext_euc
import tqdm

def coprime_test(n1, n2):
	for i in range(2, min(n1, n2) + 1):
		if (n1 % i == 0) and (n2 % i == 0):
			return False
	return True

def generate_random_prime(bits):
	n = random.randint(2 ** (bits - 1) + 1, 2 ** bits - 1)
	while not is_prime(n, 100):
		n = random.randint(2 ** (bits - 1) + 1, 2 ** bits - 1)
	return n

def generate_two_random_primes(bits):
	p1 = generate_random_prime(bits)
	p2 = p1
	while p1 == p2:
		p2 =  generate_random_prime(bits)
	return p1, p2

def gen_keys(bits):
	p, q = generate_two_random_primes(bits)

	n = p * q

	etf_val = (p - 1) * (q - 1)
	e = 65537
	d = ext_euc(e, etf_val)[1] % etf_val
	print('p and q', p, q)
	if (d * e) % etf_val != 1:
		raise Exception('Try again.')
	pub_k = (p * q, e)
	priv_k = (p * q, d)
	return pub_k, priv_k

