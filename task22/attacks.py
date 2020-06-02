import math
import random
import argparse
import signal
import time
from rsa import generate_two_random_primes
from utils import ext_euc
import sys

def find_gcf(a, b):
	"""Finding gretatest common factor of a and b with Euclidian algo"""
	while (a != 0) and (b != 0):
		if a > b:
			a %= b
		else:
			b %= a
	return a + b
	
def find_next_prime(primes):
	n = primes[-1] + 2 if primes[-1] != 2 else 3
	while True:
		is_prime = True
		for p in primes:
			if n % p == 0:
				is_prime = False
				break
		if is_prime:
			return primes + [n]
		n += 2

def update_primes(primes, B):
	if primes[-1] < B:
		while primes[-1] <= B:
			primes = find_next_prime(primes)
		return primes[:-1]
	while primes[-1] > B:
		primes = primes[:-1]
	return primes

def get_M(primes, B):
	res = 1
	for p in primes:
		res = (res * (p ** (math.trunc(math.log(B, p)))))
	return res
 
def pollard_p_1(n):
	"""Perform Pollard p-1 attack on n."""
	high = int(n ** 0.5) + 1
	low = 2
	a = 2
	primes = [2]
	step = 0
	while low <= high:
		step += 1
		B = random.randint(low, high)
		primes = update_primes(primes, B)
		M = get_M(primes, B)
		p = pow(a, M, n)
		res = find_gcf(p - 1, n)
		if (1 < res) and (res < n):
			return (res, n // res), (step, B)
		if res == 1:
			low = B + 1
		else:
			high = B - 1
	return None, (step, B)

def pollard_rho(n):
	"""Perform Pollard rho attack on n."""
	x1 = 2
	x2 = 2
	factor = 1
	g = lambda x: ((x ** 2) + 1) % n
	step = 0
	while factor == 1:
		step += 1
		x1 = g(x1)
		x2 = g(g(x2))
		factor = find_gcf(abs(x1 - x2), n)
	if factor == n:
		return None, step
	return (factor, n // factor), step


def get_cont_fraction(a, b):
	q =  a // b
	r = a % b
	if r == 0:
		return [q]
	else:
		return [q] + get_cont_fraction(b, r)

def get_converg_fraction(a):
	p = [1, a[0]]
	q = [0, 1]
	for i in range(len(a) - 1):
		p.append(a[i + 1] * p[-1] + p[-2])
		q.append(a[i + 1] * q[-1] + q[-2])
	return p[2:], q[2:]
	

def solve_quadric(a, b, c):
	d = b ** 2 - 4 * a * c
	if d < 0:
		return None, None
	elif d >= 0:
		return (-b + (d ** 0.5)) / (2 * a), (-b - (d ** 0.5)) / (2 * a)

def wiener(e, n):
	"""Perform Wiener attack on (e, n)."""
	cont_fr = get_cont_fraction(e, n)
	p, q = get_converg_fraction(cont_fr)
	f = [(e * q[i] - 1) / p[i] for i in range(len(p))]
	step = 0
	for i in range(len(p)):
		step += 1
		x1, x2 = solve_quadric(1, -(n - f[i] + 1), n)
		if x1 is None:
			continue
		if (x1 * x2) == n:
			return (int(abs(x1)), int(abs(x2))), (step, len(p))
	return None, (step, len(p))
	
def minor_mod(e, n):
	m = random.randint(2, n - 1)
	c = pow(m, e, n)
	c_cur = pow(c, e, n)
	c_next = pow(c_cur, e, n)
	while c_next != c:
		c_cur = c_next
		c_next = pow(c_cur, e, n)
	return c_cur, c_cur
		 
def cyclic(e, n):
	a_0 = 2
	a = 2
	step = 0
	while True:
		step += 1
		a = pow(a, e, n)
		factor = find_gcf(abs(a - a_0), n)
		if factor > 1: 
			return (factor, n // factor), step

def get_weak_wiener(bits):
	while True:
		p, q = generate_two_random_primes(bits)
		N = p * q
		etf = (p - 1) * (q - 1)
		d = abs(random.getrandbits(bits // 2))
		e = ext_euc(d, etf)[1]
		if (ext_euc(d, etf)[0] == 1) and (9 * pow(d, 4) < N) and (e > 0):
			if wiener(e, N)[0]:
				break
	return e, N, d

def signal_handler(signum, frame):
	raise Exception("Timed out!")

def gen_report(results, name):
	with open(name, 'w') as f:
		for k in results.keys():
			res = results[k] + [None] * (3 - len(results[k]))
			if k == 'Pollard_p_1':
				if res[2] is None:
					res[2] = [None] * 2
				f.write("Атака Полларда p-1. Результат {}. Время работы {} ms. Число шагов {}. Решение при B = {}.\n".format(res[0], res[1], res[2][0], res[2][1]))
			elif k == 'Pollard_rho':
				f.write("Атака Полларда rho. Результат {}. Время работы {} ms. Число шагов {}.\n".format(res[0], res[1], res[2]))	
			elif k == 'Wiener':
				if res[2] is None:
					res[2] = [None] * 2
				f.write("Атака Винера. Результат {}. Время работы {} ms. Число шагов {} из {}.\n".format(res[0], res[1], res[2][0], res[2][1]))
			elif k == 'Minor_mod':
				f.write("Атака восстановления шифр-текста. Результат {}. Время работы {} ms. Исходное сообщение {}.\n".format(res[0], res[1], res[2]))		
			elif k == 'Cyclic':
				f.write("Циклическая атака. Результат {}. Время работы {} ms. Число шагов {}.\n".format(res[0], res[1], res[2]))		

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Process e and N.')
	parser.add_argument('--e', type=int)
	parser.add_argument('--N', type=int)
	parser.add_argument('--attack_time', type=int, default=1, help='Time for one attack in minutes.')
	parser.add_argument('--out_file', type=str, default='report.txt', help='Name for attack report.')
	parser.add_argument('--test_regime', action='store_true', default=False, help='Enable testing regime.')
	parser.add_argument('--complexity', type=int, action='store', default=100, help='Set task complexity for test regime.')
	parser.add_argument('--attacks', type=str, action='store', default='Wiener', help='Set list of attacks to generate vulnerable keys for.')
	args = parser.parse_args()
	attacks = [lambda a, b: pollard_p_1(b), 
		lambda a, b: pollard_rho(b),
		wiener,
		minor_mod,
		cyclic]
	names = ('Pollard_p_1', 
		'Pollard_rho',
		'Wiener',
		'Minor_mod',
		'Cyclic',
		)
	if not args.test_regime:
		res = dict(zip(names, [[],[],[],[],[]]))
		for a, n in zip(attacks, names):
			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(60 * args.attack_time)
			status = None
			t = time.time()
			try:
				status = a(args.e, args.N)
				t = round((time.time() - t) * 1000, 2)
			except:
				print('Time out.')
				res[n] += ["Время вышло"]
				continue
			if status[0] is None:
				print('Fail.')
				res[n] += ['Провал', t, status[1]]
			else:
				print('Success.')
				print(status)
				res[n] += ['Успех', t, status[1]]
		gen_report(res, args.out_file)
	else:
		filtered_attacks = {name :dict(zip(names, attacks))[name] for name in args.attacks.split(',')}
		if 'Wiener' in filtered_attacks.keys():
			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(60 * args.attack_time)
			try:
				e, N, d = get_weak_wiener(args.complexity)
			except:
				print('No key found. Time out.')
				sys.exit()
		else:
			bits = args.complexity
			p, q = generate_two_random_primes(bits)
			N = p * q
			etf = (p - 1) * (q - 1)
			e = abs(random.getrandbits(bits // 2))
			d = ext_euc(e, etf)[1]
			while (ext_euc(e, etf) != 1) and ((e * d) % etf != 1):
				e = abs(random.getrandbits(bits // 2))
				d = ext_euc(e, etf)[1]
		for k in [k for k in filtered_attacks.keys() if k != 'Wiener']:
			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(60 * args.attack_time)
			res = None
			try:
				res, _ = filtered_attacks[k](e, N)
			except:
				print('No key found. Time out.')
				sys.exit()
		print('e={}. d={}, N={}'.format(e, d, N))
