import numpy as np
from utils import ext_euc, get_factor_counts_dict, crt
import signal
from el_gamal import gen_keys
import argparse
import sys
import time

def bsg_attack(h, g, p):
	s = int(np.ceil(p ** 0.5))
	T1, T2 = list(), list()
	for r in range(s):
		T1 += [h * (g ** r) % p]

	for t in range(1, s + 1):
		T2 += [g ** (t * s) % p]
	x1, x2 = 0, 0
	for r in T1:
		for t in T2:
			if r == t:
				x1 = T1.index(r)            
				x2 = T2.index(t)
				break
	return ((x2 + 1) * s - x1) % p

def pohlig_hellman_attack(h, g, p):
	primes = get_factor_counts_dict(p - 1)
	crt_dict = dict()
	for prime, power in primes.items():
		x_list = []
		h_sub = h
		for j in range(1, power + 1):
			i = 0
			q = (p - 1) // pow(prime, j)
			h_pow = pow(h_sub, q, p)
			g_pow = pow(g, (p - 1) // prime, p)
			while True:
				if pow(g_pow, i, p) == h_pow:
					x_list += [i]
					break
				i += 1
			h_sub = (h_sub * pow(ext_euc(g, p)[1], i * pow(prime, j - 1))) % p
		res_mod_prime = 0
		for j in range(power):
			res_mod_prime += pow(prime, j) * x_list[j]
		crt_dict[res_mod_prime % pow(prime, power)] = pow(prime, power)
	return crt(crt_dict)


def get_weak_pohlig_hellman(complexity):
	while True:
		pub, priv = gen_keys(complexity)
		p, g, h = pub
		x = pohlig_hellman_attack(h, g, p)
		if not (x is None) and (x == priv[2]):
			break
	return h, x, g, p 

def f(h, p, a, h_i, deg_a, deg_h):
	option = h_i % 3
	q = (p - 1) // 2
	if option == 2:
		return (h_i * h_i) % p , (2 * deg_a) % q , (2 * deg_h) % q  
	if option == 1:
		return (a * h_i) % p , (deg_a + 1) % q , deg_h 
	return (h * h_i) % p, deg_a, (deg_h + 1) % q
		
def v(i):
	return max([j for j in range(int(np.log2(i)) + 1) if (i % (2 ** j)) == 0])

def pollard_rho(h, g, p):
	T = {}
	T[0] = [h, 0, 1]
	h_i, deg_a, deg_h = h, 0, 1 
	h_i_, deg_a_, deg_h_ = h, 0, 1 
	for i in range(1, p):
		h_i, deg_a, deg_h = f(h, p, g, h_i, deg_a, deg_h)
		h_i_, deg_a_, deg_h_ = f(h, p, g, h_i_, deg_a_, deg_h_)
		h_i_, deg_a_, deg_h_ = f(h, p, g, h_i_, deg_a_, deg_h_)
		#print(h_i, deg_a, deg_h)
		#print(h_i_, deg_a_, deg_h_)
		#print(h_i, h_i_)
		if h_i == h_i_:
			dx = (deg_a - deg_a_)
		#	dx = dx if dx >= 0 else dx + p
			dy = (deg_h_ - deg_h)
		#	dy = dy if dy >= 0 else dy + p
			inv_dy = ext_euc(dy, (p-1)//2)[1]
		#	inv_dy = inv_dy if inv_dy >= 0 else inv_dy + p
		#	print(dx, inv_dy, dy, p, 'p')
			res = (dx * inv_dy) % ((p-1)//2)
			return res if res >= 0 else res #+ (p-1)//2
		else:
			continue
			
		#print(h_i, deg_a, deg_h)
		for k in T.keys():
			if T[k][0] == h_i:
				dx = (deg_a - T[k][1])
				#dx = dx if dx >= 0 else dx + p
				dy = (T[k][2] - deg_h) 
				#dy = dy if dy >= 0 else dy + p
				inv_dy = ext_euc(dy, (p-1)//2)[1]
				#inv_dy = inv_dy if inv_dy >= 0 else inv_dy + p
				#print(dx, inv_dy, dy, p, 'p')
				res = (dx * inv_dy) % ((p-1)//2)
				return res + ((p-1)//2)if res <= 0 else res
		T[v(i)] = [h_i, deg_a, deg_h]
	return None
			
	

def signal_handler(signum, frame):
	raise Exception("Timed out!")

def gen_report(results, name):
	with open(name, 'w') as f:
		for k in results.keys():
			res = results[k]
			if k == 'Baby_step_giant_step':
				f.write("Атака Больших-малых шагов. Результат {}. Время работы {} ms.\n".format(res[0], res[1]))
			elif k == 'Pohlig_Hellman':
				f.write("Атака Поллига-Хеллмена. Результат {}. Время работы {} ms.\n".format(res[0], res[1]))	
			elif k == 'Pollard_rho':
				f.write("Атака rho Полларда. Результат {}. Время работы {} ms.\n".format(res[0], res[1]))		



if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Process e and N.')
	parser.add_argument('--h', type=int)
	parser.add_argument('--g', type=int)
	parser.add_argument('--p', type=int)
	parser.add_argument('--attack_time', type=int, default=1, help='Time for one attack in minutes.')
	parser.add_argument('--out_file', type=str, default='report.txt', help='Name for attack report.')
	parser.add_argument('--test_regime', action='store_true', default=False, help='Enable testing regime.')
	parser.add_argument('--complexity', type=int, action='store', default=100, help='Set task complexity for test regime.')
	args = parser.parse_args()
	attacks = [bsg_attack,
		pohlig_hellman_attack,
		pollard_rho]
	names = ('Baby_step_giant_step', 
		'Pohlig_Hellman',
		'Pollard_rho')
	if not args.test_regime:
		res = dict(zip(names, [[],[],[],]))
		for a, n in zip(attacks, names):
			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(60 * args.attack_time)
			status = None
			t = time.time()
			try:
			#if True:
				status = a(args.h, args.g, args.p)
				t = round((time.time() - t) * 1000, 2)
			except:
				print('Time out.')
				res[n] += ["Время вышло", t, status]
				continue
			if status is None:
				print('Fail.')
				res[n] += ['Провал', t, status]
			else:
				print('Success.')
				print(status)
				res[n] += ['Успех', t, status]
		gen_report(res, args.out_file)
	else:
		k = 10
		success = False
		for _ in range(k):
			signal.signal(signal.SIGALRM, signal_handler)
			signal.alarm(60 * args.attack_time // k)
			try:
				h, x, g, p = get_weak_pohlig_hellman(args.complexity)
				print('Weak Pohlig-Hellman attack key')
				print('h={}'.format(h))
				print('x={}'.format(x))
				print('g={}'.format(g))
				print('p={}'.format(p))
			except:
				continue
			success = True
			break
		if not success:
			print('Время вышло! Ключи не найдены.')
