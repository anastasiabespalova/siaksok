import random
import numpy as np
import base64
import argparse
import json

def ext_euc(a, b):
	if a == 0:
		return b, 0, 1
	else:
		g, y, x = ext_euc(b % a, a)
	return g, x - (b // a) * y, y

def encode_text(pswd):
        if len(pswd) > 20:
                raise Exception('Password length > 30 symbols.')
        p_bytes = pswd.encode('utf-8')
        return int.from_bytes(p_bytes, 'little')

def decode_text(p_int):
        p_bytes = p_int.to_bytes((p_int.bit_length() + 7) // 8, 'little')
        return  p_bytes.decode('utf-8')

def gen_keys(bits, n, gain=None):
	# private
	if gain is None:
		gain = random.randint(2 ** (bits - 1), 2 ** bits)
	u = []
	cur_sum = 0
	for _ in range(n):
		u_i = random.randint(cur_sum + 1, cur_sum + gain)
		u += [u_i]
		cur_sum += (u_i + 1)

	# modulo
	N = random.randint(cur_sum + 1, cur_sum + gain)
	# multiplyer
	a = random.randint(2, N - 1)
	while ext_euc(a, N)[0] != 1:
		a = random.randint(2, N - 1)

	# public
	w = []
	a_ = ext_euc(a, N)[1]
	for u_i in u:
		w += [(a_ * u_i) % N]

	pub_k = w
	priv_k = (u, a, N)

	return pub_k, priv_k

def cipher(text, pub_k):
	w = pub_k
	i_text = encode_text(text)
	b_text = "{:b}".format(i_text)[::-1]
	cs = []
	for i in range(len(b_text) // len(w) + int((len(b_text) % len(w)) > 0)):
		c = 0
		sub_b = b_text[i * len(w): (i + 1) * len(w)][::-1]
		for j in range(len(sub_b)):
			c += int(sub_b[j]) * w[j + len(w) - len(sub_b)]
		cs.append(c)
	return cs[::-1]

def get_solution(u, c):
	k = len(u) - 1
	res = ['0'] * len(u)
	while k >= 0:
		if c >= u[k]:
			res[k] = '1'
		else:
			res[k] = '0'
		c -= int(res[k]) * u[k]
		k -= 1
	if c == 0:
		sol = ''
		for r in res:
			sol += r
		return sol
	return None
			

def decipher(c_text, priv_k):
	u, a, N = priv_k
	res = ''
	text = ''
	for c in c_text:
		s = (a * c) % N
		m = get_solution(u, s)
		res += m
	text = decode_text(int(res, base=2))
	return text

def gram_schmidt(bs):
	bs_ = []
	bs_.append(bs[0])
	for b in bs[1:]:
		b_ = b.copy()
		for b__ in bs_:
			b_ -= b__ * (b.dot(b__) / b__.dot(b__))
		bs_.append(b_)
	return bs_

def lll_attack(c, w):
	delta = 3 / 4
	# get bs
	bs = []
	for i, w_i in enumerate(w):
		b_i = np.zeros(len(w) + 1)
		b_i[i] = 1
		b_i[-1] = -w_i
		bs.append(b_i)
	b_i = np.zeros(len(w) + 1)
	b_i[-1] = c
	bs.append(b_i)
	#bs_ = gram_schmidt(bs)
	
	#update b
	while True:
		bs_ = gram_schmidt(bs)
		for i in range(1, len(bs)):
			for j in range(i - 1, -1, -1):
				c = round(bs[i].dot(bs_[j]) / bs_[j].dot(bs_[j]))
				bs[i] -= c * bs[j]
		restart = False
		for i in range(len(bs) - 1):
			mu = bs[i+1].dot(bs_[i]) / bs_[i].dot(bs_[i])
			b_ = mu * bs_[i] + bs_[i+1]
			if delta * bs_[i].dot(bs_[i]) > b_.dot(b_):
				b_ = bs[i]
				bs[i] = bs[i+1].copy()
				bs[i+1] = b_.copy()
				restart = True
				break
		if not restart:
			break
	return bs

def full_lll_attack(c, pub_k):
	b_text = ''
	for c_i in c:
		bs = lll_attack(c_i, pub_k)
		res = None
		for b in bs:
			if ((b == 1.0).sum() + (b == 0.0).sum()) == len(b):
				res = b[:-1]
				break
		if res is None:
			raise Exception('Attack fail')
		for r in res:
			b_text += str(int(r))
	text = decode_text(int(b_text, base=2))
	return text

def write_file(s, name):
	with open(name, 'wb') as f:
		f.write(s)

def read_file(name):
	with open(name, 'rb') as f:
		for s in f:
			return s
			
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--regime', type=str, help='[generate, cypher, hack, interactive]', default='generate')
	parser.add_argument('--key_pub_file', type=str, default='MH_PUB_KEY.json')
	parser.add_argument('--key_priv_file', type=str, default='MH_PRIV_KEY.json')
	parser.add_argument('--text', type=str, default='Hello world!')
	parser.add_argument('--complexity', type=int, default=10)
	parser.add_argument('--bits', type=int, default=10)
	parser.add_argument('--cypher_file', type=str, default='cyphered_text.txt')
	args = parser.parse_args()


if args.regime == 'interactive':
	print('Enter regime [generate, cypher, hack]:')
	reg = input()
	args.regime = reg

	print('Enter public key filename (default is {})'.format(parser.get_default('key_pub_file')))
	inp = input()
	inp = inp if inp != '' else parser.get_default('key_pub_file')
	args.key_pub_file = inp

	if reg == 'generate':
		print('Enter private key filename (default is {})'.format(parser.get_default('key_priv_file')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('key_priv_file')
		args.key_priv_file = inp

		
		print('Enter complexity value (default is {})'.format(parser.get_default('complexity')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('complexity')
		args.complexity = int(inp)

		print('Enter bits value (default is {})'.format(parser.get_default('bits')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('bits')
		args.bits = int(inp)

	elif reg == 'cypher':
		print('Enter text to be cyphered (default is {})'.format(parser.get_default('text')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('text')
		args.text = inp

		print('Enter out file name for cyphered text (default is {})'.format(parser.get_default('cypher_file')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('cypher_file')
		args.cyphered_file = inp
	elif reg == 'hack':
		print('Enter input file name containing cyphered text (default is {})'.format(parser.get_default('cypher_file')))
		inp = input()
		inp = inp if inp != '' else parser.get_default('cypher_file')
		args.cyphered_file = inp
	else:
		raise Exception('Invalid regime!')
	
if args.regime == 'generate':
	pub_k, priv_k = gen_keys(args.bits, args.complexity)
	with open(args.key_pub_file, 'w') as out_file:
		json.dump(pub_k, out_file)
	with open(args.key_priv_file, 'w') as out_file:
		json.dump(priv_k, out_file)
elif args.regime == 'cypher':
	with open(args.key_pub_file, 'r') as inp_file:
		pub_k = json.load(inp_file)
	c = cipher(args.text, pub_k)
	c_str = ''
	for c_i in c:
		c_str += str(c_i) + ' '
	c_str = bytes(c_str[:-1], 'utf-8')
	b32_c_str = base64.b32encode(c_str)
	write_file(b32_c_str, args.cypher_file)
elif args.regime == 'hack':
	with open(args.key_pub_file, 'r') as inp_file:
		pub_k = json.load(inp_file)
	b32_c_str = read_file(args.cypher_file)
	c_str = str(base64.b32decode(b32_c_str), 'utf-8')
	c = [int(c_i) for c_i in c_str.split()]
	print('Deciphered message:')
	print(full_lll_attack(c, pub_k))
	#print(decipher(c, priv_k))
else:
	raise Exception('Invalid regime!')
