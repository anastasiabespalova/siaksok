import argparse
from rsa import gen_keys, code_rsa 
import base64
import hashlib
from rabin import encode_rabin, decode_rabin, get_rabin_key
import sys
import os

M1 = '98765'
M2 = '43210'

def write_file(s, name):
	with open(name, 'wb') as f:
		f.write(s)

def read_file(name):
	with open(name, 'rb') as f:
		for s in f:
			return s

def read_passwords(file_name):
	pswds = []
	if (file_name is None) or not os.path.exists(file_name):
		return pswds
	with open(file_name, 'r') as f:
		for s in f:
			pswds += [s.split()[1:]]
	return pswds
	
def add_password(file_name, pswd, info):
	pswds = read_passwords(file_name)
	pswds += [(pswd, info)]
	with open(file_name, 'w') as f:
		for i, p in enumerate(pswds):
			f.write('{}. {} {}\n'.format(i + 1, p[0], p[1]))

def encode_pswd(pswd):
	if len(pswd) > 20:
		raise Exception('Password length > 30 symbols.')
	p_bytes = pswd.encode('utf-8')
	return int.from_bytes(p_bytes, 'little')

def decode_pswd(p_int):
	p_bytes = p_int.to_bytes((p_int.bit_length() + 7) // 8, 'little')
	return  p_bytes.decode('utf-8')

def xor(bs1, bs2):
	assert len(bs1) == len(bs2)
	res = b''
	for i in range(len(bs1)):
		res += bytes([bs1[i] ^ bs2[i]])
	return res

def bytes_to_int(bytes):
	result = 0
	for b in bytes:
		result = result * 256 + int(b)
	return result

def int_to_bytes(value):
	result = []
	val = value
	result.append(val & 0xff)
	while (val >> 8) > 0:
		val = val >> 8
		result.append(val & 0xff)
	res = b''
	for r in result[::-1]:
		res += bytes([r])
	return res

def register(pswd, pub_rsa, prv_rsa, pub_rabin, prv_rabin):
	pub_k, priv_k = gen_keys(512)
	pub_k_s = bytes(str(pub_k[0]) + ' ' + str(pub_k[1]), 'utf-8')
	b32_pub_k = base64.b32encode(pub_k_s)
	write_file(b32_pub_k, pub_rsa)

	priv_k_s = bytes(str(priv_k[0]) + ' ' + str(priv_k[1]), 'utf-8')
	m = hashlib.shake_128()
	m.update(bytes(pswd, 'utf-8'))
	h_pswd = m.digest(len(priv_k_s))
	priv_k_new = xor(h_pswd, priv_k_s)
	b32_priv_k = base64.b32encode(priv_k_new)
	write_file(b32_priv_k, prv_rsa)

	n, p, q = get_rabin_key(64)
	n_signed = int(M1 + str(n))
	c_n_signed = bytes(str(code_rsa(n_signed, priv_k[1], priv_k[0])), 'utf-8')
	b32_c_n_signed = base64.b32encode(c_n_signed)
	write_file(b32_c_n_signed, pub_rabin)

	i_pswd = encode_pswd(pswd)
	pq_signed = bytes_to_int(bytes(str(i_pswd) + str(p) + ' ' + str(q), 'utf-8'))
	c_pq_signed = bytes(str(code_rsa(pq_signed, pub_k[1], pub_k[0])), 'utf-8')
	b32_c_pq_signed = base64.b32encode(c_pq_signed)
	write_file(b32_c_pq_signed, prv_rabin)

def encode(pub_rabin, pub_rsa, password_local, pswd_file, info, verbose=True):
	if len(password_local) < 10:
		print('Password len should be greater than 10.')
		sys.exit()
	b32_c_n_signed = read_file(pub_rabin)
	c_n_signed = base64.b32decode(b32_c_n_signed)
	b32_pub_k = read_file(pub_rsa)
	pub_k_s = str(base64.b32decode(b32_pub_k), 'utf-8')
	try:
		N, e = pub_k_s.split()
		N = int(N)
		e = int(e)
		n_signed = code_rsa(int(str(c_n_signed, 'utf-8')), e, N)
		mark, n = str(n_signed)[:len(M1)], str(n_signed)[len(M1):]
		if mark != M1:
			raise Exception()
		pswd = password_local
		i_pswd = str(encode_pswd(pswd))
		signed_i_pswd = int(M2 + i_pswd)
		c_signed_i_pswd = encode_rabin(signed_i_pswd, int(n))
		if pswd_file:
			add_password(args.pswd_file, c_signed_i_pswd, info)
		else:
			if verbose:
				print('Your cyphered password:', c_signed_i_pswd)
		return c_signed_i_pswd
	except:
		print('Wrong public Rabin key or public RSA!')

def decode(password_global, password_local, prv_rsa, prv_rabin, pswd_file, pswd_num, verbose=True):
	pswd = password_global
	b32_priv_k = read_file(prv_rsa)
	priv_k_new = base64.b32decode(b32_priv_k)
	m = hashlib.shake_128()
	m.update(bytes(pswd, 'utf-8'))
	h_pswd = m.digest(len(priv_k_new))
	priv_k = xor(h_pswd, priv_k_new)
	try:
		N, d = str(priv_k, 'utf-8').split()
		N = int(N)
		d = int(d)
		b32_c_pq_signed = read_file(prv_rabin)
		c_pq_signed = base64.b32decode(b32_c_pq_signed)
		pq_signed = code_rsa(int(str(c_pq_signed, 'utf-8')), d, N)
		i_pswd = str(encode_pswd(pswd))
		current_mark = str(int_to_bytes(pq_signed), 'utf-8')[:len(i_pswd)]
		p, q = str(int_to_bytes(pq_signed), 'utf-8')[len(i_pswd):].split(' ')
		if i_pswd != current_mark:
			raise Exception()
	except:
		print('Wrong global password!')
		sys.exit()
	if pswd_file:
		c_signed_i_pswd = int(read_passwords(pswd_file)[pswd_num - 1][0])
	else:
		c_signed_i_pswd = int(password_local)
	pswds = decode_rabin(c_signed_i_pswd, int(p), int(q))
	success = False
	for p in pswds:
		if str(p)[:len(M2)] == M2:
			success = True
			break
	if not success:
		prtin('Wrong rabin!')
		sys.exit()
	i_pswd = int(str(p)[len(M2):])
	pswd = decode_pswd(i_pswd)
	if verbose:
		print('Your decoded password:', pswd)
	return pswd

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--regime', type=str, help='[register, change_pswd, encode, decode]', default='register')
	parser.add_argument('--password_global', type=str, default=None)
	parser.add_argument('--password_local', type=str, default=None)
	parser.add_argument('--pub_rsa', type=str, default='public_RSA.txt')
	parser.add_argument('--prv_rsa', type=str, default='private_RSA.txt')
	parser.add_argument('--pub_rabin', type=str, default='public_Rabin.txt')
	parser.add_argument('--prv_rabin', type=str, default='private_Rabin.txt')
	parser.add_argument('--password_global_new', type=str, default=None)
	parser.add_argument('--pswd_file', type=str, default=None)
	parser.add_argument('--pswd_num', type=int, default=1)
	parser.add_argument('--info', type=str, default='No_info')
	args = parser.parse_args()	
	regimes = ['register',
		'change_pswd',
		'encode',
		'decode']
	if args.regime == 'register':
		pswd = args.password_global
		if len(args.password_global) < 10:
			print('Global password size shold be geater than 10')
			sys.exit()

		register(pswd, args.pub_rsa, args.prv_rsa, args.pub_rabin, args.prv_rabin)
	elif args.regime == 'change_pswd':
		if len(args.password_global_new) < 10:
			print('Global password size shold be geater than 10')
			sys.exit()

		if args.pswd_file:
			decoded_pswds = []
			pswds = read_passwords(args.pswd_file)
			for p in pswds:
				decoded_pswds.append(decode(args.password_global, p[0], args.prv_rsa, args.prv_rabin, None, args.pswd_num))
		pswd = args.password_global
		b32_priv_k = read_file(args.prv_rsa)
		priv_k_new = base64.b32decode(b32_priv_k)
		m = hashlib.shake_128()
		m.update(bytes(pswd, 'utf-8'))
		h_pswd = m.digest(len(priv_k_new))
		priv_k = xor(h_pswd, priv_k_new)
		try:
			N, d = str(priv_k, 'utf-8').split()
			N = int(N)
			d = int(d)
			b32_c_pq_signed = read_file(args.prv_rabin)
			c_pq_signed = base64.b32decode(b32_c_pq_signed)
			pq_signed = code_rsa(int(str(c_pq_signed, 'utf-8')), d, N)
			i_pswd = str(encode_pswd(pswd))
			current_mark = str(int_to_bytes(pq_signed), 'utf-8')[:len(i_pswd)]
			p, q = str(int_to_bytes(pq_signed), 'utf-8')[len(i_pswd):].split(' ')
			if i_pswd != current_mark:
				raise Exception()
		except:
			print('Wrong global password!')
			sys.exit()
		if args.password_global_new is None or len(args.password_global_new) < 10:
			print('Please, enter new password!')
			sys.exit()
		pswd = args.password_global
		if len(args.password_global) < 10:
			print('Global password size shold be geater than 10')
			sys.exit()
		b32_priv_k = read_file(args.prv_rsa)
		priv_k_new = base64.b32decode(b32_priv_k)
		m = hashlib.shake_128()
		m.update(bytes(pswd, 'utf-8'))
		h_pswd = m.digest(len(priv_k_new))
		priv_k = xor(h_pswd, priv_k_new)
		try:
			N, d = str(priv_k, 'utf-8').split()	
			N = int(N)
			d = int(d)
			b32_c_pq_signed = read_file(args.prv_rabin)
			c_pq_signed = base64.b32decode(b32_c_pq_signed)
			pq_signed = code_rsa(int(str(c_pq_signed, 'utf-8')), d, N)
			i_pswd = str(encode_pswd(pswd))
			current_mark = str(int_to_bytes(pq_signed), 'utf-8')[:len(i_pswd)]
			if i_pswd != current_mark:
				raise Exception()
			register(args.password_global_new, args.pub_rsa, args.prv_rsa, args.pub_rabin, args.prv_rabin)
		except:
			print('Wrong global password!')
		if args.pswd_file:
			i = 0
			os.remove(args.pswd_file)
			coded_pswds = []
			for p in decoded_pswds:
				coded_pswds.append(encode(args.pub_rabin, args.pub_rsa, p, args.pswd_file, info=pswds[i][1]))
				i += 1
	elif args.regime == 'encode':
		encode(args.pub_rabin, args.pub_rsa, args.password_local, args.pswd_file, info=args.info)
	elif args.regime == 'decode':
		decode(args.password_global, args.password_local, args.prv_rsa, args.prv_rabin, args.pswd_file, args.pswd_num)
	else:
		print('Please, enter valid regime!')
