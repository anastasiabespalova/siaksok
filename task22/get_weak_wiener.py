from rsa import generate_two_random_primes
from utils import ext_euc
import random
from attacks import wiener

def get_weak_wiener(bits):
    p, q = generate_two_random_primes(bits)
    N = p * q
    etf = (p - 1) * (q - 1)
        
    while True:
        d = abs(random.getrandbits(bits // 2))
        e = ext_euc(d, etf)[1]
        if (ext_euc(d, etf)[0] == 1) and (9 * pow(d, 4) < N) and (e > 0):
            if wiener(e, N)[0]:
                break
    return e, N, d
