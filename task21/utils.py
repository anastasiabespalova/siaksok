import random

def ext_euc(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = ext_euc(b % a, a)
        return g, x - (b // a) * y, y

def miller_rabin_test(d, n): 
    a = 2 + random.randint(1, n - 4) 
    x = pow(a, d, n)
    if (x == 1 or x == n - 1): 
        return True
  
    while d != (n - 1): 
        x = (x ** 2) % n 
        d *= 2
        if x == 1: 
            return False 
        if x == (n - 1): 
            return True
    return False
  
def is_prime(n, k): 
    if (n <= 1) or (n == 4): 
        return False
    if n <= 3: 
        return True 
  
    d = n - 1
    while (d % 2) == 0: 
        d //= 2
    for i in range(k): 
        if not miller_rabin_test(d, n): 
            return False
    return True
