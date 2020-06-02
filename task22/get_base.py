import numpy as np
import tqdm
bits = 20

primes = [2, 3, 5]

for i in tqdm.tqdm(range(7, 2 ** bits, 2)):
	is_prime = True
	for pr in primes[1:]:
		if i % pr == 0:
			is_prime = False
			break
	if is_prime:
		primes += [i]
print('Total primes:', len(primes))
np.save('primes', np.array(primes, dtype=np.uint32))	
