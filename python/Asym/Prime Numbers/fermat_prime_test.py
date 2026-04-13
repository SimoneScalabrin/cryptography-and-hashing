import random

def is_prime(num, k=10):
    
    if n <=1:
        return False
    
    for _ in range(k):
        
        a = random.randint(2, num-2)
        # a^n-1 mod n
        x = pow(a, num-1, num)
        if x != 1:
            return False
    
    return True