

# Recursive implementation of Euclidean Algorithm to find GCD of two numbers
def gcd(a, b):
    
    # Base case: if b is 0, GCD is a
    if a % b == 0:
        return b
    
    # Recursive case: GCD of b and the remainder of a divided by b
    return gcd(b, a % b)

def gcd_iterative(a, b):
    
    while a % b != 0:
        a, b = b, a % b
        
    return b


# Example usage
if __name__ == "__main__":
    num1 = 48
    num2 = 18
    print(f"The GCD of {num1} and {num2} is: {gcd(num1, num2)}")
    
    print(f"The GCD of {num1} and {num2} using iterative method is: {gcd_iterative(num1, num2)}")