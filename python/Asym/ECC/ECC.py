import random

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return f"{self.x} - {self.y}"

class EllipticCurveCryptography:
    def __init__(self, a, b):
        # We are using a simple elliptic curve defined by the equation y^2 = x^3 + ax + b
        self.a = a
        self.b = b

    def add_points(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P.x, P.y
        x2, y2 = Q.x, Q.y

        if x1 == x2 and y1 != y2:
            # P and Q are inverses: P + (-P) = point at infinity
            return None

        if x1 == x2 and y1 == y2:
            # Point doubling
            m = (3 * x1**2 + self.a) / (2 * y1)
        else:
            # Point addition
            m = (y2 - y1) / (x2 - x1)

        # Calculate the resulting point R = P + Q
        x3 = m**2 - x1 - x2
        y3 = m * (x1 - x3) - y1

        return Point(x3, y3)

    # Implementing the double-and-add algorithm for scalar multiplication
    # O(n) time complexity, where n is the number of bits in the scalar
    def double_and_add(self, n, P):
        
        temp_point = Point(P.x, P.y)  # Start with the point P
        binary_n = bin(n)[3:]  # Convert n to binary

        for bit in binary_n:
            temp_point = self.add_points(temp_point, temp_point)  # Point doubling
            if bit == '1':
                temp_point = self.add_points(temp_point, P)  # Point addition

        return temp_point


if __name__ == "__main__":
    
    ecc = EllipticCurveCryptography(a=-2, b=2)
    
    generator_point = Point(-2, -1)
    print(ecc.add_points(generator_point, generator_point))  # Point doubling
    
    print(ecc.double_and_add(10, generator_point))  # Scalar multiplication
    
    A_random = random.randint(2, 10000)
    B_random = random.randint(2, 10000)
    
    # Public keys
    A_public = ecc.double_and_add(A_random, generator_point)
    B_public = ecc.double_and_add(B_random, generator_point)
    
    
    # Shared secrets
    A_secret_key = ecc.double_and_add(A_random, B_public)
    B_secret_key = ecc.double_and_add(B_random, A_public)
    
    print("A's secret key:", A_secret_key)
    print("B's secret key:", B_secret_key)
    print("Shared secret keys match:", A_secret_key.x == B_secret_key.x and A_secret_key.y == B_secret_key.y)