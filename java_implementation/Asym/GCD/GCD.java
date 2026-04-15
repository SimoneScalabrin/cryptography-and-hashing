package GCD;

/**
 * Euclidean Algorithm — Greatest Common Divisor (GCD)
 * =====================================================
 *
 * The Euclidean algorithm is one of the oldest known algorithms (c. 300 BC).
 * It computes the greatest common divisor (GCD) of two non-negative integers,
 * i.e. the largest integer that divides both without a remainder.
 *
 * <p>Mathematical basis:
 * <pre>
 *   gcd(a, 0) = a
 *   gcd(a, b) = gcd(b, a mod b)   for b &gt; 0
 * </pre>
 *
 * <p>Time complexity:  O(log(min(a, b)))<br>
 * Space complexity: O(log(min(a, b))) recursive / O(1) iterative
 *
 * <p>Relevance in cryptography:
 * <ul>
 *   <li>RSA key generation (checking that e and φ(n) are coprime)</li>
 *   <li>Extended Euclidean Algorithm (modular inverse, used in RSA decryption)</li>
 *   <li>Diffie-Hellman and other number-theory-based protocols</li>
 * </ul>
 */
public class GCD {

    /**
     * Returns the GCD of {@code a} and {@code b} using the recursive Euclidean algorithm.
     *
     * @param a a non-negative integer
     * @param b a non-negative integer
     * @return the greatest common divisor of a and b
     * @throws IllegalArgumentException if both a and b are zero (GCD is undefined)
     */
    public static long gcd(long a, long b) {
        a = Math.abs(a);
        b = Math.abs(b);
        if (a == 0 && b == 0) throw new IllegalArgumentException("gcd(0, 0) is undefined");
        if (b == 0) return a;
        return gcd(b, a % b);
    }

    /**
     * Returns the GCD of {@code a} and {@code b} using the iterative Euclidean algorithm.
     *
     * <p>Preferred over the recursive version for large inputs (no stack overhead).
     *
     * @param a a non-negative integer
     * @param b a non-negative integer
     * @return the greatest common divisor of a and b
     * @throws IllegalArgumentException if both a and b are zero (GCD is undefined)
     */
    public static long gcdIterative(long a, long b) {
        a = Math.abs(a);
        b = Math.abs(b);
        if (a == 0 && b == 0) throw new IllegalArgumentException("gcd(0, 0) is undefined");
        while (b != 0) {
            long temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    /**
     * Result holder for the Extended Euclidean Algorithm.
     *
     * <p>Holds {@code gcd}, {@code x}, and {@code y} such that
     * {@code a*x + b*y == gcd} (Bézout's identity).
     */
    public record ExtendedGcdResult(long gcd, long x, long y) {}

    /**
     * Returns {@code (gcd, x, y)} such that {@code a*x + b*y == gcd} (Bézout's identity).
     *
     * <p>The extended Euclidean algorithm not only finds the GCD but also the
     * Bézout coefficients {@code x} and {@code y}, which are used to compute
     * modular inverses — a fundamental operation in RSA and other public-key
     * cryptosystems.
     *
     * @param a an integer
     * @param b an integer
     * @return an {@link ExtendedGcdResult} with fields gcd, x, y
     */
    public static ExtendedGcdResult extendedGcd(long a, long b) {
        if (b == 0) return new ExtendedGcdResult(a, 1, 0);
        ExtendedGcdResult r = extendedGcd(b, a % b);
        return new ExtendedGcdResult(r.gcd(), r.y(), r.x() - (a / b) * r.y());
    }

    /**
     * Returns {@code true} if {@code a} and {@code b} are coprime (gcd == 1).
     *
     * <p>Two numbers are coprime when they share no common factor other than 1.
     * This check is used in RSA to verify that the public exponent e is valid
     * with respect to φ(n).
     *
     * @param a an integer
     * @param b an integer
     * @return {@code true} if gcd(a, b) == 1
     */
    public static boolean areCoprime(long a, long b) {
        return gcdIterative(a, b) == 1;
    }

    // -----------------------------------------------------------------------
    // Example usage
    // -----------------------------------------------------------------------
    public static void main(String[] args) {
        long[][] examples = {
            {48, 18},
            {100, 75},
            {0, 7},
            {561, 0},
            {1071, 462},  // classic textbook example
            {-56, 98},    // negative numbers
            {14, 15},     // consecutive integers → always coprime
            {3, 11},      // two distinct primes → always coprime
            {35, 64},     // no common factors → coprime
        };

        System.out.println("=".repeat(60));
        System.out.printf("%60s%n", "Euclidean Algorithm — GCD examples");
        System.out.println("=".repeat(60));

        for (long[] pair : examples) {
            long a = pair[0], b = pair[1];
            long rec = gcd(a, b);
            long it  = gcdIterative(a, b);
            String coprime = areCoprime(a, b) ? "true" : "false";
            System.out.printf("  gcd(%5d, %5d)  →  recursive=%-3d  iterative=%-3d  coprime=%s%n",
                    a, b, rec, it, coprime);
        }

        System.out.println();
        System.out.println("Extended Euclidean Algorithm — Bézout coefficients:");
        System.out.println("-".repeat(60));
        long[][] extExamples = {{35, 15}, {3, 11}, {1071, 462}};
        for (long[] pair : extExamples) {
            long a = pair[0], b = pair[1];
            ExtendedGcdResult r = extendedGcd(a, b);
            System.out.printf("  extendedGcd(%d, %d)  →  gcd=%d,  %d*(%d) + %d*(%d) = %d%n",
                    a, b, r.gcd(), a, r.x(), b, r.y(), a * r.x() + b * r.y());
        }

        System.out.println();
        System.out.println("Modular inverse via extended GCD (used in RSA):");
        System.out.println("-".repeat(60));
        // Toy RSA example: p=5, q=11 → n=55, φ(n)=40, e=3
        long e = 3, phi = 40;
        ExtendedGcdResult r = extendedGcd(e, phi);
        if (r.gcd() == 1) {
            long d = ((r.x() % phi) + phi) % phi;
            System.out.printf("  Modular inverse of %d mod %d  →  d = %d  (check: %d*%d mod %d = %d)%n",
                    e, phi, d, e, d, phi, (e * d) % phi);
        }
    }
}

