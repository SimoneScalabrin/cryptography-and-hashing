package PrimeNumbers;

/**
 * Provides a naive (trial-division) primality test.
 *
 * <p>Algorithm overview:</p>
 * <ol>
 *   <li>Reject numbers less than 2 — they are not prime by definition.</li>
 *   <li>Accept 2 as the only even prime.</li>
 *   <li>Reject all other even numbers immediately.</li>
 *   <li>Test odd divisors from 3 up to √n (inclusive).
 *       If any divisor divides n evenly, n is composite.</li>
 * </ol>
 *
 * <p>Time complexity: O(√n) — efficient enough for small-to-medium integers,
 * but impractical for very large numbers used in asymmetric cryptography
 * (e.g., RSA), where probabilistic tests like Miller-Rabin are preferred.</p>
 */
public class NaivePrimeTest {

    /**
     * Determines whether the given integer is a prime number.
     *
     * @param n The integer to test. Must be a non-negative value.
     * @return {@code true} if {@code n} is prime, {@code false} otherwise.
     */
    public boolean isPrime(int n) {
        // Numbers less than 2 are not prime by definition
        if (n < 2) return false;

        // 2 is the only even prime number
        if (n == 2) return true;

        // All other even numbers are divisible by 2, hence not prime
        if (n % 2 == 0) return false;

        // Check odd divisors up to √n — if none divide n, it is prime
        for (int i = 3; i <= Math.sqrt(n); i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    }
}
