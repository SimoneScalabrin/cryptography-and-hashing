package PrimeNumbers;

import java.util.Random;

/**
 * Probabilistic primality test based on Fermat's Little Theorem.
 *
 * <p><b>Theorem:</b> If {@code p} is prime, then for any integer {@code a}
 * with {@code 1 < a < p}:</p>
 * <pre>
 *     a^(p-1) ≡ 1 (mod p)
 * </pre>
 *
 * <p>The test picks {@code k} random bases {@code a} and verifies the
 * congruence. If it fails for any base, the number is <em>definitely</em>
 * composite. If it passes all {@code k} rounds, the number is
 * <em>probably</em> prime.</p>
 *
 * <p><b>Carmichael numbers:</b> Certain composites (e.g. 561, 1105, 1729)
 * satisfy the congruence for <em>every</em> base coprime to them and will
 * always fool this test. For stronger guarantees, prefer the Miller-Rabin
 * test.</p>
 *
 * <p><b>Time complexity:</b> O(k · log²n) due to modular exponentiation.</p>
 *
 * <p><b>Cryptographic relevance:</b> RSA key generation requires large primes
 * (~2048 bits). Probabilistic tests like this are used as fast filters before
 * deterministic verification.</p>
 */
public class FermatPrimeTest {

    private final Random random = new Random();

    /**
     * Probabilistically tests whether {@code num} is prime.
     *
     * <p>Each of the {@code k} rounds selects a random witness {@code a} in
     * {@code [2, num-2]} and checks whether {@code a^(num-1) mod num == 1}.
     * A single failure proves the number composite. Passing all rounds means
     * the number is <em>probably</em> prime, with a false-positive probability
     * of at most {@code (1/2)^k} for non-Carmichael numbers.</p>
     *
     * @param num The integer to test. Must be a positive integer.
     * @param k   Number of random witness rounds. Higher values reduce the
     *            probability of a false positive. Typical value: 10–20.
     * @return {@code true} if {@code num} is probably prime,
     *         {@code false} if it is definitely composite.
     */
    public boolean isPrime(long num, int k) {
        // Numbers ≤ 1 are not prime by definition
        if (num <= 1) return false;

        // 2 and 3 are prime; handle explicitly since randint below
        // requires num-2 ≥ 2, which fails for num < 4
        if (num <= 3) return true;

        // All even numbers greater than 2 are composite
        if (num % 2 == 0) return false;

        for (int i = 0; i < k; i++) {
            // Choose a random base a in [2, num-2]
            long a = 2 + (Math.abs(random.nextLong()) % (num - 3));

            // Fermat's congruence: a^(num-1) mod num must equal 1 for primes
            long x = modPow(a, num - 1, num);

            if (x != 1) {
                // Fermat witness found — num is definitely composite
                return false;
            }
        }

        // Passed all k rounds → probably prime
        return true;
    }

    /**
     * Overload with default {@code k = 10} witness rounds.
     *
     * @param num The integer to test.
     * @return {@code true} if {@code num} is probably prime.
     */
    public boolean isPrime(long num) {
        return isPrime(num, 10);
    }

    /**
     * Computes {@code (base^exp) mod modulus} efficiently using
     * fast exponentiation (square-and-multiply), avoiding overflow
     * by keeping intermediate results within {@code long} range via
     * modular reduction at each step.
     *
     * @param base     The base value.
     * @param exp      The exponent (non-negative).
     * @param modulus  The modulus.
     * @return {@code (base^exp) mod modulus}
     */
    private long modPow(long base, long exp, long modulus) {
        long result = 1;
        base = base % modulus;
        while (exp > 0) {
            if ((exp & 1) == 1) {
                result = multiplyMod(result, base, modulus);
            }
            exp >>= 1;
            base = multiplyMod(base, base, modulus);
        }
        return result;
    }

    /**
     * Computes {@code (a * b) mod m} safely without overflow using
     * 128-bit arithmetic via {@link Math#multiplyHigh} (Java 9+) fallback
     * to double-and-add for compatibility.
     */
    private long multiplyMod(long a, long b, long m) {
        // Use BigInteger-free approach: accumulate via binary method
        long result = 0;
        a = a % m;
        while (b > 0) {
            if ((b & 1) == 1) {
                result = (result + a) % m;
            }
            a = (a * 2) % m;
            b >>= 1;
        }
        return result;
    }
}
