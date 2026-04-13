package DiscreteLogarithm;

import java.math.BigInteger;
import java.util.Random;

// =============================================================================
// TRAPDOOR FUNCTION — The Discrete Logarithm Problem
// =============================================================================
//
// A *trapdoor function* is easy to compute in one direction but computationally
// infeasible to reverse without secret information.
//
// The discrete logarithm is the trapdoor at the heart of Diffie-Hellman (DH):
//
//   EASY  →  given (base, exponent, modulus), compute:  result = base^exponent mod modulus
//   HARD  ←  given (base, result,   modulus), find:     exponent such that base^exponent ≡ result (mod modulus)
//
// With a large prime modulus (e.g. 2048 bits) no efficient general algorithm
// is known, making reversal computationally infeasible.
// =============================================================================

public class DiscreteLogarithm {

    // -------------------------------------------------------------------------
    // modularExponentiation
    // -------------------------------------------------------------------------

    /**
     * Computes {@code base^exponent mod modulus} using fast modular exponentiation.
     *
     * <p>Delegates to {@link BigInteger#modPow(BigInteger, BigInteger)}, which
     * uses the <em>square-and-multiply</em> algorithm and runs in
     * <b>O(log exponent)</b> multiplications — efficient even for cryptographically
     * large numbers (thousands of bits).
     *
     * <p>This is the <b>EASY</b> direction of the trapdoor: given the exponent,
     * the result can be computed in microseconds regardless of the size of the modulus.
     *
     * @param base     the base g (generator / primitive root)
     * @param exponent the secret exponent x
     * @param modulus  a large prime p
     * @return {@code base^exponent mod modulus}
     *
     * <pre>
     * Examples:
     *   modularExponentiation(5, 3, 23)         → 10   // 5^3=125, 125 mod 23=10
     *   modularExponentiation(2, 10, 1024)       → 0    // 2^10=1024 mod 1024=0
     *   modularExponentiation(3, 6, 7)           → 1    // 3^6=729 mod 7=1
     * </pre>
     */
    public static BigInteger modularExponentiation(BigInteger base,
                                                    BigInteger exponent,
                                                    BigInteger modulus) {
        // BigInteger.modPow is O(log exponent) via square-and-multiply
        return base.modPow(exponent, modulus);
    }

    // -------------------------------------------------------------------------
    // discreteLogarithm
    // -------------------------------------------------------------------------

    /**
     * Solves the discrete logarithm problem by brute-force search.
     *
     * <p>Finds the smallest positive integer {@code x} such that:
     * <pre>    base^x ≡ result  (mod modulus)</pre>
     *
     * <p>This is the <b>HARD</b> direction of the trapdoor. The brute-force
     * approach tries every exponent from 1 upward — <b>O(modulus)</b> in the
     * worst case. For a large prime p (e.g. 2048-bit) this is completely
     * infeasible.
     *
     * @param base    the generator g
     * @param result  the public value g^x mod p observed by an attacker
     * @param modulus the prime modulus p
     * @return the exponent x such that {@code base^x ≡ result (mod modulus)}
     *
     * <p><b>Note:</b> educational / demo use only. Practical only for small
     * moduli (p &lt; ~10^6). Real attacks (Baby-step Giant-step, Index calculus)
     * are faster but still infeasible for large primes.
     *
     * <pre>
     * Examples:
     *   discreteLogarithm(5, 10, 23)  → 3   // 5^3 mod 23 = 10
     *   discreteLogarithm(2,  9, 11)  → 6   // 2^6 mod 11 = 9
     * </pre>
     */
    public static BigInteger discreteLogarithm(BigInteger base,
                                                BigInteger result,
                                                BigInteger modulus) {
        BigInteger exponent = BigInteger.ONE;
        // Try every exponent until base^exponent mod modulus == result
        while (!base.modPow(exponent, modulus).equals(result)) {
            exponent = exponent.add(BigInteger.ONE);
        }
        return exponent;
    }

    // -------------------------------------------------------------------------
    // diffieHellman
    // -------------------------------------------------------------------------

    // Protocol:
    //   1. Alice picks secret a, computes A = g^a mod p  → sends A to Bob
    //   2. Bob   picks secret b, computes B = g^b mod p  → sends B to Alice
    //   3. Alice computes shared = B^a mod p = g^(ab) mod p
    //      Bob   computes shared = A^b mod p = g^(ab) mod p
    //   → Both arrive at the same shared secret!
    //
    // Eve sees (p, g, A, B) but cannot recover a, b, or the shared secret
    // without solving the discrete logarithm — infeasible for large p.

    /**
     * Simulates a full Diffie-Hellman key exchange between Alice and Bob.
     *
     * @param p public prime modulus
     * @param g public generator (primitive root modulo p)
     * @param a Alice's private secret exponent
     * @param b Bob's private secret exponent
     * @return array of four BigIntegers: {public_A, public_B, shared_A, shared_B}
     * @throws AssertionError if shared secrets do not match
     */
    public static BigInteger[] diffieHellman(BigInteger p, BigInteger g,
                                              BigInteger a, BigInteger b) {
        BigInteger publicA  = modularExponentiation(g, a, p);   // Alice → Bob  (public)
        BigInteger publicB  = modularExponentiation(g, b, p);   // Bob → Alice  (public)

        BigInteger sharedA  = modularExponentiation(publicB, a, p);  // Alice computes shared key
        BigInteger sharedB  = modularExponentiation(publicA, b, p);  // Bob   computes shared key

        if (!sharedA.equals(sharedB)) {
            throw new AssertionError("Key exchange failed — shared secrets differ!");
        }
        return new BigInteger[]{publicA, publicB, sharedA, sharedB};
    }

    // =========================================================================
    // main — usage examples
    // =========================================================================

    public static void main(String[] args) {

        // ---------------------------------------------------------------------
        // 1. Basic examples
        // ---------------------------------------------------------------------
        System.out.println("=== modularExponentiation ===");
        long[][] cases = {{5, 3, 23}, {2, 10, 1024}, {3, 6, 7}};
        for (long[] c : cases) {
            BigInteger res = modularExponentiation(
                    BigInteger.valueOf(c[0]),
                    BigInteger.valueOf(c[1]),
                    BigInteger.valueOf(c[2]));
            System.out.printf("  %d^%d mod %d = %s%n", c[0], c[1], c[2], res);
        }

        // ---------------------------------------------------------------------
        // 2. Trapdoor asymmetry — timing comparison across growing prime sizes
        //
        // For each prime p we run N_SAMPLES random secrets and average timings.
        // EASY stays O(log exponent); HARD is O(p) on average, so the ratio
        // grows linearly with p — exponentially with the bit-length of p.
        // ---------------------------------------------------------------------
        int N_SAMPLES = 10;

        // {prime p, generator g, label}
        long[][] testPrimes = {
            {23L,    5L, 0},   // labels handled separately
            {97L,    5L, 1},
            {509L,   2L, 2},
            {1009L,  7L, 3},
            {2039L,  7L, 4},
            {4093L,  2L, 5},
            {8191L,  7L, 6},
            {16381L, 7L, 7},
            {32749L, 6L, 8},
        };
        String[] labels = {
            "p=23    (~5 bits)",
            "p=97    (~7 bits)",
            "p=509   (~9 bits)",
            "p=1009  (~10 bits)",
            "p=2039  (~11 bits)",
            "p=4093  (~12 bits)",
            "p=8191  (~13 bits, Mersenne prime)",
            "p=16381 (~14 bits)",
            "p=32749 (~15 bits)",
        };

        System.out.printf("%n=== Trapdoor asymmetry — how the gap grows with prime size ===%n");
        System.out.printf("  (averaged over %d random secrets each)%n%n", N_SAMPLES);
        System.out.printf("  %-35s  %10s  %12s  %8s%n", "Prime", "Easy (µs)", "Hard (µs)", "Ratio");
        System.out.printf("  %-35s  %10s  %12s  %8s%n",
                "-".repeat(35), "-".repeat(10), "-".repeat(12), "-".repeat(8));

        Random rng = new Random(42);

        for (int idx = 0; idx < testPrimes.length; idx++) {
            long pLong = testPrimes[idx][0];
            long gLong = testPrimes[idx][1];
            BigInteger p = BigInteger.valueOf(pLong);
            BigInteger g = BigInteger.valueOf(gLong);

            double sumEasy = 0, sumHard = 0;

            for (int s = 0; s < N_SAMPLES; s++) {
                // Random secret in [2, p-2]
                long secretLong = 2 + (long)(rng.nextDouble() * (pLong - 3));
                BigInteger secret = BigInteger.valueOf(secretLong);

                // EASY: modular exponentiation — O(log secret)
                long t0 = System.nanoTime();
                BigInteger pub = modularExponentiation(g, secret, p);
                sumEasy += (System.nanoTime() - t0) / 1_000.0;

                // HARD: brute-force discrete log — O(p) worst case
                t0 = System.nanoTime();
                discreteLogarithm(g, pub, p);
                sumHard += (System.nanoTime() - t0) / 1_000.0;
            }

            double avgEasy = sumEasy / N_SAMPLES;
            double avgHard = sumHard / N_SAMPLES;
            double ratio   = avgEasy > 0 ? avgHard / avgEasy : Double.POSITIVE_INFINITY;

            System.out.printf("  %-35s  %10.2f  %12.2f  %7.0fx%n",
                    labels[idx], avgEasy, avgHard, ratio);
        }

        System.out.println();
        System.out.println("  Observation: Easy stays roughly constant (O(log e) is fast).");
        System.out.println("  Hard grows ~linearly with p — the ratio widens steadily.");
        System.out.println("  For a 2048-bit prime (~10^617) brute-force would take longer");
        System.out.println("  than the age of the universe, even on all computers on Earth.");

        // ---------------------------------------------------------------------
        // 3. Diffie-Hellman key exchange (RFC 3526 — 512-bit safe prime for demo)
        // ---------------------------------------------------------------------
        System.out.println("\n=== Diffie-Hellman Key Exchange ===");

        // 512-bit safe prime from RFC 3526 / IETF
        BigInteger p_dh = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
            "FFFFFFFFFFFFFFFF", 16);

        BigInteger g_dh = BigInteger.TWO;
        BigInteger aliceSecret = new BigInteger("123456789987654321");
        BigInteger bobSecret   = new BigInteger("987654321123456789");

        long t0 = System.nanoTime();
        BigInteger[] dh = diffieHellman(p_dh, g_dh, aliceSecret, bobSecret);
        double elapsedMs = (System.nanoTime() - t0) / 1_000_000.0;

        String pStr = p_dh.toString();
        System.out.printf("  Prime p   : %s...  (%d bits)%n", pStr.substring(0, 20), p_dh.bitLength());
        System.out.printf("  Generator : %s%n", g_dh);
        System.out.printf("  Alice private (a): %s%n", aliceSecret);
        System.out.printf("  Bob   private (b): %s%n", bobSecret);
        System.out.printf("  Alice public  (g^a mod p): %s...%n", dh[0].toString().substring(0, 20));
        System.out.printf("  Bob   public  (g^b mod p): %s...%n", dh[1].toString().substring(0, 20));
        System.out.printf("  Shared secret (Alice)    : %s...%n", dh[2].toString().substring(0, 20));
        System.out.printf("  Shared secret (Bob)      : %s...%n", dh[3].toString().substring(0, 20));
        System.out.printf("  Match: %b  — computed in %.2f ms%n", dh[2].equals(dh[3]), elapsedMs);
        System.out.println();
        System.out.println("  Eve sees p, g, public_A, public_B — to recover the shared secret");
        System.out.println("  she must solve the discrete log, which is computationally infeasible");
        System.out.printf("  for a %d-bit prime.%n", p_dh.bitLength());
    }
}

