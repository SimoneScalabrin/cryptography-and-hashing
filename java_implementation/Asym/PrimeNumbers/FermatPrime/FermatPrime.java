package PrimeNumbers.FermatPrime;

/**
 * Demonstrates the Fermat probabilistic primality test implemented in
 * {@link FermatPrimeTest}.
 *
 * <p>Covers edge cases, small numbers, large numbers relevant to RSA key
 * generation, Carmichael numbers (known false positives), and the effect
 * of increasing the number of witness rounds {@code k}.</p>
 */
public class FermatPrime {

    public static void main(String[] args) {
        FermatPrimeTest fermat = new FermatPrimeTest();

        // --- Edge cases ---
        System.out.println("=== Edge Cases ===");
        long[] edgeCases = {0, 1, 2, 3, 4};
        for (long n : edgeCases) {
            System.out.printf("isPrime(%2d) -> %b%n", n, fermat.isPrime(n));
        }

        // --- Small numbers: mix of primes and composites ---
        System.out.println("\n=== Small Numbers ===");
        long[] small = {5, 10, 11, 13, 15, 17, 18, 19, 20, 23, 25};
        for (long n : small) {
            System.out.printf("isPrime(%2d) -> %b%n", n, fermat.isPrime(n));
        }

        // --- All primes in [2, 50] ---
        System.out.println("\n=== Primes in range [2, 50] ===");
        StringBuilder primes = new StringBuilder();
        for (long n = 2; n <= 50; n++) {
            if (fermat.isPrime(n)) {
                primes.append(n).append(" ");
            }
        }
        System.out.println(primes.toString().trim());

        // --- Larger numbers (relevant to RSA key generation) ---
        System.out.println("\n=== Larger Numbers (relevant to RSA key generation) ===");
        long[] large = {97L, 100L, 7919L, 7920L, 104729L, 104730L};
        for (long n : large) {
            System.out.printf("isPrime(%7d) -> %b%n", n, fermat.isPrime(n));
        }

        // --- Carmichael numbers: composites that fool the Fermat test ---
        System.out.println("\n=== Carmichael Numbers (known false positives) ===");
        long[] carmichael = {561L, 1105L, 1729L, 2465L, 8911L};
        for (long n : carmichael) {
            boolean result = fermat.isPrime(n);
            System.out.printf("isPrime(%5d) -> %b  (composite, but Fermat may say prime!)%n",
                    n, result);
        }

        // --- Effect of increasing k on a pseudo-prime composite ---
        System.out.println("\n=== Effect of increasing k (witness rounds) ===");
        // 341 = 11 × 31, a base-2 Fermat pseudo-prime
        long composite = 341L;
        int trials = 100;
        for (int k : new int[]{1, 5, 10, 20}) {
            int falsePositives = 0;
            for (int t = 0; t < trials; t++) {
                if (fermat.isPrime(composite, k)) falsePositives++;
            }
            System.out.printf("  k=%2d | false positives in %d trials: %d%n",
                    k, trials, falsePositives);
        }
    }
}
