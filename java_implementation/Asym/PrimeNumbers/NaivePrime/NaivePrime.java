package PrimeNumbers.NaivePrime;

/**
 * Demonstrates the naive primality test implemented in {@link NaivePrimeTest}.
 *
 * <p>Primality testing is a fundamental building block in asymmetric
 * cryptography. Algorithms such as RSA require large prime numbers to
 * generate public/private key pairs. This demo uses simple trial division
 * to illustrate the concept before introducing more advanced techniques.</p>
 */
public class NaivePrime {

    public static void main(String[] args) {
        NaivePrimeTest primeTest = new NaivePrimeTest();

        // --- Edge cases ---
        int[] edgeCases = {0, 1, 2, 3};
        System.out.println("=== Edge Cases ===");
        for (int n : edgeCases) {
            System.out.printf("isPrime(%2d) -> %b%n", n, primeTest.isPrime(n));
        }

        // --- Small primes and composites ---
        int[] samples = {4, 5, 10, 11, 13, 15, 17, 18, 19, 20};
        System.out.println("\n=== Small Numbers ===");
        for (int n : samples) {
            System.out.printf("isPrime(%2d) -> %b%n", n, primeTest.isPrime(n));
        }

        // --- Larger numbers (relevant to cryptographic key generation) ---
        int[] largeSamples = {97, 100, 7919, 7920, 104729};
        System.out.println("\n=== Larger Numbers ===");
        for (int n : largeSamples) {
            System.out.printf("isPrime(%6d) -> %b%n", n, primeTest.isPrime(n));
        }

        // --- Print all primes in a range (e.g., 2..50) ---
        System.out.println("\n=== Primes in range [2, 50] ===");
        StringBuilder primes = new StringBuilder();
        for (int n = 2; n <= 50; n++) {
            if (primeTest.isPrime(n)) {
                primes.append(n).append(" ");
            }
        }
        System.out.println(primes.toString().trim());
    }
}
