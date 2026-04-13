package PrimeNumbers.Factorization;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility class for integer factorization.
 *
 * <p>Provides a method to find all divisors of a positive integer using an
 * O(√n) algorithm: iterate only up to √num, and for every divisor {@code i}
 * also record the paired divisor {@code num / i}.
 */
public class IntegerFactorization {

    /**
     * Returns all factors (divisors) of the given positive integer.
     *
     * <p>The algorithm runs in <b>O(√num)</b> time. It iterates {@code i} from
     * {@code 1} to {@code floor(√num)} inclusive. Whenever {@code i} divides
     * {@code num} evenly, both {@code i} and {@code num / i} are recorded as
     * divisors (unless they are equal, which happens when {@code num} is a
     * perfect square).
     *
     * @param num a positive integer to factorize (must be &gt;= 1)
     * @return an unsorted {@link List} of all divisors of {@code num},
     *         including {@code 1} and {@code num} itself
     * @throws IllegalArgumentException if {@code num} is less than 1
     * @see <a href="https://en.wikipedia.org/wiki/Divisor_function#Finding_all_divisors">Finding all divisors</a>
     */
    public static List<Long> getFactors(long num) {
        if (num < 1) {
            throw new IllegalArgumentException("num must be >= 1, got: " + num);
        }

        List<Long> factors = new ArrayList<>();

        // Iterate only up to floor(sqrt(num)) for O(sqrt(n)) performance
        long limit = (long) Math.floor(Math.sqrt(num));

        for (long i = 1; i <= limit; i++) {
            if (num % i == 0) {          // i is a divisor
                factors.add(i);
                // Avoid duplicating the square root (e.g. 6 for num = 36)
                if (i != num / i) {
                    factors.add(num / i);
                }
            }
        }

        return factors;
    }

    // -------------------------------------------------------------------------
    // Usage examples
    // -------------------------------------------------------------------------
    public static void main(String[] args) {

        // --- Small numbers ---
        System.out.println("=== Small numbers ===");
        long[] smallCases = {1, 7, 12, 36, 100};
        for (long n : smallCases) {
            List<Long> result = getFactors(n);
            Collections.sort(result);
            System.out.printf("Factors of %4d: %s%n", n, result);
        }

        // --- Large numbers ---
        System.out.println("\n=== Large numbers ===");
        Object[][] largeCases = {
            {1_000_000L,       "1 million (perfect square)"},
            {720_720L,         "720 720 (highly composite, 240 divisors)"},
            {8_589_934_592L,   "2^33"},
            {999_999_937L,     "large prime"},
            {123_456_789L,     "semi-prime: 3 x 41 152 263"},
        };

        for (Object[] tc : largeCases) {
            long n      = (long) tc[0];
            String desc = (String) tc[1];

            long start      = System.nanoTime();
            List<Long> result = getFactors(n);
            double ms       = (System.nanoTime() - start) / 1_000_000.0;

            System.out.printf("%s (%d)  ->  %d divisors  [%.2f ms]%n",
                    desc, n, result.size(), ms);
        }
    }
}
