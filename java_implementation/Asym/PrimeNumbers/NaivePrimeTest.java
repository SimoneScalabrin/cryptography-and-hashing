package PrimeNumbers;

public class NaivePrimeTest {
    public boolean isPrime(int n) {
        
        if (n < 2) return false;

        if (n == 2) return true;

        if (n % 2 == 0) return false;


        for (int i = 3; i <= Math.floor(Math.sqrt(n)); i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    }
}
