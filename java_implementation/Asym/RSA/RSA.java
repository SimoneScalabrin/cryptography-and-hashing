package RSA;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * RSA — Rivest–Shamir–Adleman Asymmetric Encryption
 * ==================================================
 *
 * RSA is one of the first public-key cryptosystems (1977) and is still
 * widely used for secure data transmission, digital signatures, and key exchange.
 *
 * <p><b>How it works</b>
 * <ol>
 *   <li>Choose two distinct large primes p and q.</li>
 *   <li>Compute n = p * q  (public modulus).</li>
 *   <li>Compute φ(n) = (p-1)(q-1)  (Euler's totient).</li>
 *   <li>Choose e : 1 &lt; e &lt; φ(n),  gcd(e, φ(n)) = 1  (public exponent).</li>
 *   <li>Compute d ≡ e⁻¹ (mod φ(n))  (private exponent).</li>
 * </ol>
 *
 * <p>Encryption (public):   c = m^e mod n<br>
 * Decryption (private):   m = c^d mod n
 *
 * <p><b>⚠ Educational implementation.</b> Uses {@link BigInteger#probablePrime}
 * for key generation (safe for demos). Real production RSA uses 2048+ bit keys
 * and OAEP padding — see {@code RSA_AES.java} for the hybrid approach.
 */
public class RSA {

    private static final SecureRandom RNG = new SecureRandom();

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /**
     * Holds a generated RSA key pair together with its internal parameters.
     *
     * @param publicKey  (e, n)
     * @param privateKey (d, n)
     * @param p          prime factor p  ⚠ keep secret
     * @param q          prime factor q  ⚠ keep secret
     * @param phiN       Euler's totient ⚠ keep secret
     */
    public record KeyPair(
        BigInteger[] publicKey,
        BigInteger[] privateKey,
        BigInteger p,
        BigInteger q,
        BigInteger phiN
    ) {
        /** Returns the public exponent e. */
        public BigInteger e() { return publicKey[0]; }
        /** Returns the modulus n. */
        public BigInteger n() { return publicKey[1]; }
        /** Returns the private exponent d. */
        public BigInteger d() { return privateKey[0]; }
    }

    /**
     * Generates an RSA key pair using probable primes of {@code bitLength} bits each.
     *
     * <p>Steps:
     * <ol>
     *   <li>Sample two distinct probable primes p, q.</li>
     *   <li>n = p * q</li>
     *   <li>φ(n) = (p-1)(q-1)</li>
     *   <li>e = 65537 if gcd(65537, φ(n)) == 1, otherwise random.</li>
     *   <li>d = modular inverse of e mod φ(n).</li>
     * </ol>
     *
     * @param bitLength Number of bits for each prime (e.g. 512 for a 1024-bit key).
     * @return A {@link KeyPair} with all RSA parameters.
     */
    public static KeyPair generateKeyPair(int bitLength) {
        // Step 1 — two distinct probable primes
        BigInteger p = BigInteger.probablePrime(bitLength, RNG);
        BigInteger q = BigInteger.probablePrime(bitLength, RNG);
        while (q.equals(p)) {
            q = BigInteger.probablePrime(bitLength, RNG);
        }

        // Step 2 — modulus
        BigInteger n = p.multiply(q);

        // Step 3 — totient
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Step 4 — public exponent (prefer 65537, the standard choice)
        BigInteger e = BigInteger.valueOf(65537);
        if (!phiN.gcd(e).equals(BigInteger.ONE)) {
            do {
                e = BigInteger.probablePrime(bitLength / 2, RNG);
            } while (!phiN.gcd(e).equals(BigInteger.ONE));
        }

        // Step 5 — private exponent d = e⁻¹ mod φ(n)
        BigInteger d = e.modInverse(phiN);

        return new KeyPair(
            new BigInteger[]{e, n},
            new BigInteger[]{d, n},
            p, q, phiN
        );
    }

    // -----------------------------------------------------------------------
    // Encrypt / Decrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} character-by-character using the RSA public key.
     *
     * <p>Each character ordinal m must satisfy m &lt; n, otherwise a
     * {@link IllegalArgumentException} is thrown.
     *
     * @param plaintext The message to encrypt.
     * @param publicKey Array [e, n].
     * @return Array of BigIntegers (one per character).
     */
    public static BigInteger[] encrypt(String plaintext, BigInteger[] publicKey) {
        BigInteger e = publicKey[0];
        BigInteger n = publicKey[1];
        BigInteger[] cipher = new BigInteger[plaintext.length()];
        for (int i = 0; i < plaintext.length(); i++) {
            BigInteger m = BigInteger.valueOf(plaintext.charAt(i));
            if (m.compareTo(n) >= 0)
                throw new IllegalArgumentException(
                    "Character '" + plaintext.charAt(i) + "' (ord=" + m + ") >= n=" + n +
                    ". Use larger primes or ASCII-only input.");
            cipher[i] = m.modPow(e, n);
        }
        return cipher;
    }

    /**
     * Decrypts a ciphertext array produced by {@link #encrypt}.
     *
     * @param ciphertext Array of BigIntegers.
     * @param privateKey Array [d, n].
     * @return The original plaintext string.
     */
    public static String decrypt(BigInteger[] ciphertext, BigInteger[] privateKey) {
        BigInteger d = privateKey[0];
        BigInteger n = privateKey[1];
        StringBuilder sb = new StringBuilder(ciphertext.length);
        for (BigInteger c : ciphertext) {
            sb.append((char) c.modPow(d, n).intValue());
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Sign / Verify
    // -----------------------------------------------------------------------

    /**
     * Signs {@code message} with the RSA private key (textbook RSA signature).
     *
     * <p>Each character ordinal is raised to the power d mod n.
     * In real usage, only the hash of the message is signed.
     *
     * @param message    The message to sign.
     * @param privateKey Array [d, n].
     * @return Signature as an array of BigIntegers.
     */
    public static BigInteger[] sign(String message, BigInteger[] privateKey) {
        BigInteger d = privateKey[0];
        BigInteger n = privateKey[1];
        BigInteger[] sig = new BigInteger[message.length()];
        for (int i = 0; i < message.length(); i++) {
            sig[i] = BigInteger.valueOf(message.charAt(i)).modPow(d, n);
        }
        return sig;
    }

    /**
     * Verifies a signature produced by {@link #sign}.
     *
     * @param message   The original plaintext.
     * @param signature The signature array.
     * @param publicKey Array [e, n].
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     */
    public static boolean verify(String message, BigInteger[] signature, BigInteger[] publicKey) {
        BigInteger e = publicKey[0];
        BigInteger n = publicKey[1];
        if (message.length() != signature.length) return false;
        for (int i = 0; i < message.length(); i++) {
            if (signature[i].modPow(e, n).intValue() != message.charAt(i))
                return false;
        }
        return true;
    }
}

