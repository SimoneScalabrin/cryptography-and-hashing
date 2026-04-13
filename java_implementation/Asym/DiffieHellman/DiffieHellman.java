package DiffieHellman;

import java.math.BigInteger;
import java.security.SecureRandom;

// =============================================================================
// Diffie-Hellman Key Exchange
// =============================================================================
//
// Protocol overview:
//   Alice and Bob agree on a shared secret over a public channel without
//   ever transmitting the secret itself. Eve intercepts everything but
//   cannot recover the key (Discrete Logarithm Problem is hard).
//
// Public parameters (posted openly):
//   p  — large prime modulus
//   g  — primitive root / generator (typically 2 or 5)
//
// Steps:
//   1. Alice picks private key  a  (random, secret)
//      Computes public key  A = g^a mod p  → sends A to Bob
//   2. Bob picks private key  b  (random, secret)
//      Computes public key  B = g^b mod p  → sends B to Alice
//   3. Alice computes  shared = B^a mod p = g^(ab) mod p
//      Bob   computes  shared = A^b mod p = g^(ab) mod p
//   → Both get the same shared secret!
//
// Eve sees (p, g, A, B) but recovering the secret requires solving the
// Discrete Logarithm Problem — infeasible for large p.
// =============================================================================

public class DiffieHellman {

    // Cryptographically secure random number generator
    private static final SecureRandom RNG = new SecureRandom();

    // -------------------------------------------------------------------------
    // Well-known safe primes (RFC 3526 / IETF MODP groups)
    // -------------------------------------------------------------------------

    /** 512-bit safe prime — demo/educational use only (too small for production). */
    public static final BigInteger PRIME_512 = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
        "FFFFFFFFFFFFFFFF", 16);

    /** 1536-bit MODP group (RFC 3526, Group 5) — minimum acceptable in practice. */
    public static final BigInteger PRIME_1536 = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

    /** 2048-bit MODP group (RFC 3526, Group 14) — current production standard. */
    public static final BigInteger PRIME_2048 = new BigInteger(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    // -------------------------------------------------------------------------

    /**
     * Holds the result of a full DH key exchange.
     */
    public record DHResult(
        BigInteger alicePrivate,
        BigInteger bobPrivate,
        BigInteger alicePublic,
        BigInteger bobPublic,
        BigInteger sharedSecret
    ) {}

    // -------------------------------------------------------------------------

    /**
     * Generates a (privateKey, publicKey) pair for one party.
     *
     * <p>Picks a random private key in [2, p-2] using a cryptographically
     * secure RNG, then computes {@code publicKey = g^privateKey mod p}.
     *
     * @param p public prime modulus
     * @param g public generator (primitive root modulo p)
     * @return array {privateKey, publicKey}
     *
     * <pre>
     * Example:
     *   BigInteger[] kp = generateKeypair(BigInteger.valueOf(23), BigInteger.valueOf(5));
     *   // kp[0] = random private key in [2, 21]
     *   // kp[1] = 5^kp[0] mod 23
     * </pre>
     */
    public static BigInteger[] generateKeypair(BigInteger p, BigInteger g) {
        // Private key: random in [2, p-2]
        BigInteger range   = p.subtract(BigInteger.TWO);           // p-2
        BigInteger privKey;
        do {
            privKey = new BigInteger(range.bitLength(), RNG);
        } while (privKey.compareTo(BigInteger.TWO) < 0
              || privKey.compareTo(range) > 0);

        // Public key: g^private mod p  — O(log private) via square-and-multiply
        BigInteger pubKey = g.modPow(privKey, p);
        return new BigInteger[]{privKey, pubKey};
    }

    /**
     * Computes the shared secret from the other party's public key and own private key.
     *
     * <p>Both Alice and Bob call this symmetrically and obtain
     * {@code g^(ab) mod p} without ever transmitting it.
     *
     * @param theirPublic the other party's public key
     * @param myPrivate   own private key
     * @param p           public prime modulus
     * @return shared secret {@code theirPublic^myPrivate mod p}
     *
     * <pre>
     * Example (p=23, g=5, a=6, b=15):
     *   A = 5^6  mod 23 = 8
     *   B = 5^15 mod 23 = 19
     *   Alice: computeSharedSecret(B=19, a=6,  23) → 2
     *   Bob:   computeSharedSecret(A=8,  b=15, 23) → 2  ← same!
     * </pre>
     */
    public static BigInteger computeSharedSecret(BigInteger theirPublic,
                                                  BigInteger myPrivate,
                                                  BigInteger p) {
        return theirPublic.modPow(myPrivate, p);
    }

    /**
     * Simulates a complete Diffie-Hellman key exchange between Alice and Bob.
     *
     * <p>If {@code alicePrivate} or {@code bobPrivate} is {@code null}, a
     * random private key is generated for that party.
     *
     * @param p            public prime modulus
     * @param g            public generator
     * @param alicePrivate Alice's private key, or {@code null} to auto-generate
     * @param bobPrivate   Bob's private key, or {@code null} to auto-generate
     * @return {@link DHResult} with all public/private values and the shared secret
     * @throws AssertionError if Alice and Bob derive different shared secrets
     */
    public static DHResult exchange(BigInteger p, BigInteger g,
                                     BigInteger alicePrivate,
                                     BigInteger bobPrivate) {
        if (alicePrivate == null) alicePrivate = generateKeypair(p, g)[0];
        if (bobPrivate   == null) bobPrivate   = generateKeypair(p, g)[0];

        BigInteger alicePublic = g.modPow(alicePrivate, p);   // Alice → Bob
        BigInteger bobPublic   = g.modPow(bobPrivate,   p);   // Bob → Alice

        BigInteger sharedAlice = computeSharedSecret(bobPublic,   alicePrivate, p);
        BigInteger sharedBob   = computeSharedSecret(alicePublic, bobPrivate,   p);

        if (!sharedAlice.equals(sharedBob)) {
            throw new AssertionError("BUG: shared secrets do not match!");
        }
        return new DHResult(alicePrivate, bobPrivate, alicePublic, bobPublic, sharedAlice);
    }

    // =========================================================================
    // main — usage examples
    // =========================================================================

    public static void main(String[] args) {

        final String SEP = "=".repeat(60);
        final BigInteger G = BigInteger.TWO;

        // ---------------------------------------------------------------------
        // 1. Toy example (p=23, g=5) — verifiable by hand
        // ---------------------------------------------------------------------
        System.out.println(SEP);
        System.out.println("EXAMPLE 1 — Toy prime (p=23, g=5)");
        System.out.println(SEP);

        BigInteger p23 = BigInteger.valueOf(23);
        BigInteger g5  = BigInteger.valueOf(5);
        DHResult toy = exchange(p23, g5,
                BigInteger.valueOf(6),   // Alice's private key
                BigInteger.valueOf(15)); // Bob's   private key

        System.out.printf("  Public  p = 23,  g = 5%n");
        System.out.printf("  Alice private (a) = %s%n", toy.alicePrivate());
        System.out.printf("  Bob   private (b) = %s%n", toy.bobPrivate());
        System.out.printf("  Alice public  (A = g^a mod p) = %s%n", toy.alicePublic());
        System.out.printf("  Bob   public  (B = g^b mod p) = %s%n", toy.bobPublic());
        System.out.printf("  Shared secret (g^ab mod p)    = %s%n", toy.sharedSecret());
        System.out.printf("  Verify: 5^(6*15) mod 23 = 5^90 mod 23 = %s%n",
                g5.modPow(BigInteger.valueOf(90), p23));

        // ---------------------------------------------------------------------
        // 2. Random exchanges with a small prime — 5 runs
        // ---------------------------------------------------------------------
        System.out.printf("%n%s%n", SEP);
        System.out.println("EXAMPLE 2 — Random private keys, p=1009, g=7  (5 runs)");
        System.out.println(SEP);

        BigInteger p1009 = BigInteger.valueOf(1009);
        BigInteger g7    = BigInteger.valueOf(7);
        for (int i = 1; i <= 5; i++) {
            DHResult r = exchange(p1009, g7, null, null);
            System.out.printf("  Run %d: a=%4s, b=%4s → A=%4s, B=%4s → shared=%4s%n",
                    i, r.alicePrivate(), r.bobPrivate(),
                    r.alicePublic(), r.bobPublic(), r.sharedSecret());
        }

        // ---------------------------------------------------------------------
        // 3. Production-grade RFC 3526 safe primes — timing comparison
        // ---------------------------------------------------------------------
        System.out.printf("%n%s%n", SEP);
        System.out.println("EXAMPLE 3 — RFC 3526 safe primes (production-grade)");
        System.out.println(SEP);

        Object[][] groups = {
            {"512-bit  (demo only)",       PRIME_512,  G},
            {"1536-bit (RFC 3526 Grp 5)",  PRIME_1536, G},
            {"2048-bit (RFC 3526 Grp 14)", PRIME_2048, G},
        };

        for (Object[] grp : groups) {
            String    label = (String)    grp[0];
            BigInteger p    = (BigInteger) grp[1];
            BigInteger g    = (BigInteger) grp[2];

            long t0 = System.nanoTime();
            DHResult r = exchange(p, g, null, null);
            double ms  = (System.nanoTime() - t0) / 1_000_000.0;

            String shared = r.sharedSecret().toString();
            System.out.printf("%n  [%s]%n", label);
            System.out.printf("  Prime  (%d bits): %s...%n", p.bitLength(), p.toString().substring(0, 24));
            System.out.printf("  Generator g = %s%n", g);
            System.out.printf("  Alice private (a): %s...%n", r.alicePrivate().toString().substring(0, Math.min(16, r.alicePrivate().toString().length())));
            System.out.printf("  Bob   private (b): %s...%n", r.bobPrivate().toString().substring(0, Math.min(16, r.bobPrivate().toString().length())));
            System.out.printf("  Alice public  (A): %s...%n", r.alicePublic().toString().substring(0, 24));
            System.out.printf("  Bob   public  (B): %s...%n", r.bobPublic().toString().substring(0, 24));
            System.out.printf("  Shared secret    : %s...  (%d decimal digits)%n", shared.substring(0, 24), shared.length());
            System.out.printf("  Key exchange time: %.2f ms%n", ms);
        }

        // ---------------------------------------------------------------------
        // 4. Security note — what Eve sees vs what she needs
        // ---------------------------------------------------------------------
        System.out.printf("%n%s%n", SEP);
        System.out.println("SECURITY NOTE — What Eve can and cannot do");
        System.out.println(SEP);

        DHResult eve = exchange(PRIME_2048, G, null, null);
        System.out.printf("  Eve intercepts (all public):%n");
        System.out.printf("    p = %s...  (%d bits)%n",
                PRIME_2048.toString().substring(0, 24), PRIME_2048.bitLength());
        System.out.printf("    g = 2%n");
        System.out.printf("    A = %s...%n", eve.alicePublic().toString().substring(0, 24));
        System.out.printf("    B = %s...%n", eve.bobPublic().toString().substring(0, 24));
        System.out.println();
        System.out.println("  To recover the shared secret Eve must find 'a' such that:");
        System.out.println("    g^a ≡ A  (mod p)   ← Discrete Logarithm Problem");
        System.out.println();
        System.out.println("  Best known algorithm (Number Field Sieve) for a 2048-bit prime");
        System.out.println("  requires ~2^112 operations — with all computers on Earth it would");
        System.out.println("  take longer than the age of the universe.");
        System.out.println("  → The shared secret is safe even though A, B, p, g are all public.");
    }
}

