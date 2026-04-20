package ECC;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Elliptic Curve Cryptography (ECC) over the finite field GF(p).
 *
 * <p>Curve equation: <code>y² ≡ x³ + ax + b  (mod p)</code>
 *
 * <p>All arithmetic is performed modulo a prime {@code p}. Division is replaced
 * by multiplication with the modular inverse, obtained via Fermat's little
 * theorem: {@code k⁻¹ ≡ k^(p-2) (mod p)} for prime {@code p}.
 *
 * <h2>Key operations</h2>
 * <ul>
 *   <li>{@link #isOnCurve(Point)}       – verify a point belongs to the curve</li>
 *   <li>{@link #negate(Point)}           – additive inverse: −P = (x, −y mod p)</li>
 *   <li>{@link #add(Point, Point)}       – point addition / doubling</li>
 *   <li>{@link #scalarMultiply(BigInteger, Point)} – double-and-add scalar multiplication</li>
 *   <li>{@link ECDH}                     – Elliptic Curve Diffie-Hellman key exchange</li>
 * </ul>
 *
 * <h2>Security note</h2>
 * This implementation uses small educational curves.  Production code must use
 * standardised curves such as NIST P-256 / secp256k1 via the JCA/JCE API.
 */
public class ECC {

    private static final BigInteger TWO   = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR  = BigInteger.valueOf(4);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger TWENTY_SEVEN = BigInteger.valueOf(27);

    /** Coefficient {@code a} in y² ≡ x³ + ax + b. */
    public final BigInteger a;

    /** Coefficient {@code b} in y² ≡ x³ + ax + b. */
    public final BigInteger b;

    /** Prime modulus defining GF(p). */
    public final BigInteger p;

    /**
     * Constructs an elliptic curve y² ≡ x³ + ax + b (mod p).
     *
     * @param a coefficient a
     * @param b coefficient b
     * @param p prime modulus (must be prime and the curve must be non-singular)
     * @throws IllegalArgumentException if the curve is singular
     *         (i.e. {@code 4a³ + 27b² ≡ 0 (mod p)})
     */
    public ECC(BigInteger a, BigInteger b, BigInteger p) {
        // Non-singularity check: 4a³ + 27b² ≢ 0 (mod p)
        BigInteger discriminant = FOUR.multiply(a.pow(3))
                                      .add(TWENTY_SEVEN.multiply(b.pow(2)))
                                      .mod(p);
        if (discriminant.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException(
                "Singular curve: 4a³ + 27b² ≡ 0 (mod p). Choose different parameters."
            );
        }
        this.a = a;
        this.b = b;
        this.p = p;
    }

    /** Convenience constructor accepting {@code long} values. */
    public ECC(long a, long b, long p) {
        this(BigInteger.valueOf(a), BigInteger.valueOf(b), BigInteger.valueOf(p));
    }

    // -----------------------------------------------------------------------
    // Curve membership
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} iff point {@code P} satisfies y² ≡ x³ + ax + b (mod p).
     * The point at infinity is always considered to be on the curve.
     *
     * @param P the point to test
     * @return {@code true} if P is on the curve
     */
    public boolean isOnCurve(Point P) {
        if (P.isInfinity()) return true;
        BigInteger lhs = P.y.pow(2).mod(p);
        BigInteger rhs = P.x.pow(3).add(a.multiply(P.x)).add(b).mod(p);
        return lhs.equals(rhs);
    }

    // -----------------------------------------------------------------------
    // Group operations
    // -----------------------------------------------------------------------

    /**
     * Returns the additive inverse of {@code P}: −P = (x, −y mod p).
     *
     * <p>Property: P + (−P) = ∞
     *
     * @param P the point to negate
     * @return −P
     */
    public Point negate(Point P) {
        if (P.isInfinity()) return Point.INFINITY;
        return new Point(P.x, P.y.negate().mod(p));
    }

    /**
     * Returns the sum P + Q on this elliptic curve (mod p).
     *
     * <p>Handles all cases:
     * <ul>
     *   <li>P = ∞  →  Q  (identity element)</li>
     *   <li>Q = ∞  →  P  (identity element)</li>
     *   <li>P = −Q →  ∞  (additive inverses cancel)</li>
     *   <li>P = Q  →  point doubling  (tangent rule)</li>
     *   <li>else   →  general point addition  (secant rule)</li>
     * </ul>
     *
     * @param P first point
     * @param Q second point
     * @return P + Q
     */
    public Point add(Point P, Point Q) {
        if (P.isInfinity()) return Q;
        if (Q.isInfinity()) return P;

        BigInteger x1 = P.x, y1 = P.y;
        BigInteger x2 = Q.x, y2 = Q.y;

        // P and Q are additive inverses → point at infinity
        if (x1.equals(x2) && y1.add(y2).mod(p).equals(BigInteger.ZERO)) {
            return Point.INFINITY;
        }

        BigInteger m;
        if (P.equals(Q)) {
            // Point doubling: tangent slope  m = (3x₁² + a) · (2y₁)⁻¹  mod p
            BigInteger num   = THREE.multiply(x1.pow(2)).add(a).mod(p);
            BigInteger denom = TWO.multiply(y1).mod(p);
            m = num.multiply(denom.modInverse(p)).mod(p);
        } else {
            // Point addition: secant slope   m = (y₂ − y₁) · (x₂ − x₁)⁻¹  mod p
            BigInteger num   = y2.subtract(y1).mod(p);
            BigInteger denom = x2.subtract(x1).mod(p);
            m = num.multiply(denom.modInverse(p)).mod(p);
        }

        BigInteger x3 = m.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = m.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        return new Point(x3, y3);
    }

    /**
     * Returns the scalar multiple {@code n·P} using the double-and-add algorithm.
     *
     * <p>Scans the binary representation of {@code n} from LSB to MSB:
     * <ul>
     *   <li>If the current bit is 1, add the current 2ⁱ·P to the accumulator.</li>
     *   <li>Always double the current multiple for the next iteration.</li>
     * </ul>
     *
     * <p>Time complexity: O(log n) — one doubling per bit of {@code n}.
     *
     * @param n positive scalar multiplier
     * @param P base point on the curve
     * @return n·P
     * @throws IllegalArgumentException if {@code n} is not positive
     */
    public Point scalarMultiply(BigInteger n, Point P) {
        if (n.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("Scalar n must be a positive integer.");
        }

        Point result = Point.INFINITY;          // accumulator — identity element
        Point addend = new Point(P.x, P.y);     // tracks 2^i · P

        while (n.compareTo(BigInteger.ZERO) > 0) {
            if (n.testBit(0)) {                 // current bit is 1
                result = add(result, addend);
            }
            addend = add(addend, addend);        // double for next bit
            n = n.shiftRight(1);
        }
        return result;
    }

    /** Convenience overload accepting a {@code long} scalar. */
    public Point scalarMultiply(long n, Point P) {
        return scalarMultiply(BigInteger.valueOf(n), P);
    }

    /**
     * Returns the order of point {@code P}: the smallest {@code n > 0} such that
     * {@code n·P = ∞}.  Brute-force — only practical for small curves.
     *
     * @param P         the point whose order to compute
     * @param maxOrder  upper bound on the search
     * @return the order of P, or {@code -1} if not found within {@code maxOrder}
     */
    public long orderOfPoint(Point P, int maxOrder) {
        Point current = new Point(P.x, P.y);
        for (int i = 1; i <= maxOrder; i++) {
            if (current.isInfinity()) return i;
            current = add(current, P);
        }
        return -1;
    }

    @Override
    public String toString() {
        return "y² ≡ x³ + " + a + "x + " + b + "  (mod " + p + ")";
    }

    // =======================================================================
    // ECDH — Elliptic Curve Diffie-Hellman key exchange
    // =======================================================================

    /**
     * Elliptic Curve Diffie-Hellman (ECDH) key exchange.
     *
     * <p>Both parties agree on a public curve and a generator point G.  Each party
     * chooses a secret scalar (private key) and publishes its scalar multiple of G
     * (public key).  The shared secret is then:
     * <pre>
     *   Alice: a · (b·G) = (ab)·G
     *   Bob:   b · (a·G) = (ab)·G
     * </pre>
     *
     * <p>Security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
     * given G and Q = n·G, recovering n is computationally infeasible for large p.
     */
    public static class ECDH {

        private final ECC curve;
        private final Point G;
        private final BigInteger minKey;
        private final BigInteger maxKey;
        private final SecureRandom rng = new SecureRandom();

        /**
         * Constructs an ECDH instance over the given curve with generator {@code G}.
         *
         * @param curve   the agreed-upon elliptic curve
         * @param G       the agreed-upon generator (base) point
         * @param minKey  minimum value for randomly generated private keys
         * @param maxKey  maximum value for randomly generated private keys
         * @throws IllegalArgumentException if G is not on the curve
         */
        public ECDH(ECC curve, Point G, BigInteger minKey, BigInteger maxKey) {
            if (!curve.isOnCurve(G)) {
                throw new IllegalArgumentException(
                    "Generator point G is not on the given curve."
                );
            }
            this.curve  = curve;
            this.G      = G;
            this.minKey = minKey;
            this.maxKey = maxKey;
        }

        /** Convenience constructor accepting {@code long} bounds. */
        public ECDH(ECC curve, Point G, long minKey, long maxKey) {
            this(curve, G, BigInteger.valueOf(minKey), BigInteger.valueOf(maxKey));
        }

        /**
         * Generates a random private/public key pair.
         *
         * @return a {@link KeyPair} whose {@code privateKey} is a random scalar and
         *         {@code publicKey = privateKey · G}
         */
        public KeyPair generateKeyPair() {
            BigInteger range = maxKey.subtract(minKey).add(BigInteger.ONE);
            BigInteger priv;
            do {
                priv = new BigInteger(range.bitLength(), rng);
            } while (priv.compareTo(range) >= 0);
            priv = priv.add(minKey);

            Point pub = curve.scalarMultiply(priv, G);
            return new KeyPair(priv, pub);
        }

        /**
         * Computes the shared secret from one party's private key and the other
         * party's public key.
         *
         * @param privateKey      own private key scalar
         * @param otherPublicKey  the other party's public key
         * @return the shared secret point {@code privateKey · otherPublicKey}
         */
        public Point computeSharedSecret(BigInteger privateKey, Point otherPublicKey) {
            return curve.scalarMultiply(privateKey, otherPublicKey);
        }
    }

    // -----------------------------------------------------------------------
    // KeyPair record
    // -----------------------------------------------------------------------

    /** Holds an ECC private/public key pair. */
    public static class KeyPair {

        /** The private key scalar. */
        public final BigInteger privateKey;

        /** The public key point: {@code privateKey · G}. */
        public final Point publicKey;

        public KeyPair(BigInteger privateKey, Point publicKey) {
            this.privateKey = privateKey;
            this.publicKey  = publicKey;
        }

        @Override
        public String toString() {
            return "KeyPair{private=" + privateKey + ", public=" + publicKey + "}";
        }
    }
}

