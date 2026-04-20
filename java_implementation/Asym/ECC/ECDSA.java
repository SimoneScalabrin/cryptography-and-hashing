package ECC;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * ECDSA — Elliptic Curve Digital Signature Algorithm
 * ===================================================
 * ECDSA is a digital signature scheme built on top of elliptic-curve
 * cryptography.  It provides the same security level as RSA but with
 * much smaller key sizes, making it ideal for constrained environments
 * (TLS, JWT, blockchain, etc.).
 *
 * <h2>How it works</h2>
 * <ol>
 *   <li><b>Key generation</b> — choose a random scalar {@code d} as the
 *       private key; the public key is {@code Q = d·G} (a point on the curve).</li>
 *   <li><b>Signing</b> — given message hash {@code e} and private key {@code d}:
 *     <ul>
 *       <li>Pick a random nonce {@code k} in {@code [1, n-1]}.</li>
 *       <li>Compute {@code (x1, y1) = k·G}; set {@code r = x1 mod n}.</li>
 *       <li>Compute {@code s = k⁻¹ · (e + r·d) mod n}.</li>
 *       <li>Signature is the pair {@code (r, s)}.</li>
 *     </ul>
 *   </li>
 *   <li><b>Verification</b> — given hash {@code e}, public key {@code Q},
 *       and signature {@code (r, s)}:
 *     <ul>
 *       <li>{@code w  = s⁻¹ mod n}</li>
 *       <li>{@code u1 = e·w mod n},  {@code u2 = r·w mod n}</li>
 *       <li>{@code (x1, y1) = u1·G + u2·Q}</li>
 *       <li>Valid iff {@code x1 mod n == r}.</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <h2>Security notes</h2>
 * <ul>
 *   <li><b>Never reuse the nonce {@code k}.</b>  Reuse leaks the private key
 *       (the Sony PS3 hack is the canonical example).</li>
 *   <li>The nonce is generated with {@link SecureRandom} to prevent bias.</li>
 *   <li>The curves in this class are <em>educational</em>; use NIST P-256 via
 *       {@code java.security.KeyPairGenerator} for production.</li>
 * </ul>
 *
 * <p>This class reuses {@link ECC} for all curve arithmetic and
 * {@link ECC.KeyPair} for key pairs.
 */
public class ECDSA {

    private final ECC       curve;
    private final Point     G;
    /** Order of the generator point G: smallest n > 0 s.t. n·G = ∞. */
    private final BigInteger n;
    private final SecureRandom rng = new SecureRandom();

    // -----------------------------------------------------------------------
    // Signature record
    // -----------------------------------------------------------------------

    /**
     * An ECDSA signature, consisting of two integers {@code (r, s)}.
     * Both values are in the range {@code [1, n-1]}, where {@code n} is the
     * order of the generator point.
     */
    public static class Signature {

        /** First signature component: {@code r = (k·G).x mod n}. */
        public final BigInteger r;

        /** Second signature component: {@code s = k⁻¹ · (e + r·d) mod n}. */
        public final BigInteger s;

        /** Constructs a signature from two BigInteger components. */
        public Signature(BigInteger r, BigInteger s) {
            this.r = r;
            this.s = s;
        }

        @Override
        public String toString() {
            return "Signature(r=" + r + ", s=" + s + ")";
        }
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /**
     * Creates an ECDSA instance over the given curve with generator {@code G}
     * of order {@code n}.
     *
     * @param curve the elliptic curve to use
     * @param G     the generator (base) point; must be on {@code curve}
     * @param n     the order of {@code G} (prime recommended for security)
     * @throws IllegalArgumentException if G is not on the curve
     */
    public ECDSA(ECC curve, Point G, BigInteger n) {
        if (!curve.isOnCurve(G)) {
            throw new IllegalArgumentException(
                "Generator point G is not on the given curve."
            );
        }
        this.curve = curve;
        this.G     = G;
        this.n     = n;
    }

    // -----------------------------------------------------------------------
    // Key generation
    // -----------------------------------------------------------------------

    /**
     * Generates a random ECDSA key pair.
     *
     * <p>The private key {@code d} is a random scalar in {@code [1, n-1]}.
     * The public key is {@code Q = d·G}.
     *
     * @return an {@link ECC.KeyPair} whose {@code privateKey} is {@code d}
     *         and {@code publicKey} is the point {@code Q}
     */
    public ECC.KeyPair generateKeyPair() {
        BigInteger d;
        do {
            d = new BigInteger(n.bitLength(), rng);
        } while (d.compareTo(BigInteger.ONE) < 0 || d.compareTo(n) >= 0);

        Point Q = curve.scalarMultiply(d, G);
        return new ECC.KeyPair(d, Q);
    }

    // -----------------------------------------------------------------------
    // Sign
    // -----------------------------------------------------------------------

    /**
     * Signs a message hash with the given private key.
     *
     * <p>A fresh cryptographically random nonce {@code k} is generated for
     * every call.  Never reuse {@code k}: doing so leaks the private key.
     *
     * @param privateKey the signer's private key scalar {@code d}
     * @param messageHash the SHA-256 (or other) hash of the message as bytes
     * @return the ECDSA signature {@code (r, s)}
     */
    public Signature sign(BigInteger privateKey, byte[] messageHash) {
        // Truncate or zero-pad the hash to the bit-length of n
        BigInteger e = new BigInteger(1, messageHash).mod(n);

        BigInteger r = BigInteger.ZERO;
        BigInteger s = BigInteger.ZERO;

        while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO)) {
            // 1. Generate a random nonce k in [1, n-1]
            BigInteger k;
            do {
                k = new BigInteger(n.bitLength(), rng);
            } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(n) >= 0);

            // 2. Compute (x1, y1) = k·G
            Point kG = curve.scalarMultiply(k, G);
            if (kG.isInfinity()) continue;

            // 3. r = x1 mod n
            r = kG.x.mod(n);
            if (r.equals(BigInteger.ZERO)) continue;

            // 4. s = k⁻¹ · (e + r·d) mod n
            try {
                BigInteger kInv = k.modInverse(n);
                s = kInv.multiply(e.add(r.multiply(privateKey))).mod(n);
            } catch (ArithmeticException ex) {
                // k and n not coprime — retry (rare when n is prime)
                r = BigInteger.ZERO;
            }
        }

        return new Signature(r, s);
    }

    // -----------------------------------------------------------------------
    // Verify
    // -----------------------------------------------------------------------

    /**
     * Verifies an ECDSA signature against a message hash and a public key.
     *
     * @param publicKey   the signer's public key point {@code Q}
     * @param messageHash the SHA-256 (or other) hash of the message as bytes
     * @param sig         the signature {@code (r, s)} to verify
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    public boolean verify(Point publicKey, byte[] messageHash, Signature sig) {
        BigInteger r = sig.r, s = sig.s;

        // Range check
        if (r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0) return false;
        if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) return false;

        BigInteger e = new BigInteger(1, messageHash).mod(n);

        BigInteger w;
        try {
            w = s.modInverse(n);
        } catch (ArithmeticException ex) {
            return false;
        }

        BigInteger u1 = e.multiply(w).mod(n);
        BigInteger u2 = r.multiply(w).mod(n);

        Point u1G = curve.scalarMultiply(u1, G);
        Point u2Q = curve.scalarMultiply(u2, publicKey);
        Point point = curve.add(u1G, u2Q);

        if (point.isInfinity()) return false;

        return point.x.mod(n).equals(r);
    }

    // -----------------------------------------------------------------------
    // Hashing utility
    // -----------------------------------------------------------------------

    /**
     * Computes the SHA-256 digest of a UTF-8 encoded string.
     *
     * @param message the plaintext message to hash
     * @return 32-byte SHA-256 digest
     */
    public static byte[] sha256(String message) {
        try {
            return MessageDigest.getInstance("SHA-256")
                                .digest(message.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Returns a hex-encoded string of a byte array.
     *
     * @param bytes the bytes to encode
     * @return lowercase hex string
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
