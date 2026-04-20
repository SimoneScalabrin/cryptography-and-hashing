package ECC;

import java.math.BigInteger;

/**
 * Demo application for ECDSA — Elliptic Curve Digital Signature Algorithm.
 *
 * <p>Uses the educational curve {@code y² ≡ x³ + 3x + 5  (mod 10007)}
 * with generator {@code G = (1, 3)}.
 *
 * <p>Demonstrates three scenarios:
 * <ol>
 *   <li>Correct key + original message  → valid signature</li>
 *   <li>Correct key + tampered message  → invalid signature (integrity)</li>
 *   <li>Wrong public key + original message → invalid signature (authenticity)</li>
 * </ol>
 */
public class ECDSAApp {

    private static final String SEP = "=".repeat(62);
    private static final String HR  = "-".repeat(50);

    public static void main(String[] args) {

        System.out.println(SEP);
        System.out.println("  ECDSA — Elliptic Curve Digital Signature Algorithm");
        System.out.println(SEP);

        // --- Curve setup ----------------------------------------------------
        //  y² ≡ x³ + 3x + 5  (mod 10007)
        //  Generator (1, 3):  3² = 9 = 1³ + 3·1 + 5 = 9  ✓
        ECC   curve = new ECC(3, 5, 10_007);
        Point G     = new Point(1, 3);

        System.out.println("Curve : " + curve);
        System.out.println("G     = " + G);

        // --- 1. Compute order of G ------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[1] Computing order of G (n = smallest k s.t. k·G = ∞)");
        System.out.println(HR);

        long orderLong = curve.orderOfPoint(G, 20_000);
        if (orderLong < 0) {
            System.out.println("  Could not find order within search bound.");
            return;
        }
        BigInteger n = BigInteger.valueOf(orderLong);
        System.out.println("  Order n = " + n);

        // --- 2. Key generation ----------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[2] Key Generation");
        System.out.println(HR);

        ECDSA ecdsa = new ECDSA(curve, G, n);
        ECC.KeyPair keyPair = ecdsa.generateKeyPair();

        System.out.println("  Private key (d) : " + keyPair.privateKey);
        System.out.println("  Public  key (Q) : " + keyPair.publicKey);

        // --- 3. Sign a message ----------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[3] Sign");
        System.out.println(HR);

        String message = "Transfer $1,000 from Alice to Bob on 2026-04-20.";
        byte[] hash = ECDSA.sha256(message);

        System.out.println("  Message : \"" + message + "\"");
        System.out.println("  SHA-256 : " + ECDSA.toHex(hash));

        ECDSA.Signature sig = ecdsa.sign(keyPair.privateKey, hash);
        System.out.println("  " + sig);

        // --- 4. Scenario A: valid signature ---------------------------------
        System.out.println("\n" + HR);
        System.out.println("[4] Verify — Scenario A: correct key + original message");
        System.out.println(HR);

        boolean resultA = ecdsa.verify(keyPair.publicKey, hash, sig);
        System.out.println("  Valid: " + resultA);    // expected: true

        // --- 5. Scenario B: tampered message --------------------------------
        System.out.println("\n" + HR);
        System.out.println("[5] Verify — Scenario B: tampered message");
        System.out.println(HR);

        String tampered  = "Transfer $9,999 from Alice to Bob on 2026-04-20.";
        byte[] hashTampered = ECDSA.sha256(tampered);

        System.out.println("  Message : \"" + tampered + "\"");
        boolean resultB = ecdsa.verify(keyPair.publicKey, hashTampered, sig);
        System.out.println("  Valid: " + resultB);    // expected: false

        // --- 6. Scenario C: wrong public key --------------------------------
        System.out.println("\n" + HR);
        System.out.println("[6] Verify — Scenario C: wrong public key");
        System.out.println(HR);

        ECC.KeyPair wrongKey = ecdsa.generateKeyPair();
        System.out.println("  Wrong public key (Q') : " + wrongKey.publicKey);
        boolean resultC = ecdsa.verify(wrongKey.publicKey, hash, sig);
        System.out.println("  Valid: " + resultC);    // expected: false

        // --- Summary --------------------------------------------------------
        System.out.println("\n" + SEP);
        System.out.println("  Summary");
        System.out.println(SEP);
        System.out.printf("  Correct key  + original message  → Valid: %b%n", resultA);
        System.out.printf("  Correct key  + tampered message  → Valid: %b%n", resultB);
        System.out.printf("  Wrong key    + original message  → Valid: %b%n", resultC);
        System.out.println(SEP);
    }
}
