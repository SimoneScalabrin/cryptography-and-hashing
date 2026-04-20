package ECC;

import java.math.BigInteger;

/**
 * Demo application for Elliptic Curve Cryptography (ECC).
 *
 * <p>Demonstrates the following concepts on a small educational curve
 * {@code y² ≡ x³ + 2x + 3  (mod 97)} with generator G = (3, 6):
 *
 * <ol>
 *   <li>Point validation  — checking whether a point lies on the curve</li>
 *   <li>Point addition    — P + Q and point doubling P + P</li>
 *   <li>Scalar multiplication — double-and-add algorithm</li>
 *   <li>Point order       — smallest n such that n·G = ∞</li>
 *   <li>ECDH key exchange — Alice and Bob derive the same shared secret</li>
 * </ol>
 *
 * <p><b>Note:</b> These curves are <em>not</em> cryptographically secure.  Use
 * the JCA/JCE API with NIST P-256 or secp256k1 for production.
 */
public class App {

    private static final String SEP = "=" .repeat(62);
    private static final String HR  = "-" .repeat(50);

    public static void main(String[] args) {

        // --- Curve setup ----------------------------------------------------
        //  y² ≡ x³ + 2x + 3  (mod 97)
        //  Verify G = (3, 6):  6² = 36;  3³ + 2·3 + 3 = 36  ✓
        ECC   curve = new ECC(2, 3, 97);
        Point G     = new Point(3, 6);

        System.out.println(SEP);
        System.out.println("  Elliptic Curve Cryptography — Java Demo");
        System.out.println(SEP);
        System.out.println("Curve     : " + curve);
        System.out.println("Generator : G = " + G);

        // --- 1. Point validation -------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[1] Point Validation (isOnCurve)");
        System.out.println(HR);

        Point[][] candidates = {
            { G,                  null },   // label handled below
            { new Point(80, 10), null },
            { new Point(0, 0),   null },
            { Point.INFINITY,    null },
        };
        String[] labels = { "G = (3, 6) (generator)", "(80, 10)", "(0, 0)", "∞ (identity)" };

        for (int i = 0; i < candidates.length; i++) {
            boolean on = curve.isOnCurve(candidates[i][0]);
            System.out.printf("  %-28s on curve: %b%n", labels[i], on);
        }

        // --- 2. Point addition ---------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[2] Point Addition");
        System.out.println(HR);

        Point G2 = curve.add(G, G);            // point doubling: 2·G
        Point G3 = curve.add(G2, G);           // 3·G
        Point neg = curve.negate(G);           // −G
        Point inf = curve.add(G, neg);         // G + (−G) = ∞

        System.out.println("  G + G  = 2G  = " + G2);
        System.out.println("  2G + G = 3G  = " + G3);
        System.out.println("  −G          = " + neg);
        System.out.println("  G + (−G)    = " + inf + "  (point at infinity)");
        System.out.println("  ∞ + G       = " + curve.add(Point.INFINITY, G) + "  (identity)");

        // --- 3. Scalar multiplication --------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[3] Scalar Multiplication (double-and-add)");
        System.out.println(HR);

        int[] scalars = { 1, 2, 3, 5, 10, 20 };
        for (int n : scalars) {
            Point nG = curve.scalarMultiply(n, G);
            System.out.printf("  %2d · G = %s%n", n, nG);
        }

        // Consistency check: 5·G via scalarMultiply vs repeated add
        Point g5_add   = curve.add(curve.add(curve.add(curve.add(G, G), G), G), G);
        Point g5_mul   = curve.scalarMultiply(5, G);
        System.out.println("  5·G (repeated add)   = " + g5_add);
        System.out.println("  5·G (scalarMultiply) = " + g5_mul);
        System.out.println("  Results match: " + g5_add.equals(g5_mul));

        // --- 4. Point order ------------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[4] Order of Generator G");
        System.out.println(HR);

        long order = curve.orderOfPoint(G, 200);
        System.out.println("  Smallest n s.t. n·G = ∞:  n = " + order);
        if (order > 0) {
            Point check = curve.scalarMultiply(order, G);
            System.out.println("  Verification: " + order + "·G = " + check);
        }

        // --- 5. ECDH key exchange ------------------------------------------
        System.out.println("\n" + HR);
        System.out.println("[5] ECDH Key Exchange");
        System.out.println(HR);

        // Use a larger curve so that private keys in [2, 10000] are well within
        // the group order (by Hasse: #E ≈ p, so p >> 10000 is sufficient).
        // Curve: y² ≡ x³ + 3x + 5  (mod 10007)
        // Generator (1, 3): 3² = 9 = 1³ + 3·1 + 5 = 9  ✓
        ECC   ecdhCurve = new ECC(3, 5, 10_007);
        Point ecdhG     = new Point(1, 3);
        System.out.println("  Curve : " + ecdhCurve);
        System.out.println("  G     = " + ecdhG);

        ECC.ECDH ecdh = new ECC.ECDH(ecdhCurve, ecdhG, 2L, 10_000L);

        ECC.KeyPair alice = ecdh.generateKeyPair();
        ECC.KeyPair bob   = ecdh.generateKeyPair();

        System.out.println("  Alice private key : " + alice.privateKey);
        System.out.println("  Alice public  key : " + alice.publicKey);
        System.out.println("  Bob   private key : " + bob.privateKey);
        System.out.println("  Bob   public  key : " + bob.publicKey);

        Point sharedAlice = ecdh.computeSharedSecret(alice.privateKey, bob.publicKey);
        Point sharedBob   = ecdh.computeSharedSecret(bob.privateKey, alice.publicKey);

        System.out.println("\n  Alice's shared secret : " + sharedAlice);
        System.out.println("  Bob's   shared secret : " + sharedBob);
        System.out.println("  Secrets match         : " + sharedAlice.equals(sharedBob));

        System.out.println("\n" + SEP);
        System.out.println("  ECDH security note: an eavesdropper who sees G, Alice's");
        System.out.println("  public key, and Bob's public key cannot compute the shared");
        System.out.println("  secret without solving the Elliptic Curve Discrete");
        System.out.println("  Logarithm Problem (ECDLP).");
        System.out.println(SEP);
    }
}

