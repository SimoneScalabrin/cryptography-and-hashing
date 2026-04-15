package RSA;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Demo entry point for RSA and RSA+AES hybrid encryption.
 */
public class App {

    public static void main(String[] args) throws GeneralSecurityException {

        // ===================================================================
        // Part 1 — Textbook RSA (RSA.java)
        // ===================================================================
        System.out.println("=".repeat(60));
        System.out.printf("%60s%n", "Textbook RSA");
        System.out.println("=".repeat(60));

        // Key generation — 512-bit primes → 1024-bit key (demo size)
        System.out.println("\n[1] Key Generation (512-bit primes)");
        RSA.KeyPair kp = RSA.generateKeyPair(512);
        System.out.printf("  p            = %s%n", kp.p().toString().substring(0, 12) + "...");
        System.out.printf("  q            = %s%n", kp.q().toString().substring(0, 12) + "...");
        System.out.printf("  n            = %s...%n", kp.n().toString().substring(0, 12));
        System.out.printf("  e (pub exp)  = %d%n", kp.e().longValue());
        System.out.printf("  d (priv exp) = %s...%n", kp.d().toString().substring(0, 12));
        System.out.printf("  e*d mod φ(n) = %d  (must be 1)%n",
                kp.e().multiply(kp.d()).mod(kp.phiN()).intValue());

        // Encrypt / Decrypt
        System.out.println("\n[2] Encrypt / Decrypt");
        System.out.println("-".repeat(60));
        String[] messages = {"HELLO RSA", "Hi!", "Java 2025"};
        for (String msg : messages) {
            try {
                BigInteger[] cipher    = RSA.encrypt(msg, kp.publicKey());
                String       recovered = RSA.decrypt(cipher, kp.privateKey());
                String ok = recovered.equals(msg) ? "✓" : "✗";
                System.out.printf("  [%s] '%s'  →  [%d, ...]  →  '%s'%n",
                        ok, msg, cipher[0].intValue(), recovered);
            } catch (IllegalArgumentException ex) {
                System.out.printf("  [!] '%s' — %s%n", msg, ex.getMessage());
            }
        }

        // Digital signature
        System.out.println("\n[3] Digital Signature");
        System.out.println("-".repeat(60));
        String toSign  = "authentic";
        BigInteger[] sig = RSA.sign(toSign, kp.privateKey());
        System.out.printf("  Message   : '%s'%n", toSign);
        System.out.printf("  Signature : [%d, %d, ...]%n", sig[0].intValue(), sig[1].intValue());
        System.out.printf("  Valid     : %b  (original)%n", RSA.verify(toSign, sig, kp.publicKey()));
        System.out.printf("  Valid     : %b  (tampered 'tampered!')%n",
                RSA.verify("tampered!", sig, kp.publicKey()));

        // ===================================================================
        // Part 2 — RSA + AES Hybrid Encryption (RSA_AES.java)
        // ===================================================================
        System.out.println();
        System.out.println("=".repeat(60));
        System.out.printf("%60s%n", "RSA + AES Hybrid Encryption");
        System.out.println("=".repeat(60));

        // Key generation — RSA-2048
        System.out.println("\n[1] Generating RSA-2048 key pair...");
        RSA_AES.RsaKeyPair hybridKp = RSA_AES.generateKeyPair();
        System.out.printf("    Algorithm  : %s%n", hybridKp.publicKey().getAlgorithm());
        System.out.printf("    Format     : %s%n", hybridKp.publicKey().getFormat());

        // Export / import round-trip
        String pubB64  = RSA_AES.exportPublicKey(hybridKp.publicKey());
        String privB64 = RSA_AES.exportPrivateKey(hybridKp.privateKey());
        var loadedPub  = RSA_AES.importPublicKey(pubB64);
        var loadedPriv = RSA_AES.importPrivateKey(privB64);
        System.out.println("    Key export/import round-trip  ✓");

        // Hybrid encrypt / decrypt
        System.out.println("\n[2] Hybrid Encryption (RSA-OAEP wraps AES-256-CBC)");
        System.out.println("-".repeat(60));
        byte[][] payloads = {
            "Hello, hybrid encryption!".getBytes(),
            ("RSA alone cannot encrypt large data efficiently. " +
             "Hybrid encryption combines AES speed + RSA key exchange.").getBytes(),
            new byte[]{0x00, 0x01, 0x02, 'b', 'i', 'n', (byte)0xFF, 'a', 'r', 'y'},
        };
        for (byte[] payload : payloads) {
            RSA_AES.EncryptedBundle bundle   = RSA_AES.encrypt(payload, loadedPub);
            byte[]                  recovered = RSA_AES.decrypt(bundle, loadedPriv);
            boolean ok = Arrays.equals(payload, recovered);
            String preview = new String(payload).substring(0, Math.min(40, payload.length));
            if (payload.length > 40) preview += "...";
            System.out.printf("  [%s] '%s'%n", ok ? "✓" : "✗", preview);
            System.out.printf("       AES key (wrapped) : %s...%n",
                    bytesToHex(bundle.encryptedAesKey()).substring(0, 32));
            System.out.printf("       IV               : %s%n", bytesToHex(bundle.iv()));
            System.out.printf("       Ciphertext       : %s...%n",
                    bytesToHex(bundle.ciphertext()).substring(0, 32));
        }

        // Tamper detection
        System.out.println("\n[3] Tamper detection");
        System.out.println("-".repeat(60));
        RSA_AES.EncryptedBundle bundle  = RSA_AES.encrypt("secret payload".getBytes(), loadedPub);
        byte[] tampered = bundle.ciphertext().clone();
        tampered[0] ^= 0xFF;  // flip bits in first byte
        try {
            RSA_AES.decrypt(new RSA_AES.EncryptedBundle(bundle.encryptedAesKey(), bundle.iv(), tampered), loadedPriv);
            System.out.println("  [✗] Tampered ciphertext accepted — unexpected!");
        } catch (GeneralSecurityException ex) {
            System.out.println("  [✓] Tampered ciphertext correctly rejected (bad padding)");
        }
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

