package RSA;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA + AES Hybrid Encryption
 * ============================
 *
 * Pure RSA is slow and limited: it can only encrypt data smaller than the key
 * modulus. Real-world systems use <b>hybrid encryption</b>:
 *
 * <ol>
 *   <li>Generate a random AES-256 session key (fast, arbitrary-length data).</li>
 *   <li>Encrypt the actual data with AES-CBC.</li>
 *   <li>Wrap (encrypt) the AES key with RSA-OAEP (secure asymmetric key wrapping).</li>
 * </ol>
 *
 * <p>To decrypt:
 * <ol>
 *   <li>Unwrap the AES key with the RSA private key.</li>
 *   <li>Use the recovered AES key to decrypt the data.</li>
 * </ol>
 *
 * <p>This is how TLS, PGP, and most real cryptographic protocols work.
 *
 * <p><b>Algorithms used:</b>
 * <ul>
 *   <li>RSA/ECB/OAEPWithSHA-256AndMGF1Padding — secure key wrapping</li>
 *   <li>AES/CBC/PKCS5Padding with 256-bit key — payload encryption</li>
 * </ul>
 */
public class RSA_AES {

    private static final String RSA_ALGO  = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ALGO  = "AES/CBC/PKCS5Padding";
    private static final int    AES_BITS  = 256;
    private static final int    RSA_BITS  = 2048;
    private static final int    IV_BYTES  = 16;

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /**
     * Holds an RSA-2048 key pair (private + public).
     *
     * @param privateKey The RSA private key.
     * @param publicKey  The RSA public key.
     */
    public record RsaKeyPair(PrivateKey privateKey, PublicKey publicKey) {}

    /**
     * Generates an RSA-{@value #RSA_BITS} key pair.
     *
     * @return A {@link RsaKeyPair} with private and public keys.
     * @throws GeneralSecurityException if RSA key generation fails.
     */
    public static RsaKeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(RSA_BITS, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();
        return new RsaKeyPair(kp.getPrivate(), kp.getPublic());
    }

    /**
     * Exports a public key to Base64-encoded DER format (X.509 SubjectPublicKeyInfo).
     *
     * @param publicKey The public key to export.
     * @return Base64 string.
     */
    public static String exportPublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Exports a private key to Base64-encoded DER format (PKCS#8).
     *
     * @param privateKey The private key to export.
     * @return Base64 string.
     */
    public static String exportPrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Imports a public key from a Base64-encoded DER string.
     *
     * @param b64 Base64 string produced by {@link #exportPublicKey}.
     * @return The reconstructed {@link PublicKey}.
     * @throws GeneralSecurityException on invalid key data.
     */
    public static PublicKey importPublicKey(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Imports a private key from a Base64-encoded DER string.
     *
     * @param b64 Base64 string produced by {@link #exportPrivateKey}.
     * @return The reconstructed {@link PrivateKey}.
     * @throws GeneralSecurityException on invalid key data.
     */
    public static PrivateKey importPrivateKey(String b64) throws GeneralSecurityException {
        byte[] der = Base64.getDecoder().decode(b64);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    // -----------------------------------------------------------------------
    // Hybrid encryption bundle
    // -----------------------------------------------------------------------

    /**
     * Holds the result of a hybrid encryption operation.
     *
     * @param encryptedAesKey AES key wrapped with RSA-OAEP.
     * @param iv              AES initialisation vector (16 bytes).
     * @param ciphertext      AES-CBC encrypted payload.
     */
    public record EncryptedBundle(byte[] encryptedAesKey, byte[] iv, byte[] ciphertext) {}

    // -----------------------------------------------------------------------
    // Encrypt / Decrypt
    // -----------------------------------------------------------------------

    /**
     * Encrypts {@code plaintext} using RSA + AES hybrid encryption.
     *
     * <ol>
     *   <li>Generate a random AES-256 session key.</li>
     *   <li>Encrypt {@code plaintext} with AES-CBC (random IV).</li>
     *   <li>Wrap the AES key with RSA-OAEP using {@code publicKey}.</li>
     * </ol>
     *
     * @param plaintext The data to encrypt.
     * @param publicKey Recipient's RSA public key.
     * @return An {@link EncryptedBundle} containing all three components.
     * @throws GeneralSecurityException on any cryptographic error.
     */
    public static EncryptedBundle encrypt(byte[] plaintext, PublicKey publicKey)
            throws GeneralSecurityException {
        // Step 1 — random AES-256 session key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_BITS, new SecureRandom());
        SecretKey aesKey = kg.generateKey();

        // Step 2 — AES-CBC encryption with random IV
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher aesCipher = Cipher.getInstance(AES_ALGO);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] ciphertext = aesCipher.doFinal(plaintext);

        // Step 3 — RSA-OAEP key wrapping
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGO);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new EncryptedBundle(encryptedAesKey, iv, ciphertext);
    }

    /**
     * Decrypts an {@link EncryptedBundle} produced by {@link #encrypt}.
     *
     * <ol>
     *   <li>Unwrap the AES key with RSA-OAEP using {@code privateKey}.</li>
     *   <li>Decrypt the payload with AES-CBC.</li>
     * </ol>
     *
     * @param bundle     The encrypted bundle.
     * @param privateKey Recipient's RSA private key.
     * @return The original plaintext bytes.
     * @throws GeneralSecurityException on any cryptographic error (incl. bad padding
     *                                  for tampered data).
     */
    public static byte[] decrypt(EncryptedBundle bundle, PrivateKey privateKey)
            throws GeneralSecurityException {
        // Step 1 — unwrap AES key
        Cipher rsaCipher = Cipher.getInstance(RSA_ALGO);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(bundle.encryptedAesKey());
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Step 2 — AES-CBC decryption
        Cipher aesCipher = Cipher.getInstance(AES_ALGO);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(bundle.iv()));
        return aesCipher.doFinal(bundle.ciphertext());
    }
}
