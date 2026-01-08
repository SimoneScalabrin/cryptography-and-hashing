/**
 * DES.java
 * Java implementation of the DES algorithm (simplified, for educational purposes).
 * Uses Java libraries to encrypt and decrypt text with a DES key.
 */
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class DES {
    /**
     * Encrypts text using DES.
     * @param plainText The text to encrypt
     * @param key The DES key
     * @return The encrypted text in Base64
     * @throws Exception In case of encryption error
     */
    public static String encrypt(String plainText, javax.crypto.SecretKey key) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return java.util.Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts text encrypted with DES.
     * @param cipherText The encrypted text in Base64
     * @param key The DES key
     * @return The decrypted text
     * @throws Exception In case of decryption error
     */
    public static String decrypt(String cipherText, javax.crypto.SecretKey key) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(java.util.Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }

    /**
     * Generates a random DES key.
     * @return DES key
     * @throws Exception In case of key generation error
     */
    public static javax.crypto.SecretKey generateKey() throws Exception {
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("DES");
        return keyGen.generateKey();
    }

    /**
     * Example usage of the DES algorithm.
     */
    public static void main(String[] args) throws Exception {
        String text = "HELLO WORLD";
        javax.crypto.SecretKey key = generateKey();
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
