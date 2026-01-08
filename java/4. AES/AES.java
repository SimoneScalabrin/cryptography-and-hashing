/**
 * AES.java
 * Java implementation of the AES algorithm (simplified, for educational purposes).
 * Uses Java libraries to encrypt and decrypt text with an AES key.
 * Includes input validation and improved comments.
 */

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AES {
    /**
     * Encrypts text using AES.
     * @param plainText The text to encrypt
     * @param key The AES key
     * @return The encrypted text in Base64
     * @throws Exception In case of encryption error
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        if (plainText == null || key == null) throw new IllegalArgumentException("Text and key cannot be null");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts text encrypted with AES.
     * @param cipherText The encrypted text in Base64
     * @param key The AES key
     * @return The decrypted text
     * @throws Exception In case of decryption error
     */
    public static String decrypt(String cipherText, SecretKey key) throws Exception {
        if (cipherText == null || key == null) throw new IllegalArgumentException("Cipher text and key cannot be null");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decrypted);
    }

    /**
     * Generates a random 128-bit AES key.
     * @return AES key
     * @throws Exception In case of key generation error
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit AES
        return keyGen.generateKey();
    }

    /**
     * Example usage of the AES algorithm.
     */
    public static void main(String[] args) throws Exception {
        String text = "HELLO WORLD";
        SecretKey key = generateKey();
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
