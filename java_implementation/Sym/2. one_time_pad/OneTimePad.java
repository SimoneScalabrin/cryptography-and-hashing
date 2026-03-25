/**
 * OneTimePad.java
 * Java implementation of the One-Time Pad cipher.
 * Provides methods to encrypt and decrypt text using a random key of the same length as the message.
 * Includes input validation and improved comments.
 */

public class OneTimePad {
    /**
     * Encrypts text using the key with XOR operation.
     * @param text The text to encrypt
     * @param key The random key
     * @return The encrypted text
     */
    public static String encrypt(String text, String key) {
        if (text == null || key == null) throw new IllegalArgumentException("Text and key cannot be null");
        if (text.length() != key.length()) throw new IllegalArgumentException("Text and key must have the same length");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            // XOR between text character and key character
            result.append((char) (text.charAt(i) ^ key.charAt(i)));
        }
        return result.toString();
    }

    /**
     * Decrypts text encrypted with the key using XOR (symmetric operation).
     * @param cipher The encrypted text
     * @param key The random key
     * @return The decrypted text
     */
    public static String decrypt(String cipher, String key) {
        return encrypt(cipher, key); // XOR is symmetric
    }

    /**
     * Generates a random key of the specified length.
     * @param length Length of the key
     * @return Random key
     */
    public static String generateKey(int length) {
        if (length < 0) throw new IllegalArgumentException("Key length cannot be negative");
        java.util.Random rand = new java.util.Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append((char) (rand.nextInt(256)));
        }
        return key.toString();
    }

    /**
     * Example usage of the One-Time Pad cipher.
     */
    public static void main(String[] args) {
        String text = "HELLO WORLD";
        String key = generateKey(text.length());
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Edge case: empty string
        String emptyText = "";
        String emptyKey = generateKey(emptyText.length());
        String emptyEncrypted = encrypt(emptyText, emptyKey);
        String emptyDecrypted = decrypt(emptyEncrypted, emptyKey);
        System.out.println("Encrypted (empty): " + emptyEncrypted);
        System.out.println("Decrypted (empty): " + emptyDecrypted);
    }
}
