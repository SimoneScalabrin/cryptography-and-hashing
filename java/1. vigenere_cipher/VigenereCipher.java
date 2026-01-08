/**
 * VigenereCipher.java
 * Java implementation of the Vigenère cipher.
 * Provides methods to encrypt and decrypt text using an alphabetic key.
 */

public class VigenereCipher {
    /**
     * Encrypts text using the Vigenère cipher.
     * @param text The text to encrypt
     * @param key The alphabetic key
     * @return The encrypted text
     */
    public static String encrypt(String text, String key) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;
        for (char c : text.toCharArray()) {
            // Encrypt only letters, leave other characters unchanged
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int offset = (c - base + (key.charAt(keyIndex % key.length()) - 'A')) % 26;
                result.append((char) (base + offset));
                keyIndex++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Decrypts text encrypted with the Vigenère cipher.
     * @param text The encrypted text
     * @param key The alphabetic key
     * @return The decrypted text
     */
    public static String decrypt(String text, String key) {
        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;
        for (char c : text.toCharArray()) {
            // Decrypt only letters, leave other characters unchanged
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int offset = (c - base - (key.charAt(keyIndex % key.length()) - 'A') + 26) % 26;
                result.append((char) (base + offset));
                keyIndex++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Example usage of the Vigenère cipher.
     */
    public static void main(String[] args) {
        String text = "HELLO WORLD";
        String key = "KEY";
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
