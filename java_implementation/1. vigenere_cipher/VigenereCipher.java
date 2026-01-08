/**
 * VigenereCipher.java
 * Java implementation of the Vigenère cipher.
 * Provides methods to encrypt and decrypt text using an alphabetic key.
 */

public class VigenereCipher {
    /**
     * Sanitizes the key by removing non-letter characters and converting to uppercase.
     * @param key The input key
     * @return Sanitized key (uppercase letters only)
     */
    private static String sanitizeKey(String key) {
        if (key == null) throw new IllegalArgumentException("Key cannot be null");
        StringBuilder sanitized = new StringBuilder();
        for (char c : key.toCharArray()) {
            if (Character.isLetter(c)) {
                sanitized.append(Character.toUpperCase(c));
            }
        }
        if (sanitized.length() == 0) throw new IllegalArgumentException("Key must contain at least one letter");
        return sanitized.toString();
    }

    /**
     * Encrypts text using the Vigenère cipher.
     * @param text The text to encrypt
     * @param key The alphabetic key
     * @return The encrypted text
     */
    public static String encrypt(String text, String key) {
        String sanitizedKey = sanitizeKey(key);
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;
        for (char c : text.toCharArray()) {
            // Encrypt only letters, leave other characters unchanged
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int offset = (c - base + (sanitizedKey.charAt(keyIndex % sanitizedKey.length()) - 'A')) % 26;
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
        String sanitizedKey = sanitizeKey(key);
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;
        for (char c : text.toCharArray()) {
            // Decrypt only letters, leave other characters unchanged
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                int offset = (c - base - (sanitizedKey.charAt(keyIndex % sanitizedKey.length()) - 'A') + 26) % 26;
                result.append((char) (base + offset));
                keyIndex++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Example usage and basic tests for the Vigenère cipher.
     */
    public static void main(String[] args) {
        String text = "HELLO WORLD";
        String key = "KEY";
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Test with lowercase and mixed input
        String lowerText = "hello world";
        String lowerEncrypted = encrypt(lowerText, key);
        String lowerDecrypted = decrypt(lowerEncrypted, key);
        System.out.println("Encrypted (lowercase): " + lowerEncrypted);
        System.out.println("Decrypted (lowercase): " + lowerDecrypted);

        // Edge case: key with non-letters
        String weirdKey = "K3Y!";
        String weirdEncrypted = encrypt(text, weirdKey);
        String weirdDecrypted = decrypt(weirdEncrypted, weirdKey);
        System.out.println("Encrypted (weird key): " + weirdEncrypted);
        System.out.println("Decrypted (weird key): " + weirdDecrypted);
    }
}
