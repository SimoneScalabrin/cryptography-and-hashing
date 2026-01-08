package java_implementation.hashing;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for computing SHA-256 hashes.
 */
public class SHA256 {
    /**
     * Computes the SHA-256 hash of a given string.
     *
     * @param input The input string to hash.
     * @return The SHA-256 hash as a hexadecimal string.
     */
    public static String sha256Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    /**
     * Example usage of the sha256Hash function.
     */
    public static void main(String[] args) {
        String[] texts = {
            "Hello, World!",
            "hello, world!",
            "The quick brown fox jumps over the lazy dog",
            "The quick brown fox jumps over the lazy dog."
        };
        System.out.println("SHA-256 hashes of different strings:");
        for (String text : texts) {
            System.out.println("Text: " + text);
            System.out.println("SHA-256 Hash: " + sha256Hash(text) + "\n");
        }

        // Compare hashes of similar strings
        String s1 = "password123";
        String s2 = "password124";
        String hash1 = sha256Hash(s1);
        String hash2 = sha256Hash(s2);
        System.out.println("Comparing hashes of similar strings:");
        System.out.println("String 1: " + s1 + " -> " + hash1);
        System.out.println("String 2: " + s2 + " -> " + hash2);
        System.out.println("Are hashes equal? " + (hash1.equals(hash2) ? "Yes" : "No"));
    }
}
