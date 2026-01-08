package java_implementation.hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class for computing MD5 hashes.
 */
public class MD5 {
    /**
     * Computes the MD5 hash of a given string.
     *
     * @param input The input string to hash.
     * @return The MD5 hash as a hexadecimal string.
     */
    public static String md5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }

    /**
     * Example usage of the md5Hash function.
     */
    public static void main(String[] args) {
        String[] texts = {
            "Hello, World!",
            "hello, world!",
            "The quick brown fox jumps over the lazy dog",
            "The quick brown fox jumps over the lazy dog."
        };
        System.out.println("MD5 hashes of different strings:");
        for (String text : texts) {
            System.out.println("Text: " + text);
            System.out.println("MD5 Hash: " + md5Hash(text) + "\n");
        }

        // Compare hashes of similar strings
        String s1 = "password123";
        String s2 = "password124";
        String hash1 = md5Hash(s1);
        String hash2 = md5Hash(s2);
        System.out.println("Comparing hashes of similar strings:");
        System.out.println("String 1: " + s1 + " -> " + hash1);
        System.out.println("String 2: " + s2 + " -> " + hash2);
        System.out.println("Are hashes equal? " + (hash1.equals(hash2) ? "Yes" : "No"));
    }
}
