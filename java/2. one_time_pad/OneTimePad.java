// OneTimePad.java
// Java implementation of the One-Time Pad cipher
import java.util.Random;

public class OneTimePad {
    public static String encrypt(String text, String key) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            result.append((char) (text.charAt(i) ^ key.charAt(i)));
        }
        return result.toString();
    }

    public static String decrypt(String cipher, String key) {
        return encrypt(cipher, key); // XOR is symmetric
    }

    public static String generateKey(int length) {
        Random rand = new Random();
        StringBuilder key = new StringBuilder();
        for (int i = 0; i < length; i++) {
            key.append((char) (rand.nextInt(256)));
        }
        return key.toString();
    }

    public static void main(String[] args) {
        String text = "HELLO WORLD";
        String key = generateKey(text.length());
        String encrypted = encrypt(text, key);
        String decrypted = decrypt(encrypted, key);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
