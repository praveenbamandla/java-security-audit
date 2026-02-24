import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Standalone demo application showcasing both strong (modern) and weak (outdated)
 * encryption and hashing algorithms.
 *
 * Compile:  javac CryptoDemo.java
 * Run:      java CryptoDemo
 *
 * WARNING: The weak algorithms are included for educational purposes only.
 * Never use them in production systems.
 */
public class CryptoDemo {

    private static final String PLAINTEXT = "Hello, Cryptography World!";
    private static final String SEPARATOR = "=".repeat(60);

    public static void main(String[] args) throws Exception {
        System.out.println(SEPARATOR);
        System.out.println("       CRYPTOGRAPHY DEMO — Strong vs. Weak Algorithms");
        System.out.println(SEPARATOR);

        // ── Hashing ──
        System.out.println("\n>>> HASHING <<<\n");

        System.out.println("[WEAK] MD5 hash:");
        System.out.println("  " + hash("MD5", PLAINTEXT));

        System.out.println("[WEAK] SHA-1 hash:");
        System.out.println("  " + hash("SHA-1", PLAINTEXT));

        System.out.println("[STRONG] SHA-256 hash:");
        System.out.println("  " + hash("SHA-256", PLAINTEXT));

        System.out.println("[STRONG] SHA-512 hash:");
        System.out.println("  " + hash("SHA-512", PLAINTEXT));

        System.out.println("[STRONG] PBKDF2 derived key (password hashing):");
        System.out.println("  " + pbkdf2("MyS3cretP@ssw0"));

        // ── Symmetric Encryption ──
        System.out.println("\n>>> SYMMETRIC ENCRYPTION <<<\n");

        demoDES();
        demoRC4();
        demoAES_ECB();
        demoAES();

        System.out.println("\n" + SEPARATOR);
        System.out.println("Demo complete.");
    }

    // ────────────────────────────────────────────────────────────
    //  Hashing helpers
    // ────────────────────────────────────────────────────────────

    private static String hash(String algorithm, String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    private static String pbkdf2(String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 310_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] derived = factory.generateSecret(spec).getEncoded();

        return "salt=" + bytesToHex(salt) + "  key=" + bytesToHex(derived);
    }

    // ────────────────────────────────────────────────────────────
    //  Weak: DES (56-bit key, broken)
    // ────────────────────────────────────────────────────────────

    private static void demoDES() throws Exception {
        System.out.println("[WEAK] DES encryption (56-bit key):");

        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56);
        SecretKey desKey = keyGen.generateKey();

        // DES in ECB mode (also weak) for simplicity
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] encrypted = cipher.doFinal(PLAINTEXT.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("  Encrypted : " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("  Decrypted : " + new String(decrypted, StandardCharsets.UTF_8));
    }

    // ────────────────────────────────────────────────────────────
    //  Weak: RC4 (stream cipher, multiple known attacks)
    // ────────────────────────────────────────────────────────────

    private static void demoRC4() throws Exception {
        System.out.println("[WEAK] RC4 / ARCFOUR encryption:");

        KeyGenerator keyGen = KeyGenerator.getInstance("ARCFOUR");
        keyGen.init(128);
        SecretKey rc4Key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("ARCFOUR");
        cipher.init(Cipher.ENCRYPT_MODE, rc4Key);
        byte[] encrypted = cipher.doFinal(PLAINTEXT.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, rc4Key);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("  Encrypted : " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("  Decrypted : " + new String(decrypted, StandardCharsets.UTF_8));
    }

    // ────────────────────────────────────────────────────────────
    //  Weak config: AES-256 in ECB mode (no IV, block-level patterns leak)
    // ────────────────────────────────────────────────────────────

    private static void demoAES_ECB() throws Exception {
        System.out.println("[WEAK] AES-256/ECB encryption (weak mode):");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(PLAINTEXT.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("  Encrypted : " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("  Decrypted : " + new String(decrypted, StandardCharsets.UTF_8));
    }

    // ────────────────────────────────────────────────────────────
    //  Strong: AES-256 in CBC mode with random IV
    // ────────────────────────────────────────────────────────────

    private static void demoAES() throws Exception {
        System.out.println("[STRONG] AES-256/CBC encryption:");

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] encrypted = cipher.doFinal(PLAINTEXT.getBytes(StandardCharsets.UTF_8));

        cipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);

        System.out.println("  IV        : " + bytesToHex(iv));
        System.out.println("  Encrypted : " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("  Decrypted : " + new String(decrypted, StandardCharsets.UTF_8));
    }

    // ────────────────────────────────────────────────────────────
    //  Utility
    // ────────────────────────────────────────────────────────────

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
