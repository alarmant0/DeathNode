package pt.DeathNode.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Manages cryptographic keys for DeathNode.
 * Handles generation, storage, and loading of symmetric and asymmetric keys.
 */
public class KeyManager {

    private static final String KEYS_DIR = "keys";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    /**
     * Generate a new AES-256 symmetric key.
     */
    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    /**
     * Generate a new RSA key pair for signing.
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    /**
     * Save a symmetric key to file (Base64 encoded).
     */
    public static void saveSymmetricKey(SecretKey key, String filename) throws IOException {
        ensureKeysDir();
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        Path path = Paths.get(KEYS_DIR, filename + ".key");
        Files.writeString(path, encoded);
    }

    /**
     * Load a symmetric key from file.
     */
    public static SecretKey loadSymmetricKey(String filename) throws IOException {
        Path path = Paths.get(filename);
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename + ".key");
        }
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename);
        }
        String encoded = Files.readString(path).trim();
        byte[] decoded = Base64.getDecoder().decode(encoded);
        return new SecretKeySpec(decoded, "AES");
    }

    /**
     * Save RSA key pair to files.
     */
    public static void saveKeyPair(KeyPair keyPair, String name) throws IOException {
        ensureKeysDir();
        
        // Save private key
        String privateEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        Files.writeString(Paths.get(KEYS_DIR, name + ".priv"), privateEncoded);
        
        // Save public key
        String publicEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Files.writeString(Paths.get(KEYS_DIR, name + ".pub"), publicEncoded);
    }

    /**
     * Load RSA private key from file.
     */
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        Path path = Paths.get(filename);
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename + ".priv");
        }
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename);
        }
        String encoded = Files.readString(path).trim();
        byte[] decoded = Base64.getDecoder().decode(encoded);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(spec);
    }

    /**
     * Load RSA public key from file.
     */
    public static PublicKey loadPublicKey(String filename) throws Exception {
        Path path = Paths.get(filename);
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename + ".pub");
        }
        if (!Files.exists(path)) {
            path = Paths.get(KEYS_DIR, filename);
        }
        String encoded = Files.readString(path).trim();
        byte[] decoded = Base64.getDecoder().decode(encoded);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    /**
     * Generate dummy keys for testing.
     */
    public static void generateDummyKeys(String userId) throws Exception {
        ensureKeysDir();
        
        // Generate and save symmetric key
        SecretKey symKey = generateSymmetricKey();
        saveSymmetricKey(symKey, userId);
        
        // Generate and save key pair
        KeyPair keyPair = generateKeyPair();
        saveKeyPair(keyPair, userId);
        
        System.out.println("Generated keys for user: " + userId);
        System.out.println("  - Symmetric key: keys/" + userId + ".key");
        System.out.println("  - Private key:   keys/" + userId + ".priv");
        System.out.println("  - Public key:    keys/" + userId + ".pub");
    }

    private static void ensureKeysDir() throws IOException {
        Path keysPath = Paths.get(KEYS_DIR);
        if (!Files.exists(keysPath)) {
            Files.createDirectories(keysPath);
        }
    }
}
