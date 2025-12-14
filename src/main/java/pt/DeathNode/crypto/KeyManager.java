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

public class KeyManager {

    private static final String KEYS_DIR = "keys";
    private static final int AES_KEY_SIZE = 256;
    private static final int RSA_KEY_SIZE = 2048;

    public static SecretKey generateSymmetricKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static void saveSymmetricKey(SecretKey key, String filename) throws IOException {
        ensureKeysDir();
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        Path path = Paths.get(KEYS_DIR, filename + ".key");
        Files.writeString(path, encoded);
    }

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

    public static void saveKeyPair(KeyPair keyPair, String name) throws IOException {
        ensureKeysDir();
        
        String privateEncoded = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        Files.writeString(Paths.get(KEYS_DIR, name + ".priv"), privateEncoded);
        
        String publicEncoded = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        Files.writeString(Paths.get(KEYS_DIR, name + ".pub"), publicEncoded);
    }

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

    public static void generateDummyKeys(String userId) throws Exception {
        ensureKeysDir();
        
        SecretKey symKey = generateSymmetricKey();
        saveSymmetricKey(symKey, userId);
        
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
