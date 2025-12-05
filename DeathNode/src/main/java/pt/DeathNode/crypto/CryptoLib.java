package pt.DeathNode.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.Base64;

/**
 * Core cryptographic library for DeathNode secure documents.
 * 
 * Provides:
 * - Confidentiality: AES-256-GCM encryption
 * - Integrity: GCM authentication tag
 * - Authenticity: RSA digital signatures
 */
public class CryptoLib {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;  // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * Protect a report by encrypting and signing it.
     * 
     * @param report The plaintext report to protect
     * @param encryptionKey AES key for encryption
     * @param signingKey RSA private key for signing
     * @param signerId Identifier for the signer (pseudonym)
     * @return SecureDocument containing encrypted and signed data
     */
    public static SecureDocument protect(Report report, SecretKey encryptionKey, 
                                         PrivateKey signingKey, String signerId) throws Exception {
        
        // Convert report to JSON
        String plaintext = report.toJson();
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Encrypt with AES-GCM
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        
        // Create signature over the ciphertext (sign-then-encrypt pattern alternative: encrypt-then-sign)
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(signingKey);
        sig.update(ciphertext);
        byte[] signature = sig.sign();
        
        // Build secure document
        SecureDocument secDoc = new SecureDocument();
        secDoc.setIv(Base64.getEncoder().encodeToString(iv));
        secDoc.setEncryptedData(Base64.getEncoder().encodeToString(ciphertext));
        secDoc.setSignature(Base64.getEncoder().encodeToString(signature));
        secDoc.setSignerId(signerId);
        secDoc.setTimestamp(Instant.now().toString());
        
        return secDoc;
    }

    /**
     * Check the integrity and authenticity of a secure document.
     * Verifies the signature without decrypting.
     * 
     * @param secDoc The secure document to verify
     * @param verifyKey RSA public key of the signer
     * @return true if signature is valid, false otherwise
     */
    public static boolean check(SecureDocument secDoc, PublicKey verifyKey) throws Exception {
        
        // Decode ciphertext and signature
        byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
        byte[] signature = Base64.getDecoder().decode(secDoc.getSignature());
        
        // Verify signature
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(verifyKey);
        sig.update(ciphertext);
        
        return sig.verify(signature);
    }

    /**
     * Unprotect a secure document by verifying and decrypting it.
     * 
     * @param secDoc The secure document to unprotect
     * @param decryptionKey AES key for decryption
     * @param verifyKey RSA public key for signature verification
     * @return The original Report if verification and decryption succeed
     * @throws SecurityException if signature verification fails
     */
    public static Report unprotect(SecureDocument secDoc, SecretKey decryptionKey, 
                                   PublicKey verifyKey) throws Exception {
        
        // First verify the signature
        if (!check(secDoc, verifyKey)) {
            throw new SecurityException("Signature verification failed! Document may have been tampered with.");
        }
        
        // Decode IV and ciphertext
        byte[] iv = Base64.getDecoder().decode(secDoc.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
        
        // Decrypt with AES-GCM
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmSpec);
        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        
        // Parse JSON back to Report
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return Report.fromJson(plaintext);
    }

    /**
     * Verify document integrity using only the encryption key (GCM tag verification).
     * This checks if the ciphertext has been modified, without needing the signing key.
     * 
     * @param secDoc The secure document
     * @param decryptionKey AES key
     * @return true if GCM tag is valid (data integrity intact)
     */
    public static boolean verifyIntegrity(SecureDocument secDoc, SecretKey decryptionKey) {
        try {
            byte[] iv = Base64.getDecoder().decode(secDoc.getIv());
            byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
            
            Cipher cipher = Cipher.getInstance(AES_GCM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmSpec);
            cipher.doFinal(ciphertext);  // Will throw if tag verification fails
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
