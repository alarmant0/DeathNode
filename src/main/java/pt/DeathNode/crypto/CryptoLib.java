package pt.DeathNode.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.Base64;

public class CryptoLib {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    public static SecureDocument protect(Report report, SecretKey encryptionKey,
                                         PrivateKey signingKey, String signerId) throws Exception {
        return protect(report, encryptionKey, signingKey, signerId, null, null);
    }

    public static SecureDocument protect(Report report, SecretKey encryptionKey,
                                         PrivateKey signingKey, String signerId,
                                         Long sequenceNumber, String previousHash) throws Exception {

        String plaintext = report.toJson();
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintextBytes);
        
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(signingKey);
        sig.update(ciphertext);
        byte[] signature = sig.sign();
        
        SecureDocument secDoc = new SecureDocument();
        secDoc.setIv(Base64.getEncoder().encodeToString(iv));
        secDoc.setEncryptedData(Base64.getEncoder().encodeToString(ciphertext));
        secDoc.setSignature(Base64.getEncoder().encodeToString(signature));
        secDoc.setSignerId(signerId);
        secDoc.setTimestamp(Instant.now().toString());
        if (sequenceNumber != null) {
            secDoc.setSequenceNumber(sequenceNumber);
        }
        if (previousHash != null) {
            secDoc.setPreviousHash(previousHash);
        }
        
        return secDoc;
    }

    public static boolean check(SecureDocument secDoc, PublicKey verifyKey) throws Exception {
        
        byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
        byte[] signature = Base64.getDecoder().decode(secDoc.getSignature());
        
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(verifyKey);
        sig.update(ciphertext);
        
        return sig.verify(signature);
    }

    public static Report unprotect(SecureDocument secDoc, SecretKey decryptionKey, 
                                   PublicKey verifyKey) throws Exception {
        
        if (!check(secDoc, verifyKey)) {
            throw new SecurityException("Signature verification failed! Document may have been tampered with.");
        }
        
        byte[] iv = Base64.getDecoder().decode(secDoc.getIv());
        byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
        
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmSpec);
        byte[] plaintextBytes = cipher.doFinal(ciphertext);
        
        String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
        return Report.fromJson(plaintext);
    }

    public static boolean verifyIntegrity(SecureDocument secDoc, SecretKey decryptionKey) {
        try {
            byte[] iv = Base64.getDecoder().decode(secDoc.getIv());
            byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
            
            Cipher cipher = Cipher.getInstance(AES_GCM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, decryptionKey, gcmSpec);
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
