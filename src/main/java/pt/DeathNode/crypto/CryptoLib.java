package pt.DeathNode.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
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

        SecureDocument secDoc = new SecureDocument();
        secDoc.setIv(Base64.getEncoder().encodeToString(iv));
        secDoc.setEncryptedData(Base64.getEncoder().encodeToString(ciphertext));
        secDoc.setSignerId(signerId);
        secDoc.setTimestamp(Instant.now().toString());
        if (sequenceNumber != null) {
            secDoc.setSequenceNumber(sequenceNumber);
        }
        if (previousHash != null) {
            secDoc.setPreviousHash(previousHash);
        }

        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(signingKey);
        sig.update(buildSignaturePayload(secDoc));
        byte[] signature = sig.sign();
        secDoc.setSignature(Base64.getEncoder().encodeToString(signature));
        
        return secDoc;
    }

    public static boolean check(SecureDocument secDoc, PublicKey verifyKey) throws Exception {

        byte[] signature = Base64.getDecoder().decode(secDoc.getSignature());

        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(verifyKey);
        sig.update(buildSignaturePayload(secDoc));
        if (sig.verify(signature)) {
            return true;
        }

        byte[] ciphertext = Base64.getDecoder().decode(secDoc.getEncryptedData());
        Signature legacy = Signature.getInstance(SIGNATURE_ALGORITHM);
        legacy.initVerify(verifyKey);
        legacy.update(ciphertext);
        return legacy.verify(signature);
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

    public static String computeChainHash(SecureDocument secDoc) throws Exception {
        if (secDoc == null) {
            throw new IllegalArgumentException("SecureDocument is null");
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        if (secDoc.getIv() != null) {
            md.update(Base64.getDecoder().decode(secDoc.getIv()));
        }
        if (secDoc.getEncryptedData() != null) {
            md.update(Base64.getDecoder().decode(secDoc.getEncryptedData()));
        }
        if (secDoc.getSignature() != null) {
            md.update(Base64.getDecoder().decode(secDoc.getSignature()));
        }

        if (secDoc.getSignerId() != null) {
            md.update(secDoc.getSignerId().getBytes(StandardCharsets.UTF_8));
        }
        if (secDoc.getTimestamp() != null) {
            md.update(secDoc.getTimestamp().getBytes(StandardCharsets.UTF_8));
        }

        long seq = secDoc.getSequenceNumber() == null ? 0L : secDoc.getSequenceNumber();
        md.update(ByteBuffer.allocate(Long.BYTES).putLong(seq).array());

        return Base64.getEncoder().encodeToString(md.digest());
    }

    private static byte[] buildSignaturePayload(SecureDocument secDoc) {
        byte[] iv = secDoc.getIv() == null ? new byte[0] : Base64.getDecoder().decode(secDoc.getIv());
        byte[] ciphertext = secDoc.getEncryptedData() == null ? new byte[0] : Base64.getDecoder().decode(secDoc.getEncryptedData());
        byte[] signer = secDoc.getSignerId() == null ? new byte[0] : secDoc.getSignerId().getBytes(StandardCharsets.UTF_8);
        byte[] ts = secDoc.getTimestamp() == null ? new byte[0] : secDoc.getTimestamp().getBytes(StandardCharsets.UTF_8);
        long seq = secDoc.getSequenceNumber() == null ? 0L : secDoc.getSequenceNumber();
        byte[] seqBytes = ByteBuffer.allocate(Long.BYTES).putLong(seq).array();
        byte[] prev = secDoc.getPreviousHash() == null ? new byte[0] : secDoc.getPreviousHash().getBytes(StandardCharsets.UTF_8);

        ByteBuffer bb = ByteBuffer.allocate(iv.length + ciphertext.length + signer.length + ts.length + seqBytes.length + prev.length);
        bb.put(iv);
        bb.put(ciphertext);
        bb.put(signer);
        bb.put(ts);
        bb.put(seqBytes);
        bb.put(prev);
        return bb.array();
    }
}
