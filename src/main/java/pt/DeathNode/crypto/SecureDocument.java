package pt.DeathNode.crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

public class SecureDocument {

    @SerializedName("format")
    private String format = "DeathNode-Secure-v1";

    @SerializedName("algorithm")
    private String algorithm = "AES-256-GCM";

    @SerializedName("signature_algorithm")
    private String signatureAlgorithm = "SHA256withRSA";

    @SerializedName("iv")
    private String iv;

    @SerializedName("encrypted_data")
    private String encryptedData;

    @SerializedName("signature")
    private String signature;

    @SerializedName("signer_id")
    private String signerId;

    @SerializedName("timestamp")
    private String timestamp;

    @SerializedName("sequence_number")
    private Long sequenceNumber;

    @SerializedName("previous_hash")
    private String previousHash;

    public SecureDocument() {}

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

    public String getIv() { return iv; }
    public void setIv(String iv) { this.iv = iv; }

    public String getEncryptedData() { return encryptedData; }
    public void setEncryptedData(String encryptedData) { this.encryptedData = encryptedData; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public String getSignerId() { return signerId; }
    public void setSignerId(String signerId) { this.signerId = signerId; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public Long getSequenceNumber() { return sequenceNumber; }
    public void setSequenceNumber(Long sequenceNumber) { this.sequenceNumber = sequenceNumber; }

    public String getPreviousHash() { return previousHash; }
    public void setPreviousHash(String previousHash) { this.previousHash = previousHash; }

    public String toJson() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }

    public static SecureDocument fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, SecureDocument.class);
    }

    @Override
    public String toString() {
        return toJson();
    }
}
