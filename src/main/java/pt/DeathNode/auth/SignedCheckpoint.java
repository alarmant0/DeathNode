package pt.DeathNode.auth;

import java.time.Instant;

public class SignedCheckpoint {

    private String signerId;
    private long lastSequenceNumber;
    private String lastHash;
    private String issuedAt;
    private String signature;

    public SignedCheckpoint() {
    }

    public String getSignerId() {
        return signerId;
    }

    public void setSignerId(String signerId) {
        this.signerId = signerId;
    }

    public long getLastSequenceNumber() {
        return lastSequenceNumber;
    }

    public void setLastSequenceNumber(long lastSequenceNumber) {
        this.lastSequenceNumber = lastSequenceNumber;
    }

    public String getLastHash() {
        return lastHash;
    }

    public void setLastHash(String lastHash) {
        this.lastHash = lastHash;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public static SignedCheckpoint create(String signerId, long lastSequenceNumber, String lastHash) {
        SignedCheckpoint cp = new SignedCheckpoint();
        cp.setSignerId(signerId);
        cp.setLastSequenceNumber(lastSequenceNumber);
        cp.setLastHash(lastHash);
        cp.setIssuedAt(Instant.now().toString());
        return cp;
    }
}
