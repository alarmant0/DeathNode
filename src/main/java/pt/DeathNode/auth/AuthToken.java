package pt.DeathNode.auth;

import java.time.Instant;

public class AuthToken {

    private String pseudonym;
    private String clientPublicKey;
    private String issuedAt;
    private String expiresAt;
    private String signature;

    public String getPseudonym() {
        return pseudonym;
    }

    public void setPseudonym(String pseudonym) {
        this.pseudonym = pseudonym;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(String expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        Instant expiry = Instant.parse(expiresAt);
        return Instant.now().isAfter(expiry);
    }
}
