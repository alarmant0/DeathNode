package pt.DeathNode.auth;

import com.google.gson.Gson;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

public class InvitationToken {
    private String tokenId;
    private String issuerId;
    private String issuedAt;
    private String expiresAt;
    private int maxUses;
    private int currentUses;
    private boolean active;
    private String description;

    public InvitationToken() {
        this.active = true;
        this.currentUses = 0;
    }

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static InvitationToken create(String issuerId, int maxUses, long validityHours, String description) {
        InvitationToken token = new InvitationToken();

        byte[] raw = new byte[16];
        SECURE_RANDOM.nextBytes(raw);
        token.tokenId = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        token.issuerId = issuerId;
        token.issuedAt = Instant.now().toString();
        token.expiresAt = Instant.now().plus(validityHours, ChronoUnit.HOURS).toString();
        token.maxUses = maxUses;
        token.description = description;
        return token;
    }

    public boolean isValid() {
        if (!active) return false;
        if (currentUses >= maxUses) return false;
        return Instant.now().isBefore(Instant.parse(expiresAt));
    }

    public boolean useToken() {
        if (!isValid()) return false;
        currentUses++;
        if (currentUses >= maxUses) {
            active = false;
        }
        return true;
    }

    public String toJson() {
        return new Gson().toJson(this);
    }

    public static InvitationToken fromJson(String json) {
        return new Gson().fromJson(json, InvitationToken.class);
    }

    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }

    public String getIssuerId() { return issuerId; }
    public void setIssuerId(String issuerId) { this.issuerId = issuerId; }

    public String getIssuedAt() { return issuedAt; }
    public void setIssuedAt(String issuedAt) { this.issuedAt = issuedAt; }

    public String getExpiresAt() { return expiresAt; }
    public void setExpiresAt(String expiresAt) { this.expiresAt = expiresAt; }

    public int getMaxUses() { return maxUses; }
    public void setMaxUses(int maxUses) { this.maxUses = maxUses; }

    public int getCurrentUses() { return currentUses; }
    public void setCurrentUses(int currentUses) { this.currentUses = currentUses; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
