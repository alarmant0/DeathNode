package pt.DeathNode.auth;

public class TokenRequest {
    private String issuerId;
    private int maxUses;
    private long validityHours;
    private String description;

    public TokenRequest() {}

    // Getters and setters
    public String getIssuerId() { return issuerId; }
    public void setIssuerId(String issuerId) { this.issuerId = issuerId; }

    public int getMaxUses() { return maxUses; }
    public void setMaxUses(int maxUses) { this.maxUses = maxUses; }

    public long getValidityHours() { return validityHours; }
    public void setValidityHours(long validityHours) { this.validityHours = validityHours; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
