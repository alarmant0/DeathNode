package pt.DeathNode.auth;

public class TokenValidationRequest {
    private String tokenId;
    private boolean consume;

    public TokenValidationRequest() {}

    public TokenValidationRequest(String tokenId, boolean consume) {
        this.tokenId = tokenId;
        this.consume = consume;
    }

    // Getters and setters
    public String getTokenId() { return tokenId; }
    public void setTokenId(String tokenId) { this.tokenId = tokenId; }

    public boolean isConsume() { return consume; }
    public void setConsume(boolean consume) { this.consume = consume; }
}
