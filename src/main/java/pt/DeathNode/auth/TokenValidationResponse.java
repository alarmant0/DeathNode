package pt.DeathNode.auth;

public class TokenValidationResponse {
    private boolean valid;
    private InvitationToken token;

    public TokenValidationResponse() {}

    public TokenValidationResponse(boolean valid, InvitationToken token) {
        this.valid = valid;
        this.token = token;
    }

    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }

    public InvitationToken getToken() { return token; }
    public void setToken(InvitationToken token) { this.token = token; }
}
