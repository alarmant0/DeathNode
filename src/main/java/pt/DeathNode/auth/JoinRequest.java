package pt.DeathNode.auth;

public class JoinRequest {

    private String pseudonym;
    private String clientPublicKey;
    private String invitationTokenId;

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

    public String getInvitationTokenId() {
        return invitationTokenId;
    }

    public void setInvitationTokenId(String invitationTokenId) {
        this.invitationTokenId = invitationTokenId;
    }
}
