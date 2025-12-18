package pt.DeathNode.crypto;

import com.google.gson.Gson;
import pt.DeathNode.auth.*;
import pt.DeathNode.util.EndpointConfig;
import pt.DeathNode.util.TlsConfig;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TokenManager {
    private static final String GATEWAY_URL = EndpointConfig.getGatewayUrl();
    private static HttpClient client = HttpClient.newHttpClient();
    private static final Gson gson = new Gson();

    private static synchronized void ensureTlsClient() {
        try {
            TlsConfig.installClientTlsFromEnvIfPresent();
            client = HttpClient.newBuilder().sslContext(javax.net.ssl.SSLContext.getDefault()).build();
        } catch (Exception ignored) {
        }
    }

    public static InvitationToken createToken(String issuerId, int maxUses, long validityHours, String description) throws Exception {
        ensureTlsClient();
        TokenRequest request = new TokenRequest();
        request.setIssuerId(issuerId);
        request.setMaxUses(maxUses);
        request.setValidityHours(validityHours);
        request.setDescription(description);

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(GATEWAY_URL + "/api/auth/tokens/create"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(request)))
                .build();

        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return gson.fromJson(response.body(), InvitationToken.class);
        } else {
            throw new Exception("Failed to create token: " + response.body());
        }
    }

    public static TokenValidationResponse validateToken(String tokenId, boolean consume) throws Exception {
        ensureTlsClient();
        TokenValidationRequest request = new TokenValidationRequest(tokenId, consume);

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(GATEWAY_URL + "/api/auth/tokens/validate"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(request)))
                .build();

        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return gson.fromJson(response.body(), TokenValidationResponse.class);
        } else {
            throw new Exception("Failed to validate token: " + response.body());
        }
    }

    public static void main(String[] args) throws Exception {
        ensureTlsClient();

        if (args.length < 4) {
            System.out.println("Usage: TokenManager <issuerId> <maxUses> <validityHours> <description>");
            return;
        }

        String issuerId = args[0];
        int maxUses = Integer.parseInt(args[1]);
        long validityHours = Long.parseLong(args[2]);
        String description = args[3];

        try {
            InvitationToken token = createToken(issuerId, maxUses, validityHours, description);
            System.out.println("Token created successfully:");
            System.out.println("Token ID: " + token.getTokenId());
            System.out.println("Issuer: " + token.getIssuerId());
            System.out.println("Description: " + token.getDescription());
            System.out.println("Max uses: " + token.getMaxUses());
            System.out.println("Expires: " + token.getExpiresAt());
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
