package pt.DeathNode.auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.util.EndpointConfig;
import pt.DeathNode.util.TlsConfig;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class ClientMain {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    public static void main(String[] args) throws Exception {
        String userId = null;
        String serverHost = "localhost";
        int serverPort = 9090;
        String gatewayUrl = EndpointConfig.getGatewayUrl();

        for (int i = 0; i < args.length; i++) {
            if ("--user".equals(args[i]) && i + 1 < args.length) {
                userId = args[++i];
            } else if ("--server-host".equals(args[i]) && i + 1 < args.length) {
                serverHost = args[++i];
            } else if ("--server-port".equals(args[i]) && i + 1 < args.length) {
                serverPort = Integer.parseInt(args[++i]);
            }
        }

        if (serverHost != null && !serverHost.isBlank()) {
            String scheme = gatewayUrl != null && gatewayUrl.trim().toLowerCase().startsWith("https://") ? "https" : "http";
            gatewayUrl = scheme + "://" + serverHost + ":" + serverPort;
        }

        TlsConfig.installClientTlsFromEnvIfPresent();

        if (userId == null || userId.isBlank()) {
            System.err.println("Missing --user parameter");
            System.exit(1);
        }

        ensureUserKeys(userId);
        AuthToken token = loadTokenIfPresent(userId);

        if (token == null || token.isExpired()) {
            System.out.println("No valid token for user '" + userId + "'. Requesting new one from server...");
            token = requestTokenFromServer(userId, gatewayUrl);
            saveToken(userId, token);
            System.out.println("Received token for user '" + userId + "' valid until " + token.getExpiresAt());
        } else {
            System.out.println("Using existing valid token for user '" + userId + "' valid until " + token.getExpiresAt());
        }

        System.out.println("Client setup complete for user '" + userId + "'.");
        System.out.println("You can now use this VM as a DeathNode client (Alice/Bob) with authorized credentials.");
    }

    private static void ensureUserKeys(String userId) throws Exception {
        Path symPath = Paths.get("keys", userId + ".key");
        Path privPath = Paths.get("keys", userId + ".priv");
        Path pubPath = Paths.get("keys", userId + ".pub");

        if (Files.exists(symPath) && Files.exists(privPath) && Files.exists(pubPath)) {
            return;
        }

        System.out.println("Generating keys for user '" + userId + "'...");
        SecretKey symKey = KeyManager.generateSymmetricKey();
        KeyManager.saveSymmetricKey(symKey, userId);

        KeyPair kp = KeyManager.generateKeyPair();
        KeyManager.saveKeyPair(kp, userId);
    }

    private static AuthToken loadTokenIfPresent(String userId) {
        try {
            Path tokenPath = Paths.get("keys", userId + ".token");
            if (!Files.exists(tokenPath)) {
                return null;
            }
            String json = Files.readString(tokenPath);
            return GSON.fromJson(json, AuthToken.class);
        } catch (IOException e) {
            return null;
        }
    }

    private static void saveToken(String userId, AuthToken token) throws IOException {
        Path tokenPath = Paths.get("keys", userId + ".token");
        String json = GSON.toJson(token);
        Files.writeString(tokenPath, json);
    }

    private static AuthToken requestTokenFromServer(String userId, String gatewayUrl) throws Exception {
        PublicKey pubKey = KeyManager.loadPublicKey(userId);
        String base64Pub = Base64.getEncoder().encodeToString(pubKey.getEncoded());

        JoinRequest req = new JoinRequest();
        req.setPseudonym(userId);
        req.setClientPublicKey(base64Pub);

        String json = GSON.toJson(req);
        byte[] body = json.getBytes(StandardCharsets.UTF_8);

        URL url = new URL(gatewayUrl + "/api/auth/join");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }

        int code = conn.getResponseCode();
        byte[] respBytes;
        if (code == 200) {
            respBytes = conn.getInputStream().readAllBytes();
        } else {
            respBytes = conn.getErrorStream() != null ? conn.getErrorStream().readAllBytes() : new byte[0];
            String msg = new String(respBytes, StandardCharsets.UTF_8);
            throw new IOException("Server returned status " + code + ": " + msg);
        }

        String respJson = new String(respBytes, StandardCharsets.UTF_8);
        return GSON.fromJson(respJson, AuthToken.class);
    }
}
