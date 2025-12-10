package pt.DeathNode.auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import pt.DeathNode.crypto.KeyManager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

public class AuthServerMain {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SERVER_KEY_NAME = "server";

    private static final Gson GSON = new GsonBuilder().create();

    public static void main(String[] args) throws Exception {
        int port = 8080;
        long tokenValidityMinutes = 10;

        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--token-minutes".equals(args[i]) && i + 1 < args.length) {
                tokenValidityMinutes = Long.parseLong(args[++i]);
            }
        }

        ensureServerKeys();
        PrivateKey privateKey = KeyManager.loadPrivateKey(SERVER_KEY_NAME);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        long finalTokenValidityMinutes = tokenValidityMinutes;

        server.createContext("/join", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                byte[] body = exchange.getRequestBody().readAllBytes();
                String json = new String(body, StandardCharsets.UTF_8);
                JoinRequest req = GSON.fromJson(json, JoinRequest.class);

                if (req == null || req.getPseudonym() == null || req.getClientPublicKey() == null) {
                    String msg = "Invalid join request";
                    byte[] respBytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(400, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                    return;
                }

                try {
                    AuthToken token = createToken(req, privateKey, finalTokenValidityMinutes);
                    String respJson = GSON.toJson(token);
                    byte[] respBytes = respJson.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                } catch (Exception e) {
                    String msg = "Error: " + e.getMessage();
                    byte[] respBytes = msg.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                }
            }
        });

        server.start();
        System.out.println("Auth server listening on port " + port);
    }

    private static void ensureServerKeys() throws Exception {
        try {
            KeyManager.loadPrivateKey(SERVER_KEY_NAME);
        } catch (Exception e) {
            System.out.println("Generating server keys...");
            KeyPair kp = KeyManager.generateKeyPair();
            KeyManager.saveKeyPair(kp, SERVER_KEY_NAME);
        }
    }

    private static AuthToken createToken(JoinRequest req, PrivateKey serverPrivateKey, long validityMinutes) throws Exception {
        AuthToken token = new AuthToken();
        token.setPseudonym(req.getPseudonym());
        token.setClientPublicKey(req.getClientPublicKey());

        Instant now = Instant.now();
        Instant expiry = now.plus(validityMinutes, ChronoUnit.MINUTES);
        token.setIssuedAt(now.toString());
        token.setExpiresAt(expiry.toString());

        String payload = token.getPseudonym() + "|" + token.getClientPublicKey() + "|" + token.getIssuedAt() + "|" + token.getExpiresAt();
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(serverPrivateKey);
        sig.update(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        token.setSignature(Base64.getEncoder().encodeToString(signature));

        return token;
    }

    public static boolean verifyToken(AuthToken token, PublicKey serverPublicKey) {
        if (token == null || token.isExpired()) {
            return false;
        }
        try {
            String payload = token.getPseudonym() + "|" + token.getClientPublicKey() + "|" + token.getIssuedAt() + "|" + token.getExpiresAt();
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(serverPublicKey);
            sig.update(payload.getBytes(StandardCharsets.UTF_8));
            byte[] signature = Base64.getDecoder().decode(token.getSignature());
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    public static PublicKey decodeClientPublicKey(String base64Key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }
}
