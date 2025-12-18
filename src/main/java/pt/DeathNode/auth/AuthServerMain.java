package pt.DeathNode.auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.crypto.SecureDocument;
import pt.DeathNode.crypto.CryptoLib;
import pt.DeathNode.util.TlsConfig;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

public class AuthServerMain {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SERVER_KEY_NAME = "server";

    private static final Gson GSON = new GsonBuilder().create();

    private static final String DB_URL = "jdbc:sqlite:db/deathnode.db";
    private static Connection DB_CONNECTION;
    private static final ConcurrentHashMap<String, InvitationToken> tokenCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Boolean> authorizedUsers = new ConcurrentHashMap<>();

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
        initDatabase();
        PrivateKey privateKey = KeyManager.loadPrivateKey(SERVER_KEY_NAME);

        HttpServer server;
        if (TlsConfig.isTlsEnabled()) {
            javax.net.ssl.SSLContext sslContext = TlsConfig.buildSslContextFromEnv();
            HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress(port), 0);
            httpsServer.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                @Override
                public void configure(HttpsParameters params) {
                    javax.net.ssl.SSLParameters sslParams = getSSLContext().getDefaultSSLParameters();
                    params.setSSLParameters(sslParams);
                    String require = System.getenv("DEATHNODE_TLS_REQUIRE_CLIENT_AUTH");
                    if (require != null && require.trim().equalsIgnoreCase("true")) {
                        params.setNeedClientAuth(true);
                    }
                }
            });
            server = httpsServer;
        } else {
            server = HttpServer.create(new InetSocketAddress(port), 0);
        }
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

        server.createContext("/tokens/create", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                try {
                    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                    TokenRequest req = GSON.fromJson(body, TokenRequest.class);
                    
                    if (!isValidUser(req.getIssuerId())) {
                        String response = "{\"error\":\"Invalid issuer\"}";
                        byte[] respBytes = response.getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(403, respBytes.length);
                        try (OutputStream os = exchange.getResponseBody()) {
                            os.write(respBytes);
                        }
                        return;
                    }
                    
                    InvitationToken token = InvitationToken.create(
                        req.getIssuerId(), 
                        req.getMaxUses(), 
                        req.getValidityHours(), 
                        req.getDescription()
                    );
                    
                    tokenCache.put(token.getTokenId(), token);
                    saveTokenToDatabase(token);
                    
                    String response = GSON.toJson(token);
                    byte[] respBytes = response.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                } catch (Exception e) {
                    String response = "{\"error\":\"" + e.getMessage() + "\"}";
                    byte[] respBytes = response.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                }
            }
        });

        server.createContext("/tokens/validate", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                try {
                    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                    TokenValidationRequest req = GSON.fromJson(body, TokenValidationRequest.class);
                    
                    InvitationToken token = tokenCache.get(req.getTokenId());
                    boolean valid = token != null && token.isValid();
                    
                    if (valid && req.isConsume()) {
                        token.useToken();
                        saveTokenToDatabase(token);
                    }
                    
                    TokenValidationResponse response = new TokenValidationResponse(valid, token);
                    String responseJson = GSON.toJson(response);
                    byte[] respBytes = responseJson.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                } catch (Exception e) {
                    String response = "{\"error\":\"" + e.getMessage() + "\"}";
                    byte[] respBytes = response.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(500, respBytes.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(respBytes);
                    }
                }
            }
        });

        server.createContext("/reports", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String method = exchange.getRequestMethod();
                try {
                    if ("POST".equalsIgnoreCase(method)) {
                        handleStoreReport(exchange);
                    } else if ("GET".equalsIgnoreCase(method)) {
                        handleListReports(exchange);
                    } else {
                        exchange.sendResponseHeaders(405, -1);
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

        server.createContext("/checkpoints", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                try {
                    Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
                    String signer = query.get("signer");

                    List<SignedCheckpoint> cps = buildSignedCheckpoints(privateKey, signer);
                    String respJson = GSON.toJson(cps);
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

    public static boolean verifyCheckpoint(SignedCheckpoint cp, PublicKey serverPublicKey) {
        if (cp == null || cp.getSignerId() == null || cp.getIssuedAt() == null || cp.getSignature() == null) {
            return false;
        }
        try {
            String payload = checkpointPayload(cp);
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(serverPublicKey);
            sig.update(payload.getBytes(StandardCharsets.UTF_8));
            byte[] signature = Base64.getDecoder().decode(cp.getSignature());
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static String checkpointPayload(SignedCheckpoint cp) {
        String lastHash = cp.getLastHash() == null ? "" : cp.getLastHash();
        return cp.getSignerId() + "|" + cp.getLastSequenceNumber() + "|" + lastHash + "|" + cp.getIssuedAt();
    }

    private static SignedCheckpoint signCheckpoint(SignedCheckpoint cp, PrivateKey serverPrivateKey) throws Exception {
        String payload = checkpointPayload(cp);
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initSign(serverPrivateKey);
        sig.update(payload.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        cp.setSignature(Base64.getEncoder().encodeToString(signature));
        return cp;
    }

    private static List<SignedCheckpoint> buildSignedCheckpoints(PrivateKey serverPrivateKey, String onlySigner) throws Exception {
        List<SignedCheckpoint> out = new ArrayList<>();

        List<SignerHead> heads = loadLatestHeads(onlySigner);
        for (SignerHead h : heads) {
            SignedCheckpoint cp = SignedCheckpoint.create(h.signerId, h.lastSeq, h.lastHash);
            signCheckpoint(cp, serverPrivateKey);
            out.add(cp);
        }

        return out;
    }

    private static final class SignerHead {
        private final String signerId;
        private final long lastSeq;
        private final String lastHash;

        private SignerHead(String signerId, long lastSeq, String lastHash) {
            this.signerId = signerId;
            this.lastSeq = lastSeq;
            this.lastHash = lastHash;
        }
    }

    private static List<SignerHead> loadLatestHeads(String onlySigner) throws SQLException {
        List<SignerHead> out = new ArrayList<>();

        String sql;
        boolean filter = onlySigner != null && !onlySigner.trim().isEmpty();
        if (filter) {
            sql = "SELECT reporter, document_json FROM reports WHERE reporter = ? ORDER BY id DESC LIMIT 1";
        } else {
            sql = "SELECT reporter, document_json FROM reports WHERE id IN (SELECT MAX(id) FROM reports GROUP BY reporter)";
        }

        synchronized (AuthServerMain.class) {
            try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(sql)) {
                if (filter) {
                    stmt.setString(1, onlySigner.trim());
                }
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        String reporter = rs.getString(1);
                        String docJson = rs.getString(2);
                        long lastSeq = 0L;
                        String lastHash = null;
                        try {
                            SecureDocument doc = docJson == null ? null : GSON.fromJson(docJson, SecureDocument.class);
                            if (doc != null) {
                                if (doc.getSequenceNumber() != null) {
                                    lastSeq = doc.getSequenceNumber();
                                }
                                lastHash = CryptoLib.computeChainHash(doc);
                            }
                        } catch (Exception ignored) {
                            lastSeq = 0L;
                            lastHash = null;
                        }

                        if (reporter != null && !reporter.isBlank()) {
                            out.add(new SignerHead(reporter, lastSeq, lastHash));
                        }
                    }
                }
            }
        }

        return out;
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new HashMap<>();
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        String[] parts = raw.split("&");
        for (String p : parts) {
            if (p == null || p.isEmpty()) {
                continue;
            }
            int idx = p.indexOf('=');
            String k = idx >= 0 ? p.substring(0, idx) : p;
            String v = idx >= 0 ? p.substring(idx + 1) : "";
            try {
                k = URLDecoder.decode(k, StandardCharsets.UTF_8);
                v = URLDecoder.decode(v, StandardCharsets.UTF_8);
            } catch (Exception ignored) {
            }
            out.put(k, v);
        }
        return out;
    }

    private static void initDatabase() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC driver not found", e);
        }
        DB_CONNECTION = DriverManager.getConnection(DB_URL);
        try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                "CREATE TABLE IF NOT EXISTS reports (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "reporter TEXT," +
                        "created_at TEXT," +
                        "document_json TEXT NOT NULL" +
                        ")")) {
            stmt.executeUpdate();
        }

        try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                "CREATE TABLE IF NOT EXISTS invitation_tokens (" +
                        "token_id TEXT PRIMARY KEY," +
                        "issuer_id TEXT NOT NULL," +
                        "issued_at TEXT NOT NULL," +
                        "expires_at TEXT NOT NULL," +
                        "max_uses INTEGER NOT NULL," +
                        "current_uses INTEGER DEFAULT 0," +
                        "active BOOLEAN DEFAULT 1," +
                        "description TEXT" +
                        ")")) {
            stmt.executeUpdate();
        }

        try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                "CREATE TABLE IF NOT EXISTS users (" +
                        "username TEXT PRIMARY KEY CHECK (length(username) >= 3)," +
                        "password_hash TEXT NOT NULL CHECK (length(password_hash) >= 8)," +
                        "created_at TEXT NOT NULL DEFAULT (datetime('now'))," +
                        "last_login TEXT," +
                        "active BOOLEAN DEFAULT 1 CHECK (active IN (0,1))" +
                        ")")) {
            stmt.executeUpdate();
        }

        loadUsersFromDatabase();

        if (authorizedUsers.isEmpty()) {
            addDefaultUsers();
        }
    }

    private static void loadTokensFromDatabase() throws SQLException {
        try (Statement stmt = DB_CONNECTION.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM invitation_tokens")) {
            while (rs.next()) {
                InvitationToken token = new InvitationToken();
                token.setTokenId(rs.getString("token_id"));
                token.setIssuerId(rs.getString("issuer_id"));
                token.setIssuedAt(rs.getString("issued_at"));
                token.setExpiresAt(rs.getString("expires_at"));
                token.setMaxUses(rs.getInt("max_uses"));
                token.setCurrentUses(rs.getInt("current_uses"));
                token.setActive(rs.getBoolean("active"));
                token.setDescription(rs.getString("description"));
                tokenCache.put(token.getTokenId(), token);
            }
        }
    }

    private static void saveTokenToDatabase(InvitationToken token) throws SQLException {
        try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                "INSERT OR REPLACE INTO invitation_tokens " +
                "(token_id, issuer_id, issued_at, expires_at, max_uses, current_uses, active, description) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
            stmt.setString(1, token.getTokenId());
            stmt.setString(2, token.getIssuerId());
            stmt.setString(3, token.getIssuedAt());
            stmt.setString(4, token.getExpiresAt());
            stmt.setInt(5, token.getMaxUses());
            stmt.setInt(6, token.getCurrentUses());
            stmt.setBoolean(7, token.isActive());
            stmt.setString(8, token.getDescription());
            stmt.executeUpdate();
        }
    }

    private static void loadUsersFromDatabase() throws SQLException {
        try (Statement stmt = DB_CONNECTION.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT username FROM users WHERE active = 1")) {
            while (rs.next()) {
                String username = rs.getString("username");
                authorizedUsers.put(username, true);
            }
        }
    }

    private static void addDefaultUsers() throws SQLException {
        try {
            addUser("alice", "alice");
            addUser("bob", "bob");
            System.out.println("Added default users: alice, bob");
        } catch (Exception e) {
            System.err.println("Error adding default users: " + e.getMessage());
        }
    }

    private static void addUser(String username, String password) throws SQLException, NoSuchAlgorithmException {
        String passwordHash = hashPassword(password);
        try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                "INSERT OR IGNORE INTO users (username, password_hash, created_at) VALUES (?, ?, ?)")) {
            stmt.setString(1, username);
            stmt.setString(2, passwordHash);
            stmt.setString(3, Instant.now().toString());
            int rows = stmt.executeUpdate();
            if (rows > 0) {
                authorizedUsers.put(username, true);
            }
        }
    }

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private static boolean isValidUser(String userId) {
        return authorizedUsers.containsKey(userId);
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

    private static void handleStoreReport(HttpExchange exchange) throws IOException, SQLException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String json = new String(body, StandardCharsets.UTF_8);

        SecureDocument doc = GSON.fromJson(json, SecureDocument.class);
        if (doc == null || doc.getEncryptedData() == null || doc.getSignerId() == null) {
            String msg = "Invalid report payload";
            byte[] respBytes = msg.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(400, respBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(respBytes);
            }
            return;
        }

        String reporter = doc.getSignerId();
        String createdAt = doc.getTimestamp() != null ? doc.getTimestamp() : Instant.now().toString();

        if (doc.getSequenceNumber() != null) {
            SecureDocument last = loadLastReportForReporter(reporter);
            String violation = validateChainAppend(last, doc);
            if (violation != null) {
                byte[] respBytes = violation.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(409, respBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(respBytes);
                }
                return;
            }
        }

        synchronized (AuthServerMain.class) {
            try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                    "INSERT INTO reports (reporter, created_at, document_json) VALUES (?, ?, ?)")) {
                stmt.setString(1, reporter);
                stmt.setString(2, createdAt);
                stmt.setString(3, json);
                stmt.executeUpdate();
            }
        }

        String msg = "Report stored";
        byte[] respBytes = msg.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain");
        exchange.sendResponseHeaders(201, respBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(respBytes);
        }
    }

    private static SecureDocument loadLastReportForReporter(String reporter) throws SQLException {
        if (reporter == null) {
            return null;
        }
        synchronized (AuthServerMain.class) {
            try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                    "SELECT document_json FROM reports WHERE reporter = ? ORDER BY id DESC LIMIT 1")) {
                stmt.setString(1, reporter);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        String docJson = rs.getString(1);
                        if (docJson == null || docJson.isEmpty()) {
                            return null;
                        }
                        return GSON.fromJson(docJson, SecureDocument.class);
                    }
                }
            }
        }
        return null;
    }

    private static String normalizePrevHash(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String validateChainAppend(SecureDocument last, SecureDocument next) {
        Long nextSeqObj = next.getSequenceNumber();
        if (nextSeqObj == null) {
            return null;
        }
        long nextSeq = nextSeqObj;
        String nextPrev = normalizePrevHash(next.getPreviousHash());

        if (last == null || last.getSequenceNumber() == null) {
            if (nextSeq != 1L) {
                return "SR3 violation: expected first sequence_number=1 but got " + nextSeq;
            }
            if (nextPrev != null) {
                return "SR3 violation: expected previous_hash to be null for first document";
            }
            return null;
        }

        long expectedSeq = last.getSequenceNumber() + 1L;
        if (nextSeq != expectedSeq) {
            return "SR3 violation: expected sequence_number=" + expectedSeq + " but got " + nextSeq;
        }

        try {
            String expectedPrev = CryptoLib.computeChainHash(last);
            if (nextPrev == null || !expectedPrev.equals(nextPrev)) {
                return "SR3 violation: previous_hash mismatch";
            }
        } catch (Exception e) {
            return "SR3 violation: failed computing previous hash: " + e.getMessage();
        }

        return null;
    }

    private static void handleListReports(HttpExchange exchange) throws IOException, SQLException {
        StringBuilder sb = new StringBuilder();
        sb.append("[");

        synchronized (AuthServerMain.class) {
            try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                    "SELECT document_json FROM reports ORDER BY id ASC");
                 ResultSet rs = stmt.executeQuery()) {
                boolean first = true;
                while (rs.next()) {
                    if (!first) {
                        sb.append(",");
                    }
                    sb.append(rs.getString(1));
                    first = false;
                }
            }
        }

        sb.append("]");
        byte[] respBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, respBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(respBytes);
        }
    }
}
