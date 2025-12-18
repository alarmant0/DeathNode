package pt.DeathNode.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import pt.DeathNode.auth.AuthServerMain;
import pt.DeathNode.auth.AuthToken;
import pt.DeathNode.crypto.CryptoLib;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.crypto.SecureDocument;
import pt.DeathNode.util.EndpointConfig;
import pt.DeathNode.util.TlsConfig;

public class ApplicationServer {

    private static final String APP_SERVER_PORT = "9090";
    private static final String AUTH_SERVER_URL = EndpointConfig.getAuthServerUrl();
    private static final String DB_URL = "jdbc:sqlite:db/deathnode.db";
    private static Connection DB_CONNECTION;
    private static final Gson GSON = new GsonBuilder().create();
    private static HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;

        initDatabase();

        TlsConfig.installClientTlsFromEnvIfPresent();
        HTTP_CLIENT = HttpClient.newBuilder().sslContext(javax.net.ssl.SSLContext.getDefault()).build();

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

        server.createContext("/api/auth/join", new AuthProxyHandler());
        server.createContext("/api/auth/login", new AuthProxyHandler());
        server.createContext("/api/auth/register", new AuthProxyHandler());
        server.createContext("/api/auth/tokens/create", new AuthProxyHandler());
        server.createContext("/api/auth/tokens/validate", new AuthProxyHandler());

        server.createContext("/api/reports", new ReportsHandler());
        server.createContext("/api/checkpoints", new CheckpointsHandler());
        server.createContext("/api/health", new HealthHandler());

        server.start();
        System.out.println("[GATEWAY] Listening on port " + port + " (TLS=" + TlsConfig.isTlsEnabled() + ")");
        System.out.println("[GATEWAY] Auth URL: " + AUTH_SERVER_URL);
    }

    private static void initDatabase() throws SQLException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC driver not found", e);
        }
        DB_CONNECTION = DriverManager.getConnection(DB_URL);

        try (Statement stmt = DB_CONNECTION.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS reports (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "reporter TEXT NOT NULL," +
                    "created_at TEXT NOT NULL," +
                    "document_json TEXT NOT NULL" +
                    ")");
        }

        try (Statement stmt = DB_CONNECTION.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                    "username TEXT PRIMARY KEY," +
                    "password_hash TEXT NOT NULL," +
                    "active INTEGER NOT NULL DEFAULT 1" +
                    ")");
        }

        try {
            seedUserIfMissing("alice", "alice");
            seedUserIfMissing("bob", "bob");
        } catch (Exception e) {
            throw new SQLException("Failed seeding default users", e);
        }
    }

    private static void seedUserIfMissing(String username, String password) throws Exception {
        String existsSql = "SELECT 1 FROM users WHERE username = ?";
        try (PreparedStatement ps = DB_CONNECTION.prepareStatement(existsSql)) {
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return;
                }
            }
        }

        String insertSql = "INSERT INTO users(username, password_hash, active) VALUES(?, ?, 1)";
        try (PreparedStatement ps = DB_CONNECTION.prepareStatement(insertSql)) {
            ps.setString(1, username);
            ps.setString(2, hashPassword(password));
            ps.executeUpdate();
        }
    }

    private static String hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    static class AuthProxyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();

            System.out.println("[GATEWAY] " + exchange.getRemoteAddress() + " " + method + " " + path);

            try {
                if (path.endsWith("/login")) {
                    handleLogin(exchange);
                    return;
                }

                String authPath = path.replace("/api/auth", "");
                URI authUri = URI.create(AUTH_SERVER_URL + authPath);

                HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                        .uri(authUri)
                        .method(method, HttpRequest.BodyPublishers.ofString(
                                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));

                String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
                if (contentType != null && !contentType.isBlank()) {
                    requestBuilder.header("Content-Type", contentType);
                } else {
                    requestBuilder.header("Content-Type", "application/json");
                }
                String authz = exchange.getRequestHeaders().getFirst("Authorization");
                if (authz != null && !authz.isBlank()) {
                    requestBuilder.header("Authorization", authz);
                }

                HttpRequest request = requestBuilder.build();
                HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

                String respContentType = response.headers().firstValue("Content-Type").orElse("application/json");
                exchange.getResponseHeaders().set("Content-Type", respContentType);
                byte[] outBytes = response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(response.statusCode(), outBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(outBytes);
                }

            } catch (Exception e) {
                String error = "{\"error\":\"Auth service unavailable: " + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(503, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
            }
        }

        private void handleLogin(HttpExchange exchange) throws IOException {
            try {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

                String username = extractJsonValue(body, "username");
                String password = extractJsonValue(body, "password");

                if (username == null || password == null) {
                    String error = "{\"error\":\"Missing username or password\"}";
                    exchange.sendResponseHeaders(400, error.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(error.getBytes());
                    }
                    return;
                }

                if (authenticateUser(username, password)) {
                    String response = "{\"status\":\"success\",\"user\":\"" + username + "\"}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                } else {
                    String error = "{\"error\":\"Invalid credentials\"}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(401, error.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(error.getBytes());
                    }
                }

            } catch (Exception e) {
                String error = "{\"error\":\"Login failed: " + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(500, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
            }
        }

        private String extractJsonValue(String json, String key) {
            String pattern = "\"" + key + "\":\"";
            int start = json.indexOf(pattern);
            if (start == -1) return null;
            start += pattern.length();
            int end = json.indexOf("\"", start);
            return end == -1 ? null : json.substring(start, end);
        }

        private boolean authenticateUser(String username, String password) throws Exception {
            try {
                Class.forName("org.sqlite.JDBC");
            } catch (ClassNotFoundException e) {
                throw new Exception("SQLite JDBC driver not found", e);
            }

            try (Connection conn = DriverManager.getConnection(DB_URL)) {
                String sql = "SELECT password_hash FROM users WHERE username = ? AND active = 1";
                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setString(1, username);
                    ResultSet rs = stmt.executeQuery();

                    if (rs.next()) {
                        String storedHash = rs.getString("password_hash");
                        String inputHash = ApplicationServer.hashPassword(password);
                        return storedHash.equals(inputHash);
                    }
                    return false;
                }
            }
        }
    }

    static class ReportsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();

            try {
                if (!"POST".equalsIgnoreCase(method) && !"GET".equalsIgnoreCase(method)) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                String reporter = extractReporterFromToken(exchange);
                if (reporter == null) {
                    String error = "{\"error\":\"Unauthorized\"}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(401, error.getBytes(StandardCharsets.UTF_8).length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(error.getBytes(StandardCharsets.UTF_8));
                    }
                    return;
                }

                if ("POST".equalsIgnoreCase(method)) {
                    handleStoreReport(exchange, reporter);
                } else {
                    handleListReports(exchange);
                }
            } catch (Exception e) {
                String error = "{\"error\":\"" + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(500, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
            }
        }

        private void handleStoreReport(HttpExchange exchange, String reporter) throws Exception {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            SecureDocument doc = GSON.fromJson(body, SecureDocument.class);
            if (doc == null || doc.getSignerId() == null) {
                String error = "{\"error\":\"Invalid report payload\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(400, error.getBytes(StandardCharsets.UTF_8).length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes(StandardCharsets.UTF_8));
                }
                return;
            }

            if (!reporter.equals(doc.getSignerId())) {
                String error = "{\"error\":\"Signer mismatch\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(400, error.getBytes(StandardCharsets.UTF_8).length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes(StandardCharsets.UTF_8));
                }
                return;
            }

            URI authUri = URI.create(AUTH_SERVER_URL + "/reports");
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(authUri)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<byte[]> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
            exchange.getResponseHeaders().set("Content-Type", response.headers().firstValue("Content-Type").orElse("text/plain"));
            exchange.sendResponseHeaders(response.statusCode(), response.body().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.body());
            }
        }
        private void handleListReports(HttpExchange exchange) throws Exception {
            URI authUri = URI.create(AUTH_SERVER_URL + "/reports");
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(authUri)
                    .GET()
                    .build();

            HttpResponse<byte[]> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
            exchange.getResponseHeaders().set("Content-Type", response.headers().firstValue("Content-Type").orElse("application/json"));
            exchange.sendResponseHeaders(response.statusCode(), response.body().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.body());
            }
        }

        private String extractReporterFromToken(HttpExchange exchange) {
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String tokenB64 = authHeader.substring(7).trim();
                if (tokenB64.isEmpty()) {
                    return null;
                }
                try {
                    byte[] tokenJsonBytes = Base64.getDecoder().decode(tokenB64);
                    String tokenJson = new String(tokenJsonBytes, StandardCharsets.UTF_8);
                    AuthToken token = GSON.fromJson(tokenJson, AuthToken.class);
                    PublicKey serverPublicKey = KeyManager.loadPublicKey("server");
                    if (!AuthServerMain.verifyToken(token, serverPublicKey)) {
                        return null;
                    }
                    return token.getPseudonym();
                } catch (Exception e) {
                    return null;
                }
            }
            return null;
        }
    }

    static class CheckpointsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            try {
                String query = exchange.getRequestURI().getRawQuery();
                String path = "/checkpoints" + (query == null || query.isEmpty() ? "" : ("?" + query));
                URI authUri = URI.create(AUTH_SERVER_URL + path);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(authUri)
                        .GET()
                        .build();

                HttpResponse<byte[]> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
                exchange.getResponseHeaders().set("Content-Type", response.headers().firstValue("Content-Type").orElse("application/json"));
                exchange.sendResponseHeaders(response.statusCode(), response.body().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.body());
                }
            } catch (Exception e) {
                String error = "{\"error\":\"" + e.getMessage() + "\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(503, error.getBytes(StandardCharsets.UTF_8).length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes(StandardCharsets.UTF_8));
                }
            }
        }
    }

    static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"status\":\"healthy\",\"timestamp\":\"" + Instant.now().toString() + "\"}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}
