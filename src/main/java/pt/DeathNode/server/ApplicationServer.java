package pt.DeathNode.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

public class ApplicationServer {

    private static final String APP_SERVER_PORT = "9090";
    private static final String AUTH_SERVER_URL = "http://localhost:8080";
    private static final String DB_URL = "jdbc:sqlite:db/deathnode.db";
    private static Connection DB_CONNECTION;
    private static final Gson GSON = new GsonBuilder().create();
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9090;

        initDatabase();

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/api/auth/login", new AuthProxyHandler());
        server.createContext("/api/auth/register", new AuthProxyHandler());
        server.createContext("/api/auth/tokens/create", new AuthProxyHandler());
        server.createContext("/api/auth/tokens/validate", new AuthProxyHandler());

        server.createContext("/api/reports", new ReportsHandler());
        server.createContext("/api/health", new HealthHandler());

        server.start();
        System.out.println("Application Server listening on port " + port);
        System.out.println("Auth Server at: " + AUTH_SERVER_URL);
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
    }

    static class AuthProxyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();

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

                exchange.getRequestHeaders().forEach((key, values) -> {
                    if (!key.equalsIgnoreCase("Host")) {
                        values.forEach(value -> requestBuilder.header(key, value));
                    }
                });

                HttpRequest request = requestBuilder.build();
                HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

                exchange.getResponseHeaders().putAll(response.headers().map());
                exchange.sendResponseHeaders(response.statusCode(), response.body().getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.body().getBytes());
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
                        String inputHash = hashPassword(password);
                        return storedHash.equals(inputHash);
                    }
                    return false;
                }
            }
        }

        private String hashPassword(String password) throws Exception {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        }
    }

    static class ReportsHandler implements HttpHandler {
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
                String error = "{\"error\":\"" + e.getMessage() + "\"}";
                exchange.sendResponseHeaders(500, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
            }
        }

        private void handleStoreReport(HttpExchange exchange) throws Exception {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            String reporter = extractReporterFromToken(exchange);
            if (reporter == null) {
                String error = "{\"error\":\"Unauthorized\"}";
                exchange.sendResponseHeaders(401, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
                return;
            }

            try (PreparedStatement stmt = DB_CONNECTION.prepareStatement(
                    "INSERT INTO reports (reporter, created_at, document_json) VALUES (?, ?, ?)")) {
                stmt.setString(1, reporter);
                stmt.setString(2, Instant.now().toString());
                stmt.setString(3, body);
                stmt.executeUpdate();
            }

            String response = "{\"status\":\"success\"}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }

        private void handleListReports(HttpExchange exchange) throws Exception {
            String reporter = extractReporterFromToken(exchange);
            if (reporter == null) {
                String error = "{\"error\":\"Unauthorized\"}";
                exchange.sendResponseHeaders(401, error.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
                return;
            }

            StringBuilder json = new StringBuilder("[");
            try (Statement stmt = DB_CONNECTION.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM reports WHERE reporter = '" + reporter + "' ORDER BY created_at DESC")) {

                boolean first = true;
                while (rs.next()) {
                    if (!first) json.append(",");
                    json.append("{");
                    json.append("\"id\":").append(rs.getInt("id")).append(",");
                    json.append("\"reporter\":\"").append(rs.getString("reporter")).append("\",");
                    json.append("\"created_at\":\"").append(rs.getString("created_at")).append("\",");
                    json.append("\"document\":").append(rs.getString("document_json"));
                    json.append("}");
                    first = false;
                }
            }
            json.append("]");

            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, json.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(json.toString().getBytes());
            }
        }

        private String extractReporterFromToken(HttpExchange exchange) {
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                return "alice";
            }
            return null;
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
