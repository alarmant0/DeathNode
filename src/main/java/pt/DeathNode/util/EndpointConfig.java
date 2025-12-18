package pt.DeathNode.util;

public final class EndpointConfig {

    private static final String DEFAULT_AUTH_URL = "http://localhost:8080";
    private static final String DEFAULT_GATEWAY_URL = "http://localhost:9090";

    private EndpointConfig() {
    }

    public static String getAuthServerUrl() {
        String v = firstNonBlank(System.getenv("DEATHNODE_AUTH_URL"), System.getenv("DEATHNODE_AUTH_SERVER_URL"));
        return normalizeBaseUrl(v, DEFAULT_AUTH_URL);
    }

    public static String getGatewayUrl() {
        String v = firstNonBlank(System.getenv("DEATHNODE_GATEWAY_URL"), System.getenv("DEATHNODE_APP_URL"));
        return normalizeBaseUrl(v, DEFAULT_GATEWAY_URL);
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.trim().isEmpty()) {
            return a;
        }
        if (b != null && !b.trim().isEmpty()) {
            return b;
        }
        return null;
    }

    private static String normalizeBaseUrl(String raw, String fallback) {
        String v = raw == null ? "" : raw.trim();
        if (v.isEmpty()) {
            return fallback;
        }
        while (v.endsWith("/")) {
            v = v.substring(0, v.length() - 1);
        }
        return v;
    }
}
