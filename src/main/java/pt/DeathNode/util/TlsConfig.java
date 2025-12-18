package pt.DeathNode.util;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;

public final class TlsConfig {

    private TlsConfig() {
    }

    public static boolean isTlsEnabled() {
        String ks = System.getenv("DEATHNODE_TLS_KEYSTORE_PATH");
        return ks != null && !ks.trim().isEmpty();
    }

    public static SSLContext buildSslContextFromEnv() throws Exception {
        String ksPath = requiredEnv("DEATHNODE_TLS_KEYSTORE_PATH");
        String ksPass = requiredEnv("DEATHNODE_TLS_KEYSTORE_PASSWORD");
        String ksType = envOrDefault("DEATHNODE_TLS_KEYSTORE_TYPE", "PKCS12");

        String tsPath = System.getenv("DEATHNODE_TLS_TRUSTSTORE_PATH");
        String tsPass = System.getenv("DEATHNODE_TLS_TRUSTSTORE_PASSWORD");
        String tsType = envOrDefault("DEATHNODE_TLS_TRUSTSTORE_TYPE", "PKCS12");

        KeyStore keyStore = KeyStore.getInstance(ksType);
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            keyStore.load(fis, ksPass.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, ksPass.toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (tsPath != null && !tsPath.trim().isEmpty()) {
            if (tsPass == null) {
                throw new IllegalArgumentException("DEATHNODE_TLS_TRUSTSTORE_PASSWORD is required when DEATHNODE_TLS_TRUSTSTORE_PATH is set");
            }
            KeyStore trustStore = KeyStore.getInstance(tsType);
            try (FileInputStream fis = new FileInputStream(tsPath)) {
                trustStore.load(fis, tsPass.toCharArray());
            }
            tmf.init(trustStore);
        } else {
            tmf.init((KeyStore) null);
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    public static void installClientTlsFromEnvIfPresent() throws Exception {
        String tsPath = System.getenv("DEATHNODE_TLS_TRUSTSTORE_PATH");
        if (tsPath == null || tsPath.trim().isEmpty()) {
            return;
        }
        String tsPass = requiredEnv("DEATHNODE_TLS_TRUSTSTORE_PASSWORD");
        String tsType = envOrDefault("DEATHNODE_TLS_TRUSTSTORE_TYPE", "PKCS12");

        KeyStore trustStore = KeyStore.getInstance(tsType);
        try (FileInputStream fis = new FileInputStream(tsPath)) {
            trustStore.load(fis, tsPass.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(sslContext);
    }

    private static String envOrDefault(String k, String d) {
        String v = System.getenv(k);
        if (v == null || v.trim().isEmpty()) {
            return d;
        }
        return v.trim();
    }

    private static String requiredEnv(String k) {
        String v = System.getenv(k);
        if (v == null || v.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing required environment variable: " + k);
        }
        return v.trim();
    }
}
