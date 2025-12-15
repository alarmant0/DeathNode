package pt.DeathNode.crypto;

import javax.crypto.SecretKey;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

public class DeathNodeCLI {

    private static final String TOOL_NAME = "deathnode";

    public static void main(String[] args) {
        if (args.length == 0) {
            printHelp();
            return;
        }

        String command = args[0].toLowerCase();

        try {
            switch (command) {
                case "help":
                    printHelp();
                    break;
                case "protect":
                    handleProtect(args);
                    break;
                case "check":
                    handleCheck(args);
                    break;
                case "unprotect":
                    handleUnprotect(args);
                    break;
                case "genkeys":
                    handleGenKeys(args);
                    break;
                case "submit":
                    handleSubmit(args);
                    break;
                default:
                    System.err.println("Error: Unknown command '" + command + "'");
                    System.err.println("Run '" + TOOL_NAME + " help' for usage information.");
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            if (System.getenv("DEBUG") != null) {
                e.printStackTrace();
            }
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("DeathNode - Secure Document Tool");
        System.out.println("=================================");
        System.out.println();
        System.out.println("A cryptographic library for protecting anonymous reports.");
        System.out.println();
        System.out.println("USAGE:");
        System.out.println("  " + TOOL_NAME + " <command> [arguments]");
        System.out.println();
        System.out.println("COMMANDS:");
        System.out.println();
        System.out.println("  help");
        System.out.println("      Display this help message.");
        System.out.println();
        System.out.println("  protect <input-file> <key-name> <output-file>");
        System.out.println("      Encrypt and sign a plaintext report.");
        System.out.println("      - input-file:  Path to plaintext JSON report");
        System.out.println("      - key-name:    Name of the key files (without extension)");
        System.out.println("                     Expects: keys/<key-name>.key (AES)");
        System.out.println("                              keys/<key-name>.priv (RSA private)");
        System.out.println("      - output-file: Path for the protected document");
        System.out.println();
        System.out.println("  check <input-file> <key-name>");
        System.out.println("      Verify the signature of a protected document.");
        System.out.println("      - input-file:  Path to protected document");
        System.out.println("      - key-name:    Name of the key files (without extension)");
        System.out.println("                     Expects: keys/<key-name>.pub (RSA public)");
        System.out.println();
        System.out.println("  unprotect <input-file> <key-name> <output-file>");
        System.out.println("      Verify, decrypt and extract the original report.");
        System.out.println("      - input-file:  Path to protected document");
        System.out.println("      - key-name:    Name of the key files (without extension)");
        System.out.println("                     Expects: keys/<key-name>.key (AES)");
        System.out.println("                              keys/<key-name>.pub (RSA public)");
        System.out.println("      - output-file: Path for the decrypted report");
        System.out.println();
        System.out.println("  genkeys <user-id>");
        System.out.println("      Generate a new set of dummy keys for testing.");
        System.out.println("      - user-id:     Identifier for the key set");
        System.out.println("      Creates: keys/<user-id>.key, keys/<user-id>.priv, keys/<user-id>.pub");
        System.out.println();
        System.out.println("  submit <user-id> <suspect> <location> <description> <output-file>");
        System.out.println("      Convenience command to create and protect a new report for a user.");
        System.out.println("      - user-id:     Pseudonym (e.g., bob, alice)");
        System.out.println("      - suspect:     Suspect identifier");
        System.out.println("      - location:    Location string (use quotes if it has spaces)");
        System.out.println("      - description: Description text (use quotes if it has spaces)");
        System.out.println("      - output-file: Path for the protected document (.secure)");
        System.out.println();
        System.out.println("SECURITY:");
        System.out.println("  - Encryption: AES-256-GCM (confidentiality + integrity)");
        System.out.println("  - Signatures: SHA256withRSA (authenticity)");
        System.out.println();
        System.out.println("EXAMPLES:");
        System.out.println("  " + TOOL_NAME + " genkeys shadow_fox");
        System.out.println("  " + TOOL_NAME + " protect report.json shadow_fox report.secure");
        System.out.println("  " + TOOL_NAME + " check report.secure shadow_fox");
        System.out.println("  " + TOOL_NAME + " unprotect report.secure shadow_fox report_decrypted.json");
    }

    private static void handleProtect(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Error: Missing arguments for 'protect' command.");
            System.err.println("Usage: " + TOOL_NAME + " protect <input-file> <key-name> <output-file>");
            System.exit(1);
        }

        String inputFile = args[1];
        String keyName = args[2];
        String outputFile = args[3];

        Path inputPath = Paths.get(inputFile);
        if (!Files.exists(inputPath)) {
            throw new IllegalArgumentException("Input file not found: " + inputFile);
        }
        String reportJson = Files.readString(inputPath);
        Report report = Report.fromJson(reportJson);

        SecretKey encKey = KeyManager.loadSymmetricKey(keyName);
        PrivateKey signKey = KeyManager.loadPrivateKey(keyName);

        ChainStateStore.ChainParams chainParams = ChainStateStore.nextParams(keyName);
        SecureDocument secDoc = CryptoLib.protect(
                report,
                encKey,
                signKey,
                keyName,
                chainParams.getSequenceNumber(),
                chainParams.getPreviousHash()
        );
        ChainStateStore.updateFromDocument(keyName, secDoc);

        Files.writeString(Paths.get(outputFile), secDoc.toJson());

        System.out.println("Document protected successfully.");
        System.out.println("  Input:  " + inputFile);
        System.out.println("  Output: " + outputFile);
        System.out.println("  Signer: " + keyName);
    }

    private static void handleCheck(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Error: Missing arguments for 'check' command.");
            System.err.println("Usage: " + TOOL_NAME + " check <input-file> <key-name>");
            System.exit(1);
        }

        String inputFile = args[1];
        String keyName = args[2];

        Path inputPath = Paths.get(inputFile);
        if (!Files.exists(inputPath)) {
            throw new IllegalArgumentException("Input file not found: " + inputFile);
        }
        String secDocJson = Files.readString(inputPath);
        SecureDocument secDoc = SecureDocument.fromJson(secDocJson);

        PublicKey verifyKey = KeyManager.loadPublicKey(keyName);

        boolean valid = CryptoLib.check(secDoc, verifyKey);

        System.out.println("Document verification:");
        System.out.println("  File:      " + inputFile);
        System.out.println("  Signer ID: " + secDoc.getSignerId());
        System.out.println("  Timestamp: " + secDoc.getTimestamp());
        System.out.println("  Format:    " + secDoc.getFormat());
        System.out.println();
        
        if (valid) {
            System.out.println("  Status: VALID - Signature verified successfully.");
        } else {
            System.out.println("  Status: INVALID - Signature verification FAILED!");
            System.out.println("  WARNING: Document may have been tampered with.");
            System.exit(2);
        }
    }

    private static void handleUnprotect(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Error: Missing arguments for 'unprotect' command.");
            System.err.println("Usage: " + TOOL_NAME + " unprotect <input-file> <key-name> <output-file>");
            System.exit(1);
        }

        String inputFile = args[1];
        String keyName = args[2];
        String outputFile = args[3];

        Path inputPath = Paths.get(inputFile);
        if (!Files.exists(inputPath)) {
            throw new IllegalArgumentException("Input file not found: " + inputFile);
        }
        String secDocJson = Files.readString(inputPath);
        SecureDocument secDoc = SecureDocument.fromJson(secDocJson);

        SecretKey decKey = KeyManager.loadSymmetricKey(keyName);
        PublicKey verifyKey = KeyManager.loadPublicKey(keyName);

        Report report = CryptoLib.unprotect(secDoc, decKey, verifyKey);

        Files.writeString(Paths.get(outputFile), report.toJson());

        System.out.println("Document unprotected successfully.");
        System.out.println("  Input:     " + inputFile);
        System.out.println("  Output:    " + outputFile);
        System.out.println("  Report ID: " + report.getReportId());
        System.out.println("  Status:    Signature verified, data decrypted.");
    }

    private static void handleGenKeys(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Error: Missing arguments for 'genkeys' command.");
            System.err.println("Usage: " + TOOL_NAME + " genkeys <user-id>");
            System.exit(1);
        }

        String userId = args[1];
        KeyManager.generateDummyKeys(userId);
    }

    private static void handleSubmit(String[] args) throws Exception {
        if (args.length < 6) {
            System.err.println("Error: Missing arguments for 'submit' command.");
            System.err.println("Usage: " + TOOL_NAME + " submit <user-id> <suspect> <location> <description> <output-file>");
            System.exit(1);
        }

        String userId      = args[1];
        String suspect     = args[2];
        String location    = args[3];
        String description = args[4];
        String outputFile  = args[5];

        KeyManager.generateDummyKeys(userId);

        Report report = Report.createNew(userId, suspect, description, location);

        SecretKey encKey   = KeyManager.loadSymmetricKey(userId);
        PrivateKey signKey = KeyManager.loadPrivateKey(userId);

        ChainStateStore.ChainParams chainParams = ChainStateStore.nextParams(userId);
        SecureDocument secDoc = CryptoLib.protect(
                report,
                encKey,
                signKey,
                userId,
                chainParams.getSequenceNumber(),
                chainParams.getPreviousHash()
        );
        ChainStateStore.updateFromDocument(userId, secDoc);

        String secJson = secDoc.toJson();

        Files.writeString(Paths.get(outputFile), secJson, StandardCharsets.UTF_8);

        try {
            URL url = new URL("http://localhost:8080/reports");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            byte[] body = secJson.getBytes(StandardCharsets.UTF_8);
            conn.getOutputStream().write(body);

            int code = conn.getResponseCode();
            if (code / 100 != 2) {
                System.err.println("Warning: server /reports responded with status " + code);
            } else {
                System.out.println("Report also stored on server (HTTP " + code + ").");
            }
        } catch (Exception e) {
            System.err.println("Warning: failed to POST report to server: " + e.getMessage());
        }

        System.out.println("Report submitted (protected) successfully.");
        System.out.println("  User:   " + userId);
        System.out.println("  File:   " + outputFile);
        System.out.println("  ID:     " + report.getReportId());
    }
}
