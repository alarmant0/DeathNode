package pt.DeathNode.tui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import pt.DeathNode.crypto.CryptoLib;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.crypto.Report;
import pt.DeathNode.crypto.SecureDocument;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class ReportsListWindow extends BasicWindow {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private final String currentUser;

    public ReportsListWindow(String currentUser) {
        super("View Reports");
        this.currentUser = currentUser;
        initializeUI();
    }

    private void initializeUI() {
        Panel mainPanel = new Panel();
        mainPanel.setLayoutManager(new GridLayout(1));

        mainPanel.addComponent(new Label("Reports from server (" + currentUser + "):")
                .setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1)));

        mainPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        TextBox listBox = new TextBox(new TerminalSize(80, 15));
        listBox.setReadOnly(true);
        listBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        mainPanel.addComponent(listBox);

        Label statusLabel = new Label("");
        statusLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        mainPanel.addComponent(statusLabel);

        Panel buttons = new Panel(new GridLayout(2));
        Button refresh = new Button("Refresh", () -> loadReports(listBox, statusLabel));
        Button close = new Button("Close", this::close);
        buttons.addComponent(refresh);
        buttons.addComponent(close);
        mainPanel.addComponent(buttons);

        setComponent(mainPanel);

        loadReports(listBox, statusLabel);
    }

    private void loadReports(TextBox listBox, Label statusLabel) {
        listBox.setText("");
        try {
            URL url = new URL("http://localhost:8080/reports");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                statusLabel.setText("Server returned " + code + " with no body");
                return;
            }
            byte[] bytes = is.readAllBytes();
            String json = new String(bytes, StandardCharsets.UTF_8);

            SecureDocument[] docs = GSON.fromJson(json, SecureDocument[].class);
            if (docs == null || docs.length == 0) {
                statusLabel.setText("No reports found.");
                return;
            }

            int shown = 0;
            StringBuilder sb = new StringBuilder();
            for (SecureDocument doc : docs) {
                if (doc == null || doc.getEncryptedData() == null) {
                    continue;
                }
                String signer = doc.getSignerId() != null ? doc.getSignerId() : "?";
                String timestamp = doc.getTimestamp() != null ? doc.getTimestamp() : "?";

                try {
                    if (signer != null && !"?".equals(signer)) {
                        SecretKey decKey = KeyManager.loadSymmetricKey(signer);
                        PublicKey verifyKey = KeyManager.loadPublicKey(signer);
                        Report report = CryptoLib.unprotect(doc, decKey, verifyKey);

                        String suspect = report.getContent() != null && report.getContent().getSuspect() != null
                                ? report.getContent().getSuspect() : "?";
                        String location = report.getContent() != null && report.getContent().getLocation() != null
                                ? report.getContent().getLocation() : "?";

                        String prefix = currentUser.equals(signer) ? "[ME] " : "[" + signer + "] ";
                        String line = prefix + timestamp + " | " + suspect + " @ " + location;
                        sb.append(line).append('\n');
                        shown++;
                    } else {
                        String line = "[" + signer + "] " + timestamp + " | [encrypted]";
                        sb.append(line).append('\n');
                        shown++;
                    }
                } catch (Exception e) {
                    String prefix = currentUser.equals(signer) ? "[ME:FAILED] " : "[" + signer + ":FAILED] ";
                    String line = prefix + timestamp + " | error decrypting";
                    sb.append(line).append('\n');
                    shown++;
                }
            }

            listBox.setText(sb.toString());
            statusLabel.setText("Loaded " + shown + " reports from server.");
        } catch (Exception e) {
            statusLabel.setText("Error loading reports: " + e.getMessage());
        }
    }
}
