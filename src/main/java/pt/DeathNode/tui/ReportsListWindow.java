package pt.DeathNode.tui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
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
import java.util.ArrayList;
import java.util.List;

public class ReportsListWindow extends BasicWindow {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private final String currentUser;

    private static final class ReportItem {
        private final String label;
        private final String details;

        private ReportItem(String label, String details) {
            this.label = label;
            this.details = details;
        }
    }

    public ReportsListWindow(String currentUser) {
        super("DEATH NODE :: ARCHIVE");
        this.currentUser = currentUser;
        initializeUI();
    }

    @Override
    public boolean handleInput(KeyStroke key) {
        if (key != null && key.getKeyType() == KeyType.Escape) {
            close();
            return true;
        }
        return super.handleInput(key);
    }

    private void initializeUI() {
        Panel root = new Panel(new LinearLayout(Direction.VERTICAL));

        Label header = new Label("ARCHIVE / " + currentUser);
        header.setLayoutData(LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        root.addComponent(header);
        root.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Panel content = new Panel(new GridLayout(2));
        content.setLayoutData(LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        Panel left = new Panel(new LinearLayout(Direction.VERTICAL));
        left.addComponent(new Label("REPORTS"));
        left.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        ActionListBox list = new ActionListBox(new TerminalSize(34, 16));
        left.addComponent(list);

        Panel right = new Panel(new LinearLayout(Direction.VERTICAL));
        right.addComponent(new Label("DETAILS"));
        right.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        TextBox details = new TextBox(new TerminalSize(58, 16));
        details.setReadOnly(true);
        right.addComponent(details);

        content.addComponent(left);
        content.addComponent(right);
        root.addComponent(content);

        root.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Label statusLabel = new Label(" ");
        root.addComponent(statusLabel);

        Panel buttons = new Panel(new GridLayout(3));
        Button refresh = new Button("REFRESH", () -> loadReports(list, details, statusLabel));
        Button back = new Button("BACK", this::close);
        Button clear = new Button("CLEAR", () -> details.setText(""));
        buttons.addComponent(refresh);
        buttons.addComponent(clear);
        buttons.addComponent(back);
        root.addComponent(buttons);

        Border border = Borders.doubleLine("ARCHIVE  [ESC to close]");
        border.setComponent(root);
        setComponent(border);
        setHints(java.util.Collections.singletonList(Hint.CENTERED));

        loadReports(list, details, statusLabel);
    }

    private void loadReports(ActionListBox list, TextBox detailsBox, Label statusLabel) {
        list.clearItems();
        detailsBox.setText("");
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

            List<ReportItem> items = new ArrayList<>();
            for (SecureDocument doc : docs) {
                if (doc == null || doc.getEncryptedData() == null) {
                    continue;
                }
                String signer = doc.getSignerId() != null ? doc.getSignerId() : "?";
                String timestamp = doc.getTimestamp() != null ? doc.getTimestamp() : "?";

                String labelPrefix = currentUser.equals(signer) ? "ME" : signer;
                String label;
                String details;

                try {
                    if (signer != null && !"?".equals(signer)) {
                        SecretKey decKey = KeyManager.loadSymmetricKey(signer);
                        PublicKey verifyKey = KeyManager.loadPublicKey(signer);
                        Report report = CryptoLib.unprotect(doc, decKey, verifyKey);

                        String suspect = report.getContent() != null && report.getContent().getSuspect() != null
                                ? report.getContent().getSuspect() : "?";
                        String location = report.getContent() != null && report.getContent().getLocation() != null
                                ? report.getContent().getLocation() : "?";
                        String description = report.getContent() != null && report.getContent().getDescription() != null
                                ? report.getContent().getDescription() : "";

                        label = "[" + labelPrefix + "] " + timestamp + " | " + suspect + " @ " + location;
                        StringBuilder db = new StringBuilder();
                        db.append("Signer: ").append(signer).append('\n');
                        db.append("Timestamp: ").append(timestamp).append('\n');
                        db.append("Suspect: ").append(suspect).append('\n');
                        db.append("Location: ").append(location).append('\n');
                        if (!description.isEmpty()) {
                            db.append('\n').append(description).append('\n');
                        }
                        details = db.toString();
                    } else {
                        label = "[" + labelPrefix + "] " + timestamp + " | [encrypted]";
                        details = "Encrypted report details not available.";
                    }
                } catch (Exception e) {
                    label = "[" + labelPrefix + "] " + timestamp + " | [decrypt failed]";
                    details = "Error decrypting report: " + e.getMessage();
                }

                items.add(new ReportItem(label, details));
            }

            if (items.isEmpty()) {
                statusLabel.setText("No readable reports returned.");
                return;
            }

            for (int i = 0; i < items.size(); i++) {
                ReportItem item = items.get(i);
                list.addItem(item.label, () -> detailsBox.setText(item.details));
            }

            statusLabel.setText("Loaded " + items.size() + " reports. Click one to view details.");
            detailsBox.setText(items.get(0).details);
        } catch (Exception e) {
            statusLabel.setText("Error loading reports: " + e.getMessage());
        }
    }
}
