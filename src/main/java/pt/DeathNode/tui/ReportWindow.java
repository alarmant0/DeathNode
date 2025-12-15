package pt.DeathNode.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import pt.DeathNode.crypto.Report;
import pt.DeathNode.crypto.SecureDocument;
import pt.DeathNode.crypto.CryptoLib;
import pt.DeathNode.crypto.KeyManager;

import javax.crypto.SecretKey;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;

public class ReportWindow extends BasicWindow {
    private final String username;
    private final WindowBasedTextGUI textGUI;

    public ReportWindow(String username, WindowBasedTextGUI textGUI) {
        super("DEATH NODE :: REPORT TERMINAL");
        this.username = username;
        this.textGUI = textGUI;
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
        Panel mainPanel = new Panel();
        mainPanel.setLayoutManager(new GridLayout(1));

        mainPanel.addComponent(new Label("SUBMIT NEW REPORT").setLayoutData(
                GridLayout.createHorizontallyFilledLayoutData(1)));

        mainPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel suspectPanel = new Panel(new GridLayout(2));
        suspectPanel.addComponent(new Label("Suspect:"));
        TextBox suspectBox = new TextBox();
        suspectBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        suspectPanel.addComponent(suspectBox);
        mainPanel.addComponent(suspectPanel);

        mainPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel locationPanel = new Panel(new GridLayout(2));
        locationPanel.addComponent(new Label("Location:"));
        TextBox locationBox = new TextBox();
        locationBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        locationPanel.addComponent(locationBox);
        mainPanel.addComponent(locationPanel);

        mainPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        mainPanel.addComponent(new Label("Description:"));
        TextBox descriptionBox = new TextBox(new TerminalSize(60, 5));
        descriptionBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        mainPanel.addComponent(descriptionBox);

        Label messageLabel = new Label("");
        messageLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        mainPanel.addComponent(messageLabel);

        Panel buttons = new Panel(new GridLayout(3));
        Button submit = new Button("Submit", () -> {
            String suspect = suspectBox.getText().trim();
            String location = locationBox.getText().trim();
            String description = descriptionBox.getText().trim();

            if (suspect.isEmpty() || location.isEmpty() || description.isEmpty()) {
                messageLabel.setText("All fields are required!");
                return;
            }

            try {
                Report report = Report.createNew(username, suspect, description, location);

                SecretKey encKey = KeyManager.loadSymmetricKey(username);
                PrivateKey signKey = KeyManager.loadPrivateKey(username);

                SecureDocument secDoc = CryptoLib.protect(report, encKey, signKey, username);

                String secJson = secDoc.toJson();

                Path outPath = Paths.get("report_" + username + ".secure");
                Files.writeString(outPath, secJson, StandardCharsets.UTF_8);

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
                    }
                } catch (Exception e) {
                    System.err.println("Warning: failed to POST report to server: " + e.getMessage());
                }

                System.out.println("Protected report written to: " + outPath.toAbsolutePath());
                messageLabel.setText("Protected report saved and sent to server as " + outPath.getFileName());
            } catch (Exception e) {
                messageLabel.setText("Error protecting report: " + e.getMessage());
            }
        });

        Button viewReports = new Button("View Reports", () -> {
            ReportsListWindow listWindow = new ReportsListWindow(username);
            textGUI.addWindowAndWait(listWindow);
        });

        Button close = new Button("Back", this::close);
        buttons.addComponent(submit);
        buttons.addComponent(viewReports);
        buttons.addComponent(close);
        mainPanel.addComponent(buttons);

        Border border = Borders.doubleLine("REPORT");
        border.setComponent(mainPanel);
        setComponent(border);
        setHints(java.util.Collections.singletonList(Hint.CENTERED));
    }
}
