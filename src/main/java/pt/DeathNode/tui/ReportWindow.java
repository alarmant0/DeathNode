package pt.DeathNode.tui;

import com.googlecode.lanterna.TerminalPosition;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
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
import java.util.concurrent.atomic.AtomicBoolean;

public class ReportWindow extends BasicWindow {
    private final String username;
    private final WindowBasedTextGUI textGUI;

    private AtomicBoolean ambientRunning;
    private Thread ambientThread;

    public ReportWindow(String username, WindowBasedTextGUI textGUI) {
        super("DEATH NODE :: REPORT");
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

    private void showRyukDialog() {
        final long openedAtMs = System.currentTimeMillis();
        final BasicWindow dialog = new BasicWindow("DEATH NOTE :: RYUK") {
            @Override
            public boolean handleInput(KeyStroke key) {
                if (key != null && key.getKeyType() == KeyType.Escape) {
                    close();
                    return true;
                }

                if (key != null && (key.getKeyType() == KeyType.Enter || key.getKeyType() == KeyType.Character)) {
                    long elapsed = System.currentTimeMillis() - openedAtMs;
                    if (elapsed < 450) {
                        return true;
                    }
                }
                return super.handleInput(key);
            }
        };

        Panel panel = new Panel(new LinearLayout(Direction.VERTICAL));
        panel.addComponent(new Label("Submission accepted."));
        panel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        String art = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠈⠹⡆⢀⣤⣤⡀⢠⣤⢠⣤⣿⡤⣴⡆⠀⣴⠀⠀⠀⢠⣄⠀⢠⡄⠀⠀⠀⣤⣄⣿⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠰⠆⠀⣷⢸⣧⣀⡀⢸⢹⡆⠀⢸⡇⠠⣧⢤⣿⠀⠀⠀⢸⡟⣦⣸⡇⡞⡙⢣⡀⢠⡇⠀⢿⠋⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⣠⠟⢸⣇⣀⡀⣿⠉⢻⡀⢸⡇⠀⣿⠀⣿⠀⠀⠀⣸⡇⠘⢿⡏⢇⣁⡼⠃⣼⠃⠀⣼⡓⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⡿⠒⠋⠁⠀⠈⠉⠉⠁⠉⠀⠀⠀⠀⠉⠀⠉⠀⠉⠀⠀⠀⠉⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠛⠓⠲⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣠⣴⣶⣾⣿⣿⣾⣷⣦⣤⣿⣶⣶⣤⣄⣀⢤⡀⠀⠀⠀⠀⢰⣴⣶⣷⣴⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣄⣀⣀⣀⣤⣤⣶⣶⣶⣦⣤⠤
⠠⠔⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⠀⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⢀⣀⣤⣾⣿⣿⣿⣿⣿⣿⣿⠟⠛⠛⠂⠀⠀
⠀⠀⠀⠘⠋⠉⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⢻⣿⣿⣿⣿⡏⠀⠀⠀⢀⣤⣾⣿⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⠀⡿⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠼⠛⠟⠋⣿⣿⡿⠋⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⠋⠙⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡿⠀⠸⠋⣿⣿⣿⠛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠻⣿⣿⣿⠋⠛⠇⠀⠀⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⠀⢀⣿⣿⠁⠀⠈⢻⣿⣿⣿⣿⣿⡿⠋⠈⣿⣿⡏⠃⠀⠘⣿⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡏⠀⠀⠀⠈⣿⣿⣿⣿⣿⠀⠀⠀⠸⣿⣇⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⣼⣿⣿⣿⣿⣿⡄⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠁⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣇⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⢠⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣦⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠋⠉⠉⠛⠉⠋⠻⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⣤⣾⣿⣿⣿⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⡇⠙⠀⠀⠀⢸⠋⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⢿⣷⡢⡀⠀⠀⢀⣰⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⠀⠁⠁⠀⠀⠀⠀⠉⢠⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡄⠀⠀⠀⠀⠀⠀⠀⣾⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣇⠀⠀⠀⠀⠀⠀⢸⣿⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡿⠀⠀⠀⠀⠀⠀⠘⢿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠃⠀⠀⠀⠀⠀⠀⠀⠈⠻⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

""";

        String[] lines = art.split("\\n", -1);
        int maxLen = 0;
        for (String line : lines) {
            if (line != null && line.length() > maxLen) {
                maxLen = line.length();
            }
        }
        int boxW = Math.min(120, Math.max(60, maxLen + 2));
        int boxH = Math.min(40, Math.max(16, lines.length + 1));

        TextBox artBox = new TextBox(new TerminalSize(boxW, boxH));
        artBox.setReadOnly(true);
        artBox.setText(art);
        panel.addComponent(artBox);

        Panel buttonPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        Button ok = new Button("OK", dialog::close);
        ok.setEnabled(false);
        ok.setRenderer(new SolidFocusButtonRenderer());
        buttonPanel.addComponent(ok);
        panel.addComponent(buttonPanel);

        dialog.setComponent(panel);
        dialog.setHints(java.util.Collections.singletonList(Hint.CENTERED));

        Thread autoClose = new Thread(() -> {
            try {
                Thread.sleep(650);
            } catch (InterruptedException ignored) {
                return;
            }
            invokeLater(() -> {
                try {
                    dialog.close();
                } catch (Exception ignored) {
                }
            });
        }, "deathnode-ryuk-autoclose");
        autoClose.setDaemon(true);
        autoClose.start();

        new Thread(() -> {
            try {
                Thread.sleep(450);
            } catch (InterruptedException ignored) {
                return;
            }
            invokeLater(() -> ok.setEnabled(true));
        }, "deathnode-ryuk-ok-delay").start();

        textGUI.addWindowAndWait(dialog);
    }

    @Override
    public void close() {
        stopAmbient();
        super.close();
    }

    private void initializeUI() {
        Panel mainPanel = new Panel();
        mainPanel.setLayoutManager(new GridLayout(1));

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
        final Button[] submitRef = new Button[1];
        final Button submit = new Button("Submit", () -> {
            String suspect = suspectBox.getText().trim();
            String location = locationBox.getText().trim();
            String description = descriptionBox.getText().trim();

            if (suspect.isEmpty() || location.isEmpty() || description.isEmpty()) {
                messageLabel.setText("All fields are required!");
                return;
            }

            submitRef[0].setEnabled(false);
            suspectBox.setEnabled(false);
            locationBox.setEnabled(false);
            descriptionBox.setEnabled(false);
            messageLabel.setText("Submitting...");

            AtomicBoolean loading = new AtomicBoolean(true);
            Thread spinnerThread = new Thread(() -> {
                String[] frames = new String[]{"|", "/", "-", "\\"};
                int i = 0;
                while (loading.get()) {
                    String msg = "Submitting " + frames[i % frames.length];
                    invokeLater(() -> {
                        if (loading.get()) {
                            messageLabel.setText(msg);
                        }
                    });
                    i++;
                    try {
                        Thread.sleep(120);
                    } catch (InterruptedException ignored) {
                        return;
                    }
                }
            }, "deathnode-report-submit-spinner");
            spinnerThread.setDaemon(true);
            spinnerThread.start();

            new Thread(() -> {
                String finalMsg;
                boolean success = false;
                try {
                    Report report = Report.createNew(username, suspect, description, location);

                    SecretKey encKey = KeyManager.loadSymmetricKey(username);
                    PrivateKey signKey = KeyManager.loadPrivateKey(username);

                    SecureDocument secDoc = CryptoLib.protect(report, encKey, signKey, username);
                    String secJson = secDoc.toJson();

                    Path outDir = Paths.get("db", "reports");
                    Files.createDirectories(outDir);
                    Path outPath = outDir.resolve("report_" + username + ".secure");
                    Files.writeString(outPath, secJson, StandardCharsets.UTF_8);
                    success = true;

                    boolean posted = false;
                    try {
                        URL url = new URL("http://localhost:8080/reports");
                        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                        conn.setConnectTimeout(1500);
                        conn.setReadTimeout(1500);
                        conn.setRequestMethod("POST");
                        conn.setRequestProperty("Content-Type", "application/json");
                        conn.setDoOutput(true);

                        byte[] body = secJson.getBytes(StandardCharsets.UTF_8);
                        try (java.io.OutputStream os = conn.getOutputStream()) {
                            os.write(body);
                        }

                        int code = conn.getResponseCode();
                        posted = (code / 100) == 2;
                        if (!posted) {
                            System.err.println("Warning: server /reports responded with status " + code);
                        }
                    } catch (Exception e) {
                        System.err.println("Warning: failed to POST report to server: " + e.getMessage());
                    }

                    System.out.println("Protected report written to: " + outPath.toAbsolutePath());
                    finalMsg = posted
                            ? "Protected report saved and sent as " + outPath.getFileName()
                            : "Protected report saved as " + outPath.getFileName() + " (server unreachable)";
                } catch (Exception e) {
                    finalMsg = "Error protecting report: " + e.getMessage();
                } finally {
                    loading.set(false);
                    spinnerThread.interrupt();
                }

                String msg = finalMsg;
                boolean showRyuk = success;
                invokeLater(() -> {
                    messageLabel.setText(msg);
                    submitRef[0].setEnabled(true);
                    suspectBox.setEnabled(true);
                    locationBox.setEnabled(true);
                    descriptionBox.setEnabled(true);

                    if (showRyuk) {
                        showRyukDialog();
                    }
                });
            }, "deathnode-report-submit").start();
        });
        submitRef[0] = submit;
        submit.setRenderer(new SolidFocusButtonRenderer());

        final Button viewReports = new Button("View Reports", () -> {
            ReportsListWindow listWindow = new ReportsListWindow(username);
            textGUI.addWindowAndWait(listWindow);
        });
        viewReports.setRenderer(new SolidFocusButtonRenderer());

        final Button close = new Button("Back", this::close);
        close.setRenderer(new SolidFocusButtonRenderer());
        buttons.addComponent(submit);
        buttons.addComponent(viewReports);
        buttons.addComponent(close);
        mainPanel.addComponent(buttons);

        Border border = Borders.doubleLine();
        border.setComponent(mainPanel);
        setComponent(border);
        setHints(java.util.Collections.singletonList(Hint.CENTERED));
    }

    private void invokeLater(Runnable runnable) {
        if (textGUI == null) {
            runnable.run();
            return;
        }
        textGUI.getGUIThread().invokeLater(runnable);
    }

    private void startAmbient(Label target) {
        stopAmbient();
        ambientRunning = new AtomicBoolean(true);
        ambientThread = new Thread(() -> {
            int tick = 0;
            while (ambientRunning.get()) {
                String frame = buildAmbientFrame(tick++);
                invokeLater(() -> {
                    if (ambientRunning.get()) {
                        target.setText(frame);
                    }
                });
                try {
                    Thread.sleep(150);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
        }, "deathnode-ambient-report");
        ambientThread.setDaemon(true);
        ambientThread.start();
    }

    private void stopAmbient() {
        if (ambientRunning != null) {
            ambientRunning.set(false);
        }
        if (ambientThread != null) {
            ambientThread.interrupt();
            ambientThread = null;
        }
    }

    private static String buildAmbientFrame(int tick) {
        String stream = "0123456789abcdef";
        int width = 52;
        int offset = tick % stream.length();
        StringBuilder repeated = new StringBuilder(width + stream.length());
        while (repeated.length() < width + stream.length()) {
            repeated.append(stream);
        }
        String rep = repeated.toString();
        String slice = rep.substring(offset, offset + width);
        String caret = (tick % 2 == 0) ? "|" : " ";
        return "IDLE " + caret + "  " + slice;
    }

    private static final class SolidFocusButtonRenderer implements Button.ButtonRenderer {
        @Override
        public TerminalPosition getCursorLocation(Button component) {
            return null;
        }

        @Override
        public TerminalSize getPreferredSize(Button component) {
            String label = component.getLabel() == null ? "" : component.getLabel();
            return new TerminalSize(Math.max(6, label.length() + 4), 1);
        }

        @Override
        public void drawComponent(TextGUIGraphics graphics, Button component) {
            int width = graphics.getSize().getColumns();
            if (width <= 0) {
                return;
            }

            TextColor focusedBg = TextColor.Factory.fromString("#39ff14");
            TextColor focusedFg = TextColor.Factory.fromString("#050607");
            TextColor normalBg = TextColor.Factory.fromString("#101415");
            TextColor normalFg = TextColor.Factory.fromString("#39ff14");

            graphics.setBackgroundColor(component.isFocused() ? focusedBg : normalBg);
            graphics.setForegroundColor(component.isFocused() ? focusedFg : normalFg);
            graphics.fill(' ');

            if (width >= 2) {
                graphics.putString(0, 0, "<");
                graphics.putString(width - 1, 0, ">");
            }

            String label = component.getLabel() == null ? "" : component.getLabel();
            int start = Math.max(0, (width - label.length()) / 2);
            if (start + label.length() > width) {
                label = label.substring(0, Math.max(0, width - start));
            }
            graphics.putString(start, 0, label);
        }
    }
}
