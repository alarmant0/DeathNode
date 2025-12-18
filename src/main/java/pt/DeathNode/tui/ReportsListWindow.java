package pt.DeathNode.tui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.googlecode.lanterna.TerminalPosition;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import pt.DeathNode.crypto.CryptoLib;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.crypto.Report;
import pt.DeathNode.crypto.SecureDocument;
import pt.DeathNode.util.EndpointConfig;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;

public class ReportsListWindow extends BasicWindow {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private final String currentUser;
    private RadioBoxList<ReportItem> reportList;
    private TextBox detailsBox;
    private Label statusLabel;
    private Label selectionLabel;
    private Runnable refreshAction;
    private int lastSelectedIndex = -1;
    private volatile boolean loading;
    private Thread spinnerThread;
    private Button refreshButton;

    private AtomicBoolean ambientRunning;
    private Thread ambientThread;

    private static final class ReportItem {
        private final String label;
        private final String details;

        private ReportItem(String label, String details) {
            this.label = label;
            this.details = details;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public ReportsListWindow(String currentUser) {
        super("DEATH NODE :: ARCHIVE / " + currentUser);
        this.currentUser = currentUser;
        initializeUI();
    }

    @Override
    public void close() {
        stopAmbient();
        loading = false;
        if (spinnerThread != null) {
            spinnerThread.interrupt();
            spinnerThread = null;
        }
        super.close();
    }

    private static String sanitizeText(String s, boolean allowNewlines) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') {
                if (allowNewlines) {
                    out.append(c);
                } else {
                    out.append(' ');
                }
                continue;
            }
            if (c < 0x20 || c == 0x7f) {
                out.append(' ');
                continue;
            }
            out.append(c);
        }
        return out.toString();
    }

    private static String sanitizeSingleLine(String s) {
        return sanitizeText(s, false);
    }

    private static String sanitizeMultiLine(String s) {
        return sanitizeText(s, true);
    }

    private void invokeLater(Runnable r) {
        TextGUI textGUI = getTextGUI();
        if (textGUI instanceof AbstractTextGUI) {
            ((AbstractTextGUI) textGUI).getGUIThread().invokeLater(r);
        } else {
            r.run();
        }
    }

    private void startSpinner() {
        if (spinnerThread != null) {
            spinnerThread.interrupt();
            spinnerThread = null;
        }
        spinnerThread = new Thread(() -> {
            String[] frames = new String[]{"|", "/", "-", "\\"};
            int i = 0;
            while (loading) {
                String msg = "Loading reports " + frames[i % frames.length];
                invokeLater(() -> {
                    if (statusLabel != null && loading) {
                        statusLabel.setText(msg);
                    }
                });
                i++;
                try {
                    Thread.sleep(120);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
        }, "deathnode-spinner");
        spinnerThread.setDaemon(true);
        spinnerThread.start();
    }

    @Override
    public boolean handleInput(KeyStroke key) {
        if (key != null && key.getKeyType() == KeyType.Escape) {
            close();
            return true;
        }

        if (key != null && key.getKeyType() == KeyType.Character) {
            Character ch = key.getCharacter();
            if (ch != null && (ch == 'r' || ch == 'R') && refreshAction != null) {
                refreshAction.run();
                return true;
            }
        }
        boolean handled = super.handleInput(key);
        updateDetailsFromSelection();
        return handled;
    }

    private void updateDetailsFromSelection() {
        if (loading || reportList == null || detailsBox == null || reportList.getItemCount() == 0) {
            return;
        }
        int idx = reportList.getSelectedIndex();
        if (idx < 0) {
            idx = reportList.getCheckedItemIndex();
        }
        if (idx < 0 || idx >= reportList.getItemCount()) {
            return;
        }

        if (selectionLabel != null) {
            selectionLabel.setText("Selected: " + (idx + 1) + "/" + reportList.getItemCount());
        }

        if (idx == lastSelectedIndex) {
            return;
        }
        lastSelectedIndex = idx;

        ReportItem item = reportList.getItemAt(idx);
        if (item != null) {
            detailsBox.setText(sanitizeMultiLine(item.details));
        }
    }

    private static final class FetchResult {
        private final List<ReportItem> items;
        private final String error;

        private FetchResult(List<ReportItem> items, String error) {
            this.items = items;
            this.error = error;
        }
    }

    private FetchResult fetchReports() {
        try {
            URL url = new URL(EndpointConfig.getGatewayUrl() + "/api/reports");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            String bearer = loadBearerToken(currentUser);
            if (bearer != null) {
                conn.setRequestProperty("Authorization", bearer);
            }
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(1500);

            int code = conn.getResponseCode();
            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                return new FetchResult(null, sanitizeSingleLine("Server returned " + code + " with no body"));
            }
            byte[] bytes = is.readAllBytes();
            String json = new String(bytes, StandardCharsets.UTF_8);

            SecureDocument[] docs = GSON.fromJson(json, SecureDocument[].class);
            if (docs == null || docs.length == 0) {
                return new FetchResult(new ArrayList<>(), null);
            }

            String sr3Error = validateSr3(docs);
            if (sr3Error != null) {
                return new FetchResult(null, sanitizeSingleLine(sr3Error));
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

                items.add(new ReportItem(sanitizeSingleLine(label), sanitizeMultiLine(details)));
            }

            return new FetchResult(items, null);
        } catch (Exception e) {
            return new FetchResult(null, sanitizeSingleLine("Error loading reports: " + e.getMessage()));
        }
    }

    private static String loadBearerToken(String userId) {
        if (userId == null || userId.isBlank()) {
            return null;
        }
        try {
            Path tokenPath = Paths.get("keys", userId + ".token");
            if (!Files.exists(tokenPath)) {
                return null;
            }
            String tokenJson = Files.readString(tokenPath, StandardCharsets.UTF_8);
            if (tokenJson == null || tokenJson.isBlank()) {
                return null;
            }
            String tokenB64 = Base64.getEncoder().encodeToString(tokenJson.getBytes(StandardCharsets.UTF_8));
            return "Bearer " + tokenB64;
        } catch (Exception e) {
            return null;
        }
    }

    private static String normalizePrevHash(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String validateSr3(SecureDocument[] docs) {
        Map<String, List<SecureDocument>> bySigner = new HashMap<>();
        for (SecureDocument d : docs) {
            if (d == null) {
                continue;
            }
            String signer = d.getSignerId();
            if (signer == null) {
                continue;
            }
            bySigner.computeIfAbsent(signer, k -> new ArrayList<>()).add(d);
        }

        for (Map.Entry<String, List<SecureDocument>> e : bySigner.entrySet()) {
            String signer = e.getKey();
            List<SecureDocument> list = e.getValue();
            if (list == null || list.isEmpty()) {
                continue;
            }

            boolean anySeq = false;
            boolean anyMissingSeq = false;
            for (SecureDocument d : list) {
                if (d.getSequenceNumber() == null) {
                    anyMissingSeq = true;
                } else {
                    anySeq = true;
                }
            }
            if (!anySeq || anyMissingSeq) {
                continue;
            }

            list.sort(Comparator.comparingLong(SecureDocument::getSequenceNumber));

            long expectedSeq = 1L;
            SecureDocument prev = null;
            for (SecureDocument cur : list) {
                long seq = cur.getSequenceNumber();
                if (seq != expectedSeq) {
                    return "SR3 violation for signer '" + signer + "': expected sequence_number=" + expectedSeq + " but got " + seq;
                }

                String prevHash = normalizePrevHash(cur.getPreviousHash());
                if (prev == null) {
                    if (prevHash != null) {
                        return "SR3 violation for signer '" + signer + "': expected previous_hash to be null at sequence_number=1";
                    }
                } else {
                    try {
                        String expectedPrev = CryptoLib.computeChainHash(prev);
                        if (prevHash == null || !expectedPrev.equals(prevHash)) {
                            return "SR3 violation for signer '" + signer + "': previous_hash mismatch at sequence_number=" + seq;
                        }
                    } catch (Exception ex) {
                        return "SR3 violation for signer '" + signer + "': failed computing previous hash";
                    }
                }

                prev = cur;
                expectedSeq++;
            }
        }

        return null;
    }

    private void refreshReportsAsync() {
        if (reportList == null || detailsBox == null || statusLabel == null) {
            return;
        }
        if (loading) {
            return;
        }
        loading = true;

        if (refreshButton != null) {
            refreshButton.setEnabled(false);
        }

        reportList.clearItems();
        detailsBox.setText("");
        lastSelectedIndex = -1;
        if (selectionLabel != null) {
            selectionLabel.setText("Selected: 0/0");
        }
        statusLabel.setText("Loading reports...");
        startSpinner();

        new Thread(() -> {
            FetchResult result = fetchReports();

            Runnable uiUpdate = () -> {
                try {
                    reportList.clearItems();
                    detailsBox.setText("");
                    lastSelectedIndex = -1;

                    if (result.error != null) {
                        statusLabel.setText(sanitizeSingleLine(result.error));
                        if (selectionLabel != null) {
                            selectionLabel.setText("Selected: 0/0");
                        }
                        return;
                    }

                    if (result.items == null || result.items.isEmpty()) {
                        statusLabel.setText("No reports found.");
                        if (selectionLabel != null) {
                            selectionLabel.setText("Selected: 0/0");
                        }
                        return;
                    }

                    for (ReportItem item : result.items) {
                        reportList.addItem(item);
                    }

                    reportList.setCheckedItemIndex(0);
                    reportList.setSelectedIndex(0);
                    reportList.takeFocus();
                    updateDetailsFromSelection();
                    statusLabel.setText("Loaded " + result.items.size() + " reports. Use UP/DOWN to view details.");
                } finally {
                    loading = false;
                    if (refreshButton != null) {
                        refreshButton.setEnabled(true);
                    }
                }
            };

            invokeLater(uiUpdate);
        }, "deathnode-reports-fetch").start();
    }

    private void initializeUI() {
        Panel root = new Panel(new LinearLayout(Direction.VERTICAL));

        root.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Panel content = new Panel(new GridLayout(2));
        content.setLayoutData(LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        Panel left = new Panel(new LinearLayout(Direction.VERTICAL));
        left.addComponent(new Label("REPORTS"));
        left.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        RadioBoxList<ReportItem> list = new RadioBoxList<>(new TerminalSize(34, 16));
        this.reportList = list;
        list.setListItemRenderer(new AbstractListBox.ListItemRenderer<ReportItem, RadioBoxList<ReportItem>>() {
            @Override
            public void drawItem(TextGUIGraphics graphics, RadioBoxList<ReportItem> listBox, int index, ReportItem item, boolean selected, boolean focused) {
                TextColor bg = selected ? TextColor.Factory.fromString("#39ff14") : TextColor.Factory.fromString("#101415");
                TextColor fg = selected ? TextColor.Factory.fromString("#050607") : TextColor.Factory.fromString("#d7d7d7");
                int width = graphics.getSize().getColumns();
                graphics.setBackgroundColor(bg);
                graphics.setForegroundColor(fg);
                graphics.fill(' ');

                String label = item == null ? "" : sanitizeSingleLine(item.toString());
                if (label.length() > width) {
                    label = label.substring(0, Math.max(0, width));
                }
                graphics.putString(0, 0, label);
            }
        });
        left.addComponent(list);

        Label selected = new Label("Selected: 0/0");
        this.selectionLabel = selected;
        left.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        left.addComponent(selected);

        Panel right = new Panel(new LinearLayout(Direction.VERTICAL));
        right.addComponent(new Label("DETAILS"));
        right.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        TextBox details = new TextBox(new TerminalSize(58, 16));
        details.setReadOnly(true);
        right.addComponent(details);
        this.detailsBox = details;

        content.addComponent(left);
        content.addComponent(right);
        root.addComponent(content);

        root.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Label hints = new Label("Keys: UP/DOWN select | TAB buttons | R refresh | ESC back");
        root.addComponent(hints);

        Label statusLabel = new Label(" ");
        this.statusLabel = statusLabel;
        root.addComponent(statusLabel);

        Panel buttons = new Panel(new GridLayout(2));
        Button refresh = new Button("REFRESH", this::refreshReportsAsync);
        Button back = new Button("BACK", this::close);
        this.refreshButton = refresh;
        refresh.setRenderer(new SolidFocusButtonRenderer());
        back.setRenderer(new SolidFocusButtonRenderer());
        buttons.addComponent(refresh);
        buttons.addComponent(back);
        root.addComponent(buttons);

        root.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label ambientLabel = new Label(" ");
        root.addComponent(ambientLabel);

        Border border = Borders.doubleLine();
        border.setComponent(root);
        setComponent(border);
        setHints(java.util.Collections.singletonList(Hint.CENTERED));

        startAmbient(ambientLabel);

        refreshReportsAsync();
        list.takeFocus();

        this.refreshAction = this::refreshReportsAsync;
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
        }, "deathnode-ambient-archive");
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
