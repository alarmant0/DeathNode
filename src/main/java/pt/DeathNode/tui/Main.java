package pt.DeathNode.tui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.googlecode.lanterna.SGR;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.TerminalPosition;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.graphics.SimpleTheme;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.MouseCaptureMode;
import com.googlecode.lanterna.terminal.Terminal;
import com.googlecode.lanterna.terminal.swing.SwingTerminalFrame;
import pt.DeathNode.auth.AuthToken;
import pt.DeathNode.auth.JoinRequest;
import pt.DeathNode.auth.TokenValidationResponse;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.crypto.TokenManager;
import pt.DeathNode.tui.ReportWindow;
import pt.DeathNode.util.EndpointConfig;
import pt.DeathNode.util.TlsConfig;

import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import javax.swing.WindowConstants;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.RenderingHints;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public class Main {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String GATEWAY_URL = EndpointConfig.getGatewayUrl();
    private static final String DB_URL = "jdbc:sqlite:db/deathnode.db";
    private static final SimpleTheme DEATH_THEME = buildTheme();

    private static Image loadAppIconOrFallback() {
        try {
            File f = new File("img/icon/ryuk.png");
            if (f.isFile()) {
                BufferedImage img = ImageIO.read(f);
                if (img != null) {
                    return img;
                }
            }
        } catch (Exception ignored) {
        }
        return buildAppIcon();
    }

    private static Image buildAppIcon() {
        int size = 32;
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        Color bg = new Color(5, 6, 7);
        Color accent = new Color(57, 255, 20);
        Color cover = new Color(10, 11, 12);
        Color paper = new Color(230, 230, 230);

        g.setColor(bg);
        g.fillRect(0, 0, size, size);

        int pad = 6;
        int bookX = pad;
        int bookY = pad;
        int bookW = size - pad * 2;
        int bookH = size - pad * 2;

        g.setColor(cover);
        g.fillRoundRect(bookX, bookY, bookW, bookH, 5, 5);

        g.setColor(accent);
        g.drawRoundRect(bookX, bookY, bookW, bookH, 5, 5);
        g.drawLine(bookX + 4, bookY + 2, bookX + 4, bookY + bookH - 2);

        g.setColor(paper);
        g.setFont(new Font(Font.SERIF, Font.BOLD, 8));
        FontMetrics fm = g.getFontMetrics();
        String line1 = "DEATH";
        String line2 = "NOTE";
        int cx = bookX + (bookW - Math.max(fm.stringWidth(line1), fm.stringWidth(line2))) / 2 + 2;
        int cy = bookY + 10;
        g.drawString(line1, cx, cy);
        g.drawString(line2, cx + 3, cy + fm.getHeight());

        int skullX = bookX + 7;
        int skullY = bookY + 6;
        g.setColor(paper);
        g.fillOval(skullX, skullY, 8, 7);
        g.setColor(bg);
        g.fillOval(skullX + 2, skullY + 2, 2, 2);
        g.fillOval(skullX + 5, skullY + 2, 2, 2);
        g.fillRect(skullX + 4, skullY + 4, 1, 2);

        g.dispose();
        return img;
    }

    private static SimpleTheme buildTheme() {
        TextColor bg = TextColor.Factory.fromString("#050607");
        TextColor fg = TextColor.Factory.fromString("#d7d7d7");
        TextColor panelBg = TextColor.Factory.fromString("#101415");
        TextColor accent = TextColor.Factory.fromString("#39ff14");

        SimpleTheme theme = new SimpleTheme(fg, bg);
        theme.addOverride(Button.class, accent, panelBg, SGR.BOLD);
        theme.addOverride(Label.class, fg, panelBg);
        theme.addOverride(TextBox.class, accent, panelBg, SGR.BOLD);
        theme.addOverride(ActionListBox.class, accent, panelBg, SGR.BOLD);
        theme.addOverride(BasicWindow.class, fg, bg);
        return theme;
    }

    public static void main(String[] args) throws IOException {
        try {
            TlsConfig.installClientTlsFromEnvIfPresent();
        } catch (Exception ignored) {
        }

        DefaultTerminalFactory terminalFactory = new DefaultTerminalFactory()
                .setPreferTerminalEmulator(true)
                .setTerminalEmulatorTitle("T27 :: DEATHNODE")
                .setInitialTerminalSize(new TerminalSize(120, 36))
                .setMouseCaptureMode(MouseCaptureMode.CLICK_RELEASE_DRAG_MOVE);

        SwingTerminalFrame terminalFrame = terminalFactory.createSwingTerminal();
        terminalFrame.setTitle("T27 :: DEATHNODE");
        terminalFrame.setIconImage(loadAppIconOrFallback());
        terminalFrame.setResizable(false);
        terminalFrame.pack();
        terminalFrame.setLocationRelativeTo(null);
        terminalFrame.setVisible(true);

        Terminal terminal = terminalFrame;
        Screen screen = new TerminalScreen(terminal);
        screen.startScreen();

        WindowBasedTextGUI textGUI = new MultiWindowTextGUI(screen);
        textGUI.setTheme(DEATH_THEME);

        MatrixRainComponent matrix = new MatrixRainComponent();
        BasicWindow backgroundWindow = new BasicWindow() {
            @Override
            public boolean handleInput(KeyStroke key) {
                return false;
            }
        };
        backgroundWindow.setHints(Arrays.asList(Window.Hint.NO_DECORATIONS, Window.Hint.FULL_SCREEN));
        backgroundWindow.setComponent(matrix);
        textGUI.addWindow(backgroundWindow);

        AtomicBoolean matrixRunning = new AtomicBoolean(true);
        Thread matrixThread = new Thread(() -> {
            while (matrixRunning.get()) {
                invokeLater(textGUI, matrix::tick);
                try {
                    Thread.sleep(130);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
        }, "deathnode-matrix-rain");
        matrixThread.setDaemon(true);
        matrixThread.start();

        BasicWindow authWindow = new BasicWindow("DEATH NODE :: ACCESS TERMINAL") {
            @Override
            public boolean handleInput(KeyStroke key) {
                if (key != null && key.getKeyType() == KeyType.Escape) {
                    close();
                    return true;
                }
                return super.handleInput(key);
            }
        };

        AtomicBoolean shuttingDown = new AtomicBoolean(false);
        Runnable cleanup = () -> {
            if (!shuttingDown.compareAndSet(false, true)) {
                return;
            }
            try {
                try {
                    matrixRunning.set(false);
                } catch (Exception ignored) {
                }
                try {
                    matrixThread.interrupt();
                } catch (Exception ignored) {
                }

                try {
                    backgroundWindow.close();
                } catch (Exception ignored) {
                }
                try {
                    authWindow.close();
                } catch (Exception ignored) {
                }
                try {
                    screen.stopScreen();
                } catch (Exception ignored) {
                }
            } finally {
                try {
                    terminalFrame.dispose();
                } catch (Exception ignored) {
                }
            }
        };

        terminalFrame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        terminalFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                new Thread(cleanup, "deathnode-shutdown").start();
            }

            @Override
            public void windowClosed(WindowEvent e) {
                new Thread(cleanup, "deathnode-shutdown").start();
            }
        });

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                cleanup.run();
            } catch (Exception ignored) {
            }
        }, "deathnode-shutdown-hook"));

        Panel loginPanel = createLoginPanel(textGUI, authWindow);

        final Runnable[] showLoginRef = new Runnable[1];
        Runnable onBackToLogin = () -> {
            Runnable r = showLoginRef[0];
            if (r != null) {
                r.run();
            }
        };

        Panel tokenRegisterPanel = createTokenRegisterPanel(textGUI, authWindow, onBackToLogin);

        showLoginRef[0] = () -> {
            loginPanel.setVisible(true);
            tokenRegisterPanel.setVisible(false);
        };

        tokenRegisterPanel.setVisible(false);

        Panel cardPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        cardPanel.addComponent(loginPanel);
        cardPanel.addComponent(tokenRegisterPanel);

        ActionListBox nav = new ActionListBox(new TerminalSize(22, 8));
        nav.setListItemRenderer(new AbstractListBox.ListItemRenderer<Runnable, ActionListBox>() {
            @Override
            public void drawItem(TextGUIGraphics graphics, ActionListBox listBox, int index, Runnable item, boolean selected, boolean focused) {
                TextColor bg = selected ? TextColor.Factory.fromString("#39ff14") : TextColor.Factory.fromString("#101415");
                TextColor fg = selected ? TextColor.Factory.fromString("#050607") : TextColor.Factory.fromString("#d7d7d7");
                int width = graphics.getSize().getColumns();
                graphics.setBackgroundColor(bg);
                graphics.setForegroundColor(fg);
                graphics.fill(' ');

                String label = item == null ? "" : item.toString();
                if (label.length() > width) {
                    label = label.substring(0, Math.max(0, width));
                }
                graphics.putString(0, 0, label);
            }
        });
        nav.addItem("LOGIN", onBackToLogin);
        nav.addItem("INVITATION TOKEN", () -> {
            loginPanel.setVisible(false);
            tokenRegisterPanel.setVisible(true);
        });
        nav.addItem("QUIT", authWindow::close);

        Panel navPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        navPanel.addComponent(new Label("NAVIGATION").addStyle(SGR.BOLD));
        navPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        navPanel.addComponent(nav);

        Panel contentPanel = new Panel(new GridLayout(2));
        contentPanel.addComponent(navPanel);
        contentPanel.addComponent(cardPanel);

        Panel mainPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        mainPanel.addComponent(contentPanel);

        final Label statusHintLabel = new Label("Keys: TAB switch | ENTER activate | ESC quit");
        statusHintLabel.setLayoutData(LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        mainPanel.addComponent(statusHintLabel);

        Border border = Borders.doubleLine();
        border.setComponent(mainPanel);
        authWindow.setComponent(border);
        authWindow.setHints(Collections.singletonList(Window.Hint.CENTERED));

        textGUI.addWindowAndWait(authWindow);

        matrixRunning.set(false);
        matrixThread.interrupt();
        backgroundWindow.close();
        screen.stopScreen();
        terminalFrame.dispose();
    }

    private static Panel createLoginPanel(WindowBasedTextGUI textGUI, BasicWindow authWindow) {
        Panel loginPanel = new Panel();
        loginPanel.setLayoutManager(new GridLayout(1));
        loginPanel.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.FILL,
                GridLayout.Alignment.CENTER,
                true,
                true
        ));

        Label title = new Label(" SYSTEM ACCESS ");
        title.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        loginPanel.addComponent(title);

        loginPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel userPanel = new Panel(new GridLayout(2));
        userPanel.addComponent(new Label("Username:"));
        final TextBox loginUsernameBox = new TextBox();
        loginUsernameBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        userPanel.addComponent(loginUsernameBox);
        loginPanel.addComponent(userPanel);

        loginPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel passPanel = new Panel(new GridLayout(2));
        passPanel.addComponent(new Label("Password:"));
        final TextBox loginPasswordBox = new TextBox().setMask('*');
        loginPasswordBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        passPanel.addComponent(loginPasswordBox);
        loginPanel.addComponent(passPanel);

        final Label loginMsgLabel = new Label(" ");
        loginMsgLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        loginPanel.addComponent(loginMsgLabel);

        loginPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        final Button[] loginBtnRef = new Button[1];
        final Button loginBtn = new Button("Login", () -> {
            String username = loginUsernameBox.getText();
            String password = loginPasswordBox.getText();
            attemptLogin(username, password, loginMsgLabel, textGUI, authWindow, loginBtnRef[0], loginUsernameBox, loginPasswordBox);
        });
        loginBtnRef[0] = loginBtn;
        loginBtn.setRenderer(new SolidFocusButtonRenderer());
        loginBtn.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        loginPanel.addComponent(loginBtn);

        return loginPanel;
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

    private static void attemptLogin(String username, String password,
                                     Label msgLabel, WindowBasedTextGUI textGUI, BasicWindow loginWindow,
                                     Button loginBtn, TextBox usernameBox, TextBox passwordBox) {
        username = username == null ? "" : username.trim();
        password = password == null ? "" : password.trim();

        final String finalPassword = password;

        if (username.isEmpty() || password.isEmpty()) {
            msgLabel.setText("Please enter both username and password");
            return;
        }

        final String userId = username;
        if (loginBtn != null) {
            loginBtn.setEnabled(false);
        }
        if (usernameBox != null) {
            usernameBox.setEnabled(false);
        }
        if (passwordBox != null) {
            passwordBox.setEnabled(false);
        }

        AtomicBoolean loading = new AtomicBoolean(true);
        Thread spinnerThread = new Thread(() -> {
            String[] frames = new String[]{"|", "/", "-", "\\"};
            int i = 0;
            while (loading.get()) {
                String msg = "Authenticating " + frames[i % frames.length];
                invokeLater(textGUI, () -> {
                    if (msgLabel != null && loading.get()) {
                        msgLabel.setText(msg);
                    }
                });
                i++;
                try {
                    Thread.sleep(120);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
        }, "deathnode-login-spinner");
        spinnerThread.setDaemon(true);
        spinnerThread.start();

        new Thread(() -> {
            String error = null;
            boolean ok = false;
            try {
                if (!authenticateUser(userId, finalPassword)) {
                    error = "Invalid username or password";
                    return;
                }

                ensureUserKeys(userId);
                AuthToken token = loadTokenIfPresent(userId);

                if (token == null || token.isExpired()) {
                    invokeLater(textGUI, () -> {
                        if (msgLabel != null) {
                            msgLabel.setText("Registering user on server...");
                        }
                    });
                    token = requestTokenFromServer(userId);
                    saveToken(userId, token);
                }
                ok = true;
            } catch (Exception e) {
                error = "Login failed: " + e.getMessage();
            } finally {
                loading.set(false);
                spinnerThread.interrupt();
                String finalError = error;
                boolean finalOk = ok;
                invokeLater(textGUI, () -> {
                    if (loginBtn != null) {
                        loginBtn.setEnabled(true);
                    }
                    if (usernameBox != null) {
                        usernameBox.setEnabled(true);
                    }
                    if (passwordBox != null) {
                        passwordBox.setEnabled(true);
                    }
                    if (!finalOk && msgLabel != null) {
                        msgLabel.setText(finalError == null ? "Login failed" : finalError);
                    }
                });
            }

            if (!ok) {
                return;
            }

            CountDownLatch createdLatch = new CountDownLatch(1);
            final ReportWindow[] reportWindowRef = new ReportWindow[1];
            invokeLater(textGUI, () -> {
                ReportWindow reportWindow = new ReportWindow(userId, textGUI);
                reportWindowRef[0] = reportWindow;
                textGUI.addWindow(reportWindow);
                createdLatch.countDown();
            });

            try {
                createdLatch.await();
            } catch (InterruptedException ignored) {
                return;
            }

            if (reportWindowRef[0] != null) {
                textGUI.waitForWindowToClose(reportWindowRef[0]);
            }

            invokeLater(textGUI, loginWindow::close);
        }, "deathnode-login").start();
    }

    private static boolean authenticateUser(String username, String password) throws Exception {
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

    private static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    private static void createLocalUser(String username, String password) throws Exception {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        if (username.trim().length() < 3) {
            throw new IllegalArgumentException("Username must be at least 3 characters");
        }

        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new Exception("SQLite JDBC driver not found", e);
        }

        String passwordHash = hashPassword(password);
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            try (java.sql.Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE TABLE IF NOT EXISTS users (" +
                        "username TEXT PRIMARY KEY CHECK (length(username) >= 3)," +
                        "password_hash TEXT NOT NULL CHECK (length(password_hash) >= 8)," +
                        "created_at TEXT NOT NULL DEFAULT (datetime('now'))," +
                        "last_login TEXT," +
                        "active BOOLEAN DEFAULT 1 CHECK (active IN (0,1))" +
                        ")");
            }

            String sql = "INSERT INTO users (username, password_hash, active) VALUES (?, ?, 1)";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, username.trim());
                ps.setString(2, passwordHash);
                ps.executeUpdate();
            }
        }
    }

    private static void ensureUserKeys(String userId) throws Exception {
        Path keysDir = Paths.get("keys");
        if (!Files.exists(keysDir)) {
            Files.createDirectories(keysDir);
        }

        Path symPath = keysDir.resolve(userId + ".key");
        Path privPath = keysDir.resolve(userId + ".priv");
        Path pubPath = keysDir.resolve(userId + ".pub");

        if (Files.exists(symPath) && Files.exists(privPath) && Files.exists(pubPath)) {
            return;
        }

        SecretKey symKey = KeyManager.generateSymmetricKey();
        KeyManager.saveSymmetricKey(symKey, userId);

        KeyPair kp = KeyManager.generateKeyPair();
        KeyManager.saveKeyPair(kp, userId);
    }

    private static AuthToken loadTokenIfPresent(String userId) {
        try {
            Path tokenPath = Paths.get("keys", userId + ".token");
            if (!Files.exists(tokenPath)) {
                return null;
            }
            String json = new String(Files.readAllBytes(tokenPath), StandardCharsets.UTF_8);
            return GSON.fromJson(json, AuthToken.class);
        } catch (IOException e) {
            return null;
        }
    }

    private static void saveToken(String userId, AuthToken token) throws IOException {
        Path keysDir = Paths.get("keys");
        if (!Files.exists(keysDir)) {
            Files.createDirectories(keysDir);
        }
        Path tokenPath = keysDir.resolve(userId + ".token");
        String json = GSON.toJson(token);
        Files.write(tokenPath, json.getBytes(StandardCharsets.UTF_8));
    }

    private static AuthToken requestTokenFromServer(String userId) throws Exception {
        PublicKey pubKey = KeyManager.loadPublicKey(userId);
        String base64Pub = Base64.getEncoder().encodeToString(pubKey.getEncoded());

        JoinRequest req = new JoinRequest();
        req.setPseudonym(userId);
        req.setClientPublicKey(base64Pub);

        String json = GSON.toJson(req);
        byte[] body = json.getBytes(StandardCharsets.UTF_8);

        URL url = new URL(GATEWAY_URL + "/api/auth/join");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }

        int code = conn.getResponseCode();
        byte[] respBytes;
        if (code == 200) {
            respBytes = readAllBytes(conn.getInputStream());
        } else {
            respBytes = conn.getErrorStream() != null ? readAllBytes(conn.getErrorStream()) : new byte[0];
        }

        String response = new String(respBytes, StandardCharsets.UTF_8);
        if (code != 200) {
            throw new IOException("Server returned " + code + ": " + response);
        }

        return GSON.fromJson(response, AuthToken.class);
    }

    private static byte[] readAllBytes(java.io.InputStream inputStream) throws IOException {
        try (java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream()) {
            byte[] data = new byte[8192];
            int nRead;
            while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return buffer.toByteArray();
        }
    }

    private static Panel createTokenRegisterPanel(WindowBasedTextGUI textGUI, BasicWindow authWindow, Runnable onBack) {
        Panel tokenPanel = new Panel();
        tokenPanel.setLayoutManager(new GridLayout(1));
        tokenPanel.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.FILL,
                GridLayout.Alignment.CENTER,
                true,
                true
        ));

        Label title = new Label(" INVITATION TOKEN ");
        title.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        tokenPanel.addComponent(title);

        Label hint = new Label("Invite-only. Use a token generated by Alice/Bob.");
        hint.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        tokenPanel.addComponent(hint);

        tokenPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Panel userPanel = new Panel(new GridLayout(2));
        userPanel.addComponent(new Label("Username:"));
        final TextBox tokenUsernameBox = new TextBox();
        tokenUsernameBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        userPanel.addComponent(tokenUsernameBox);
        tokenPanel.addComponent(userPanel);

        tokenPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Panel passPanel = new Panel(new GridLayout(2));
        passPanel.addComponent(new Label("Password:"));
        final TextBox passwordBox = new TextBox().setMask('*');
        passwordBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        passPanel.addComponent(passwordBox);
        tokenPanel.addComponent(passPanel);

        tokenPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Panel confirmPanel = new Panel(new GridLayout(2));
        confirmPanel.addComponent(new Label("Confirm:"));
        final TextBox confirmBox = new TextBox().setMask('*');
        confirmBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        confirmPanel.addComponent(confirmBox);
        tokenPanel.addComponent(confirmPanel);

        tokenPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Panel tokenPanelInput = new Panel(new GridLayout(2));
        tokenPanelInput.addComponent(new Label("Token:"));
        final TextBox tokenBox = new TextBox();
        tokenBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        tokenPanelInput.addComponent(tokenBox);
        tokenPanel.addComponent(tokenPanelInput);

        final Label statusLabel = new Label(" ");
        statusLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        tokenPanel.addComponent(statusLabel);

        tokenPanel.addComponent(new EmptySpace(TerminalSize.ONE));

        Panel buttonPanel = new Panel(new GridLayout(3));
        final Button[] registerBtnRef = new Button[1];
        final Button registerBtn = new Button("Register", () -> {
            String username = tokenUsernameBox.getText().trim();
            String tokenId = tokenBox.getText().trim();
            String password = passwordBox.getText();
            String confirm = confirmBox.getText();

            if (username.isEmpty() || tokenId.isEmpty() || password.isEmpty() || confirm.isEmpty()) {
                showDialog(textGUI, "Error", "Username, password, and token are required!");
                return;
            }

            if (!password.equals(confirm)) {
                showDialog(textGUI, "Error", "Passwords do not match!");
                return;
            }

            registerBtnRef[0].setEnabled(false);
            tokenUsernameBox.setEnabled(false);
            tokenBox.setEnabled(false);
            passwordBox.setEnabled(false);
            confirmBox.setEnabled(false);
            statusLabel.setText("Validating token...");

            AtomicBoolean loading = new AtomicBoolean(true);
            Thread spinnerThread = new Thread(() -> {
                String[] frames = new String[]{"|", "/", "-", "\\"};
                int i = 0;
                while (loading.get()) {
                    String msg = "Enrolling " + frames[i % frames.length];
                    invokeLater(textGUI, () -> {
                        if (loading.get()) {
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
            }, "deathnode-token-spinner");
            spinnerThread.setDaemon(true);
            spinnerThread.start();

            new Thread(() -> {
                String error = null;
                boolean ok = false;
                try {
                    TokenValidationResponse response = TokenManager.validateToken(tokenId, true);
                    if (!response.isValid()) {
                        error = "Invalid or expired token!";
                        return;
                    }

                    createLocalUser(username, password);
                    ensureUserKeys(username);

                    AuthToken authToken = requestTokenFromServer(username);
                    saveToken(username, authToken);

                    ok = true;
                } catch (Exception e) {
                    error = "Registration failed: " + e.getMessage();
                } finally {
                    loading.set(false);
                    spinnerThread.interrupt();
                }

                String finalError = error;
                boolean finalOk = ok;
                invokeLater(textGUI, () -> {
                    registerBtnRef[0].setEnabled(true);
                    tokenUsernameBox.setEnabled(true);
                    tokenBox.setEnabled(true);
                    passwordBox.setEnabled(true);
                    confirmBox.setEnabled(true);

                    statusLabel.setText(" ");

                    if (!finalOk) {
                        showDialog(textGUI, "Error", finalError == null ? "Registration failed" : finalError);
                        return;
                    }

                    showDialog(textGUI, "Success", "Enrollment complete. Return to LOGIN.");
                    tokenUsernameBox.setText("");
                    tokenBox.setText("");
                    passwordBox.setText("");
                    confirmBox.setText("");
                    onBack.run();
                });
            }, "deathnode-token-enroll").start();
        });
        registerBtnRef[0] = registerBtn;
        registerBtn.setRenderer(new SolidFocusButtonRenderer());

        final Button cancelBtn = new Button("Cancel", () -> {
            tokenUsernameBox.setText("");
            tokenBox.setText("");
            passwordBox.setText("");
            confirmBox.setText("");
            statusLabel.setText(" ");
        });
        cancelBtn.setRenderer(new SolidFocusButtonRenderer());

        final Button backBtn = new Button("Back", onBack);
        backBtn.setRenderer(new SolidFocusButtonRenderer());

        buttonPanel.addComponent(registerBtn);
        buttonPanel.addComponent(cancelBtn);
        buttonPanel.addComponent(backBtn);
        tokenPanel.addComponent(buttonPanel);

        return tokenPanel;
    }

    private static void showDialog(WindowBasedTextGUI textGUI, String title, String message) {
        BasicWindow dialog = new BasicWindow(title);
        dialog.setHints(Collections.singletonList(Window.Hint.CENTERED));

        Panel panel = new Panel(new LinearLayout(Direction.VERTICAL));
        panel.addComponent(new Label(message));

        Panel buttonPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        Button okBtn = new Button("OK", dialog::close);
        okBtn.setRenderer(new SolidFocusButtonRenderer());
        buttonPanel.addComponent(okBtn);
        panel.addComponent(buttonPanel);

        final Label ambientLabel = new Label(" ");
        ambientLabel.setLayoutData(LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        ambientLabel.setText(buildAmbientFrame(0));
        panel.addComponent(ambientLabel);

        dialog.setComponent(panel);

        AtomicBoolean ambientRunning = new AtomicBoolean(true);
        Thread ambientThread = new Thread(() -> {
            int tick = 0;
            while (ambientRunning.get()) {
                String frame = buildAmbientFrame(tick++);
                invokeLater(textGUI, () -> {
                    if (ambientRunning.get()) {
                        ambientLabel.setText(frame);
                    }
                });
                try {
                    Thread.sleep(150);
                } catch (InterruptedException ignored) {
                    return;
                }
            }
        }, "deathnode-ambient-dialog");
        ambientThread.setDaemon(true);
        ambientThread.start();

        textGUI.addWindowAndWait(dialog);
        ambientRunning.set(false);
        ambientThread.interrupt();
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

    private static void invokeLater(WindowBasedTextGUI textGUI, Runnable runnable) {
        if (textGUI == null) {
            runnable.run();
            return;
        }
        textGUI.getGUIThread().invokeLater(runnable);
    }

    private static final class MatrixRainComponent extends AbstractComponent<MatrixRainComponent> {
        private static final TextColor BG = TextColor.Factory.fromString("#050607");
        private static final TextColor HEAD = TextColor.Factory.fromString("#d7ffd7");
        private static final TextColor TRAIL_1 = TextColor.Factory.fromString("#39ff14");
        private static final TextColor TRAIL_2 = TextColor.Factory.fromString("#1f7a1a");
        private static final TextColor TRAIL_3 = TextColor.Factory.fromString("#0f3510");

        private final Random rnd = new Random();
        private TerminalSize lastSize;
        private int[] headY;
        private int[] speed;
        private int[] trail;
        private int tick;

        void tick() {
            if (lastSize == null) {
                invalidate();
                return;
            }
            ensureColumns(lastSize.getColumns(), lastSize.getRows());
            tick++;

            boolean advance = (tick % 2) == 0;
            int rows = lastSize.getRows();
            if (advance) {
                for (int x = 0; x < headY.length; x++) {
                    headY[x] += speed[x];
                    if (headY[x] > rows + trail[x] + 2) {
                        resetColumn(x, rows);
                    }
                }
            }
            invalidate();
        }

        private void ensureColumns(int cols, int rows) {
            if (cols <= 0 || rows <= 0) {
                return;
            }
            if (headY != null && headY.length == cols) {
                return;
            }
            headY = new int[cols];
            speed = new int[cols];
            trail = new int[cols];
            for (int i = 0; i < cols; i++) {
                resetColumn(i, rows);
            }
        }

        private void resetColumn(int x, int rows) {
            headY[x] = -rnd.nextInt(Math.max(1, rows));
            speed[x] = 1;
            trail[x] = 10 + rnd.nextInt(26);
        }

        private char randChar() {
            String charset = "0123456789abcdef" +
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                    "!@#$%^&*()_+-=[]{};:,.<>?/\\|";
            return charset.charAt(rnd.nextInt(charset.length()));
        }

        @Override
        protected ComponentRenderer<MatrixRainComponent> createDefaultRenderer() {
            return new ComponentRenderer<MatrixRainComponent>() {
                @Override
                public TerminalSize getPreferredSize(MatrixRainComponent component) {
                    return TerminalSize.ZERO;
                }

                @Override
                public void drawComponent(TextGUIGraphics g, MatrixRainComponent c) {
                    TerminalSize size = g.getSize();
                    c.lastSize = size;
                    c.ensureColumns(size.getColumns(), size.getRows());

                    g.setBackgroundColor(BG);
                    g.setForegroundColor(TRAIL_1);
                    g.fill(' ');

                    int cols = size.getColumns();
                    int rows = size.getRows();
                    if (c.headY == null) {
                        return;
                    }

                    for (int x = 0; x < cols; x++) {
                        int yHead = c.headY[x];
                        for (int t = 0; t <= c.trail[x]; t++) {
                            int y = yHead - t;
                            if (y < 0 || y >= rows) {
                                continue;
                            }
                            if (t == 0) {
                                g.setForegroundColor(HEAD);
                            } else if (t < 4) {
                                g.setForegroundColor(TRAIL_1);
                            } else if (t < 10) {
                                g.setForegroundColor(TRAIL_2);
                            } else {
                                g.setForegroundColor(TRAIL_3);
                            }
                            g.putString(x, y, String.valueOf(c.randChar()));
                        }
                    }

                    if ((c.tick % 55) < 10) {
                        int y = c.rnd.nextInt(Math.max(1, rows));
                        g.setForegroundColor(TRAIL_3);
                        for (int x = 0; x < cols; x++) {
                            if (c.rnd.nextInt(3) == 0) {
                                g.putString(x, y, String.valueOf(c.randChar()));
                            }
                        }
                    }

                    if ((c.tick % 160) < 26) {
                        String[] banner = new String[]{
                                "██████╗ ███████╗ █████╗ ████████╗██╗  ██╗",
                                "██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║",
                                "██║  ██║█████╗  ███████║   ██║   ███████║",
                                "██║  ██║██╔══╝  ██╔══██║   ██║   ██╔══██║",
                                "██████╔╝███████╗██║  ██║   ██║   ██║  ██║",
                                "╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝"
                        };
                        int startY = Math.max(0, rows / 2 - banner.length / 2);
                        for (int i = 0; i < banner.length; i++) {
                            String line = banner[i];
                            StringBuilder gl = new StringBuilder(line);
                            int glitches = 1 + c.rnd.nextInt(5);
                            for (int j = 0; j < glitches; j++) {
                                int idx = c.rnd.nextInt(gl.length());
                                char ch = gl.charAt(idx);
                                if (ch != ' ') {
                                    gl.setCharAt(idx, c.randChar());
                                }
                            }
                            int startX = Math.max(0, (cols - gl.length()) / 2);
                            if (startX + gl.length() <= cols) {
                                g.setForegroundColor(i == 0 ? HEAD : TRAIL_1);
                                g.putString(startX, startY + i, gl.toString());
                            }
                        }
                    }
                }
            };
        }
    }
}
