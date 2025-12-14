package pt.DeathNode.tui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;
import pt.DeathNode.auth.AuthToken;
import pt.DeathNode.auth.JoinRequest;
import pt.DeathNode.crypto.KeyManager;
import pt.DeathNode.tui.ReportWindow;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;

public class Main {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final String AUTH_SERVER_HOST = "localhost";
    private static final int AUTH_SERVER_PORT = 8080;
    private static final String VALID_USER = "admin";
    private static final String VALID_PASS = "1234";

    public static void main(String[] args) throws IOException {
        DefaultTerminalFactory terminalFactory = new DefaultTerminalFactory();
        Terminal terminal = terminalFactory.createTerminal();
        Screen screen = new TerminalScreen(terminal);
        screen.startScreen();

        WindowBasedTextGUI textGUI = new MultiWindowTextGUI(screen);
        BasicWindow authWindow = new BasicWindow("Authentication");

        Panel mainContentPanel = new Panel(new LinearLayout(Direction.VERTICAL));

        Panel loginPanel = createLoginPanel(textGUI, authWindow);
        mainContentPanel.addComponent(loginPanel);

        Panel registerPanel = createRegisterPanel(textGUI, authWindow);
        registerPanel.setVisible(false);
        mainContentPanel.addComponent(registerPanel);

        Panel switchPanel = new Panel(new GridLayout(2));
        Button switchToRegister = new Button("Create Account", () -> {
            loginPanel.setVisible(false);
            registerPanel.setVisible(true);
        });
        Button switchToLogin = new Button("Back to Login", () -> {
            loginPanel.setVisible(true);
            registerPanel.setVisible(false);
        });
        switchPanel.addComponent(switchToRegister);
        switchPanel.addComponent(switchToLogin);
        mainContentPanel.addComponent(switchPanel);

        Panel bottomPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        bottomPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Button quitBtn = new Button("Quit", authWindow::close);
        bottomPanel.addComponent(quitBtn);

        Panel mainPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        mainPanel.addComponent(mainContentPanel);
        mainPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        mainPanel.addComponent(bottomPanel);

        authWindow.setComponent(mainPanel);
        authWindow.setHints(Collections.singletonList(Window.Hint.CENTERED));

        textGUI.addWindowAndWait(authWindow);
        screen.stopScreen();
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

        Label title = new Label(" Login");
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
        Button loginBtn = new Button("Login", () -> {
            String username = loginUsernameBox.getText();
            String password = loginPasswordBox.getText();
            attemptLogin(username, password, loginMsgLabel, textGUI, authWindow);
        });
        loginBtn.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        loginPanel.addComponent(loginBtn);

        return loginPanel;
    }

    private static Panel createRegisterPanel(WindowBasedTextGUI textGUI, BasicWindow authWindow) {
        Panel registerPanel = new Panel();
        registerPanel.setLayoutManager(new GridLayout(1));
        registerPanel.setLayoutData(GridLayout.createLayoutData(
                GridLayout.Alignment.FILL,
                GridLayout.Alignment.CENTER,
                true,
                true
        ));

        Label title = new Label(" Register");
        title.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        registerPanel.addComponent(title);

        registerPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel userPanel = new Panel(new GridLayout(2));
        userPanel.addComponent(new Label("Username:"));
        final TextBox regUsernameBox = new TextBox();
        regUsernameBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        userPanel.addComponent(regUsernameBox);
        registerPanel.addComponent(userPanel);

        registerPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel emailPanel = new Panel(new GridLayout(2));
        emailPanel.addComponent(new Label("Email:"));
        final TextBox emailBox = new TextBox();
        emailBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        emailPanel.addComponent(emailBox);
        registerPanel.addComponent(emailPanel);

        registerPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel passPanel = new Panel(new GridLayout(2));
        passPanel.addComponent(new Label("Password:"));
        final TextBox regPasswordBox = new TextBox().setMask('*');
        regPasswordBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        passPanel.addComponent(regPasswordBox);
        registerPanel.addComponent(passPanel);

        registerPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Panel confirmPassPanel = new Panel(new GridLayout(2));
        confirmPassPanel.addComponent(new Label("Confirm:"));
        final TextBox confirmPassBox = new TextBox().setMask('*');
        confirmPassBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        confirmPassPanel.addComponent(confirmPassBox);
        registerPanel.addComponent(confirmPassPanel);

        final Label registerMsgLabel = new Label(" ");
        registerMsgLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        registerPanel.addComponent(registerMsgLabel);

        registerPanel.addComponent(new EmptySpace(TerminalSize.ONE));
        Button registerBtn = new Button("Register", () -> {
            String username = regUsernameBox.getText();
            String email = emailBox.getText();
            String password = regPasswordBox.getText();
            String confirmPassword = confirmPassBox.getText();

            if (username.isEmpty() || email.isEmpty() || password.isEmpty() || confirmPassword.isEmpty()) {
                registerMsgLabel.setText("All fields are required!");
                return;
            }

            if (!password.equals(confirmPassword)) {
                registerMsgLabel.setText("Passwords do not match!");
                return;
            }

            registerMsgLabel.setText("Registration successful!");

            regUsernameBox.setText("");
            emailBox.setText("");
            regPasswordBox.setText("");
            confirmPassBox.setText("");
        });
        registerBtn.setLayoutData(GridLayout.createHorizontallyFilledLayoutData(1));
        registerPanel.addComponent(registerBtn);

        return registerPanel;
    }

    private static void attemptLogin(String username, String password,
                                     Label msgLabel, WindowBasedTextGUI textGUI, BasicWindow loginWindow) {
        username = username == null ? "" : username.trim();
        password = password == null ? "" : password.trim();

        if (username.isEmpty() || password.isEmpty()) {
            msgLabel.setText("Please enter both username and password");
            return;
        }

        if (password.length() < 4) {
            msgLabel.setText("Password must be at least 4 characters");
            return;
        }

        try {
            ensureUserKeys(username);
            AuthToken token = loadTokenIfPresent(username);

            if (token == null || token.isExpired()) {
                msgLabel.setText("Registering user on server...");
                token = requestTokenFromServer(username, AUTH_SERVER_HOST, AUTH_SERVER_PORT);
                saveToken(username, token);
            }

            loginWindow.close();

            ReportWindow reportWindow = new ReportWindow(username, textGUI);
            textGUI.addWindow(reportWindow);
            textGUI.waitForWindowToClose(reportWindow);

        } catch (Exception e) {
            msgLabel.setText("Login failed: " + e.getMessage());
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

    private static AuthToken requestTokenFromServer(String userId, String host, int port) throws Exception {
        PublicKey pubKey = KeyManager.loadPublicKey(userId);
        String base64Pub = Base64.getEncoder().encodeToString(pubKey.getEncoded());

        JoinRequest req = new JoinRequest();
        req.setPseudonym(userId);
        req.setClientPublicKey(base64Pub);

        String json = GSON.toJson(req);
        byte[] body = json.getBytes(StandardCharsets.UTF_8);

        URL url = new URL("http://" + host + ":" + port + "/join");
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
}
