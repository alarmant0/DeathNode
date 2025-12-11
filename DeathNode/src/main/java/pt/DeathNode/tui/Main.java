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

        // Terminal and Screen setup
        DefaultTerminalFactory terminalFactory = new DefaultTerminalFactory();
        Terminal terminal = terminalFactory.createTerminal();
        Screen screen = new TerminalScreen(terminal);
        screen.startScreen();

        WindowBasedTextGUI textGUI = new MultiWindowTextGUI(screen);
        BasicWindow loginWindow = new BasicWindow("Login");

        // --- Layout ---
        Panel mainPanel = new Panel(new GridLayout(1));

        // Title
        Label title = new Label("🔐 Entrar");
        title.setLayoutData(GridLayout.createHorizontallyFilledLayoutData());
        mainPanel.addComponent(title);

        // Username input
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));
        Panel userPanel = new Panel(new GridLayout(2));
        userPanel.addComponent(new Label("Username"));
        final TextBox usernameBox = new TextBox();
        usernameBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData());
        userPanel.addComponent(usernameBox);
        mainPanel.addComponent(userPanel);

        // Password input
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));
        Panel passPanel = new Panel(new GridLayout(2));
        passPanel.addComponent(new Label("Password"));
        final TextBox passwordBox = new TextBox().setMask('*');
        passwordBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData());
        passPanel.addComponent(passwordBox);
        mainPanel.addComponent(passPanel);

        // Message label
        mainPanel.addComponent(new EmptySpace(new TerminalSize(0, 1)));
        final Label msgLabel = new Label(" ");
        msgLabel.setLayoutData(GridLayout.createHorizontallyFilledLayoutData());
        mainPanel.addComponent(msgLabel);

        // Buttons
        Panel buttonPanel = new Panel(new GridLayout(2));
        Button registerBtn = new Button("Registar", () ->
                attemptRegister(usernameBox.getText(), passwordBox.getText(), msgLabel, textGUI, loginWindow)
        );
        Button loginBtn = new Button("Login", () ->
                attemptLogin(usernameBox.getText(), passwordBox.getText(), msgLabel, textGUI, loginWindow)
        );
        buttonPanel.addComponent(registerBtn);
        buttonPanel.addComponent(loginBtn);

        mainPanel.addComponent(buttonPanel);

        loginWindow.setComponent(mainPanel);
        loginWindow.setHints(Collections.singletonList(Window.Hint.CENTERED));

        textGUI.addWindowAndWait(loginWindow);
        screen.stopScreen();
    }

    private static void attemptRegister(String username, String password,
                                        Label msgLabel, WindowBasedTextGUI textGUI, BasicWindow loginWindow) {

        username = username == null ? "" : username.trim();
        password = password == null ? "" : password.trim();

        if (username.isEmpty() || password.isEmpty()) {
            msgLabel.setText("Preenche os dois campos");
            return;
        }

        try {
            // Use the entered username as the pseudonym for DeathNode.
            // Perform Security Challenge A registration against the auth server.
            ensureUserKeys(username);
            msgLabel.setText("A registar utilizador no servidor...");
            AuthToken token = requestTokenFromServer(username, AUTH_SERVER_HOST, AUTH_SERVER_PORT);
            saveToken(username, token);

            // Close login
            loginWindow.close();

            // Open chat window
            ChatWindow chat = new ChatWindow();
            textGUI.addWindow(chat);

            // Focus input field so typing works immediately
            chat.focusInput(textGUI);

            textGUI.waitForWindowToClose(chat);

        } catch (Exception e) {
            msgLabel.setText("Falha ao registar: " + e.getMessage());
        }
    }

    private static void attemptLogin(String username, String password,
                                     Label msgLabel, WindowBasedTextGUI textGUI, BasicWindow loginWindow) {

        username = username == null ? "" : username.trim();
        password = password == null ? "" : password.trim();

        if (username.isEmpty() || password.isEmpty()) {
            msgLabel.setText("Preenche os dois campos");
            return;
        }

        AuthToken token = loadTokenIfPresent(username);
        if (token == null) {
            msgLabel.setText("Utilizador não registado. Usa 'Registar' primeiro.");
            return;
        }
        if (token.isExpired()) {
            msgLabel.setText("Token expirado. Faz 'Registar' novamente.");
            return;
        }

        // Token válido: considera o utilizador autenticado
        loginWindow.close();

        ChatWindow chat = new ChatWindow();
        textGUI.addWindow(chat);

        chat.focusInput(textGUI);
        textGUI.waitForWindowToClose(chat);
    }

    private static void ensureUserKeys(String userId) throws Exception {
        Path symPath = Paths.get("keys", userId + ".key");
        Path privPath = Paths.get("keys", userId + ".priv");
        Path pubPath = Paths.get("keys", userId + ".pub");

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
            String json = Files.readString(tokenPath);
            return GSON.fromJson(json, AuthToken.class);
        } catch (IOException e) {
            return null;
        }
    }

    private static void saveToken(String userId, AuthToken token) throws IOException {
        Path tokenPath = Paths.get("keys", userId + ".token");
        String json = GSON.toJson(token);
        Files.writeString(tokenPath, json);
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
            respBytes = conn.getInputStream().readAllBytes();
        } else {
            respBytes = conn.getErrorStream() != null ? conn.getErrorStream().readAllBytes() : new byte[0];
            String msg = new String(respBytes, StandardCharsets.UTF_8);
            throw new IOException("Servidor retornou estado " + code + ": " + msg);
        }

        String respJson = new String(respBytes, StandardCharsets.UTF_8);
        return GSON.fromJson(respJson, AuthToken.class);
    }
}
