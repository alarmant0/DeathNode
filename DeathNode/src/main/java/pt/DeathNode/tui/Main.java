package pt.DeathNode.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.screen.Screen;
import com.googlecode.lanterna.screen.TerminalScreen;
import com.googlecode.lanterna.terminal.DefaultTerminalFactory;
import com.googlecode.lanterna.terminal.Terminal;

import java.io.IOException;
import java.util.Collections;

public class Main {

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
        Button loginBtn = new Button("Login", () ->
                attemptLogin(usernameBox.getText(), passwordBox.getText(), msgLabel, textGUI, loginWindow)
        );
        Button quitBtn = new Button("Sair", loginWindow::close);
        buttonPanel.addComponent(loginBtn);
        buttonPanel.addComponent(quitBtn);

        mainPanel.addComponent(buttonPanel);

        loginWindow.setComponent(mainPanel);
        loginWindow.setHints(Collections.singletonList(Window.Hint.CENTERED));

        textGUI.addWindowAndWait(loginWindow);
        screen.stopScreen();
    }

    private static void attemptLogin(String username, String password,
                                     Label msgLabel, WindowBasedTextGUI textGUI, BasicWindow loginWindow) {

        username = username == null ? "" : username.trim();
        password = password == null ? "" : password.trim();

        if (username.isEmpty() || password.isEmpty()) {
            msgLabel.setText("Preenche os dois campos");
            return;
        }

        if (username.equals(VALID_USER) && password.equals(VALID_PASS)) {

            // Close login
            loginWindow.close();

            // Open chat window
            ChatWindow chat = new ChatWindow();
            textGUI.addWindow(chat);

            // Focus input field so typing works immediately
            chat.focusInput(textGUI);

            textGUI.waitForWindowToClose(chat);

        } else {
            msgLabel.setText("Credenciais inválidas — tenta outra vez");
        }
    }
}
