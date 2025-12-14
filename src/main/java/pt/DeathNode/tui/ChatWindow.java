package pt.DeathNode.tui;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.gui2.*;
import com.googlecode.lanterna.input.KeyStroke;
import com.googlecode.lanterna.input.KeyType;

import java.util.Collections;

public class ChatWindow extends BasicWindow {

    private final TextBox chatArea;
    private final MessageBox inputBox;

    public ChatWindow() {
        super("Chat");

        Panel main = new Panel(new GridLayout(1));

        chatArea = new TextBox(new TerminalSize(60, 20));
        chatArea.setReadOnly(true);
        chatArea.setVerticalFocusSwitching(false);
        main.addComponent(chatArea);

        inputBox = new MessageBox();
        inputBox.setLayoutData(GridLayout.createHorizontallyFilledLayoutData());
        main.addComponent(inputBox);

        Panel btnPanel = new Panel(new GridLayout(2));
        btnPanel.addComponent(new Button("Send", this::sendMessage));
        btnPanel.addComponent(new Button("Close", this::close));
        main.addComponent(btnPanel);

        setComponent(main);
        setHints(Collections.singletonList(Hint.CENTERED));
    }

    public void focusInput(TextGUI gui) {
        gui.getGUIThread().invokeLater(() -> inputBox.takeFocus());
    }

    private class MessageBox extends TextBox {
        @Override
        public synchronized Result handleKeyStroke(KeyStroke key) {
            if (key.getKeyType() == KeyType.Enter) {
                sendMessage();
                return Result.HANDLED;
            }
            return super.handleKeyStroke(key);
        }
    }

    private void sendMessage() {
        String text = inputBox.getText().trim();
        if (!text.isEmpty()) {
            chatArea.addLine("You: " + text);
            inputBox.setText("");
        }
    }
}
