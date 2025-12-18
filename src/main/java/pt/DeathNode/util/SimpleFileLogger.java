package pt.DeathNode.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

public final class SimpleFileLogger {

    private final Path file;

    public SimpleFileLogger(String relativePath) {
        this.file = Paths.get(relativePath);
    }

    public void info(String msg) {
        write("INFO", msg, null);
    }

    public void warn(String msg) {
        write("WARN", msg, null);
    }

    public void error(String msg, Throwable t) {
        write("ERROR", msg, t);
    }

    private synchronized void write(String level, String msg, Throwable t) {
        try {
            Path parent = file.getParent();
            if (parent != null && !Files.exists(parent)) {
                Files.createDirectories(parent);
            }
            StringBuilder sb = new StringBuilder();
            sb.append(Instant.now()).append(" [").append(level).append("] ").append(msg == null ? "" : msg);
            if (t != null) {
                sb.append(" | ").append(t.getClass().getName()).append(": ").append(t.getMessage());
            }
            sb.append(System.lineSeparator());
            Files.write(file, sb.toString().getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }
    }
}
