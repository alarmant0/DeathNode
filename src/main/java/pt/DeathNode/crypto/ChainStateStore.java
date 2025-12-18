package pt.DeathNode.crypto;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ChainStateStore {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Path DIR = Paths.get("db", "chain");

    private ChainStateStore() {
    }

    public static final class ChainState {
        private long lastSequence;
        private String lastHash;

        public long getLastSequence() {
            return lastSequence;
        }

        public void setLastSequence(long lastSequence) {
            this.lastSequence = lastSequence;
        }

        public String getLastHash() {
            return lastHash;
        }

        public void setLastHash(String lastHash) {
            this.lastHash = lastHash;
        }
    }

    public static final class ChainParams {
        private final long sequenceNumber;
        private final String previousHash;

        private ChainParams(long sequenceNumber, String previousHash) {
            this.sequenceNumber = sequenceNumber;
            this.previousHash = previousHash;
        }

        public long getSequenceNumber() {
            return sequenceNumber;
        }

        public String getPreviousHash() {
            return previousHash;
        }
    }

    public static synchronized ChainParams nextParams(String signerId) throws Exception {
        ChainState state = loadState(signerId);
        long nextSeq = state.getLastSequence() + 1;
        String prevHash = state.getLastHash();
        return new ChainParams(nextSeq, prevHash);
    }

    public static synchronized void updateFromDocument(String signerId, SecureDocument doc) throws Exception {
        if (doc.getSequenceNumber() == null) {
            return;
        }
        ChainState state = loadState(signerId);
        state.setLastSequence(doc.getSequenceNumber());
        state.setLastHash(CryptoLib.computeChainHash(doc));
        saveState(signerId, state);
    }

    private static ChainState loadState(String signerId) throws Exception {
        ensureDir();
        Path p = statePath(signerId);
        if (!Files.exists(p)) {
            ChainState s = new ChainState();
            s.setLastSequence(0L);
            s.setLastHash(null);
            return s;
        }
        String json = Files.readString(p, StandardCharsets.UTF_8);
        ChainState s = GSON.fromJson(json, ChainState.class);
        if (s == null) {
            s = new ChainState();
            s.setLastSequence(0L);
            s.setLastHash(null);
        }
        return s;
    }

    private static void saveState(String signerId, ChainState state) throws Exception {
        ensureDir();
        Path p = statePath(signerId);
        Files.writeString(p, GSON.toJson(state), StandardCharsets.UTF_8);
    }

    private static Path statePath(String signerId) {
        String safe = signerId == null ? "unknown" : signerId.replaceAll("[^a-zA-Z0-9._-]", "_");
        return DIR.resolve(safe + ".json");
    }

    private static void ensureDir() throws Exception {
        if (!Files.exists(DIR)) {
            Files.createDirectories(DIR);
        }
    }
}
