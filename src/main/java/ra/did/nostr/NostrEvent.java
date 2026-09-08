package ra.did.nostr;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A Nostr event (DID {@code DESIGN.md} §2): the signed record format shared with
 * every other implementation. BIP-340 Schnorr signature over the SHA-256 of a
 * whitespace-free canonical JSON array.
 *
 * <p>Canonical serialisation (§2.1) is hand-rolled here rather than delegated to
 * a JSON library: only the seven escapes {@code " \ \n \r \t \b \f} are emitted,
 * everything else (including all multi-byte UTF-8) is literal. Getting this exact
 * is what makes signatures reproduce across the language ports.
 */
public final class NostrEvent {

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern HEX128 = Pattern.compile("^[0-9a-f]{128}$");

    private String id;
    private String pubkey;
    private long createdAt;
    private int kind;
    private List<List<String>> tags = new ArrayList<>();
    private String content = "";
    private String sig;

    public NostrEvent() {}

    // --- factories ------------------------------------------------

    /** An unsigned event ready to hand to {@link NostrKeyRing#signEvent} or {@link #sign}. */
    public static NostrEvent unsigned(int kind, List<List<String>> tags, String content, long createdAt) {
        NostrEvent e = new NostrEvent();
        e.kind = kind;
        e.tags = tags == null ? new ArrayList<>() : deepCopyTags(tags);
        e.content = content == null ? "" : content;
        e.createdAt = createdAt;
        return e;
    }

    @SuppressWarnings("unchecked")
    public static NostrEvent fromMap(Map<String, Object> m) {
        NostrEvent e = new NostrEvent();
        e.id = (String) m.get("id");
        e.pubkey = (String) m.get("pubkey");
        e.createdAt = ((Number) m.get("created_at")).longValue();
        e.kind = ((Number) m.get("kind")).intValue();
        e.content = m.get("content") == null ? "" : (String) m.get("content");
        e.sig = (String) m.get("sig");
        e.tags = new ArrayList<>();
        Object rawTags = m.get("tags");
        if (rawTags instanceof List) {
            for (Object t : (List<Object>) rawTags) {
                List<String> tag = new ArrayList<>();
                for (Object v : (List<Object>) t) tag.add(String.valueOf(v));
                e.tags.add(tag);
            }
        }
        return e;
    }

    // --- canonical form (§2.1) ----------------------------------

    /** The exact string that is hashed to produce {@code id}. */
    public String canonicalPreimage() {
        return canonicalize(pubkey, createdAt, kind, tags, content);
    }

    static String canonicalize(String pubkey, long createdAt, int kind, List<List<String>> tags, String content) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("[0,");
        escapeString(sb, pubkey);
        sb.append(',').append(createdAt).append(',').append(kind).append(',');
        sb.append('[');
        for (int i = 0; i < tags.size(); i++) {
            if (i > 0) sb.append(',');
            List<String> tag = tags.get(i);
            sb.append('[');
            for (int j = 0; j < tag.size(); j++) {
                if (j > 0) sb.append(',');
                escapeString(sb, tag.get(j));
            }
            sb.append(']');
        }
        sb.append(']').append(',');
        escapeString(sb, content);
        sb.append(']');
        return sb.toString();
    }

    private static void appendTagsJson(StringBuilder sb, List<List<String>> tags) {
        sb.append('[');
        for (int i = 0; i < tags.size(); i++) {
            if (i > 0) sb.append(',');
            List<String> tag = tags.get(i);
            sb.append('[');
            for (int j = 0; j < tag.size(); j++) {
                if (j > 0) sb.append(',');
                escapeString(sb, tag.get(j));
            }
            sb.append(']');
        }
        sb.append(']');
    }

    /** The full signed event as compact JSON (Nostr wire form). Not the canonical preimage. */
    public String toJson() {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{\"id\":");
        escapeString(sb, id == null ? "" : id);
        sb.append(",\"pubkey\":");
        escapeString(sb, pubkey == null ? "" : pubkey);
        sb.append(",\"created_at\":").append(createdAt);
        sb.append(",\"kind\":").append(kind);
        sb.append(",\"tags\":");
        appendTagsJson(sb, tags);
        sb.append(",\"content\":");
        escapeString(sb, content);
        sb.append(",\"sig\":");
        escapeString(sb, sig == null ? "" : sig);
        sb.append('}');
        return sb.toString();
    }

    /** id / pubkey / created_at / kind / tags / content / sig as a plain map. */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("id", id);
        m.put("pubkey", pubkey);
        m.put("created_at", createdAt);
        m.put("kind", kind);
        List<List<String>> tagsCopy = new ArrayList<>();
        for (List<String> t : tags) tagsCopy.add(new ArrayList<>(t));
        m.put("tags", tagsCopy);
        m.put("content", content);
        m.put("sig", sig);
        return m;
    }

    static void escapeString(StringBuilder sb, String s) {
        sb.append('"');
        int n = s.length();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:   sb.append(c);
            }
        }
        sb.append('"');
    }

    /** SHA-256 (lowercase hex) of the canonical preimage. */
    public String computeId() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonicalPreimage().getBytes(StandardCharsets.UTF_8));
            return NostrKeys.toHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // --- signing / verification (§2.2) --------------------------

    /**
     * Sign this event in place with a 32-byte secret hex. {@code pubkey}, {@code id}
     * and {@code sig} are (re)computed. {@code auxRand32} may be {@code null}; 32
     * zero bytes make the signature reproducible.
     */
    public NostrEvent sign(String secretHex, byte[] auxRand32) {
        byte[] sk = NostrKeys.fromHex(secretHex);
        this.pubkey = NostrKeys.toHex(Bip340.xOnlyPublicKey(sk));
        this.id = computeId();
        this.sig = NostrKeys.toHex(Bip340.sign(NostrKeys.fromHex(id), sk, auxRand32));
        return this;
    }

    public static final class VerifyResult {
        public final boolean ok;
        /** 1–4, or 0 on success. */
        public final int step;
        public final String reason;
        VerifyResult(boolean ok, int step, String reason) { this.ok = ok; this.step = step; this.reason = reason; }
        static VerifyResult ok() { return new VerifyResult(true, 0, null); }
        static VerifyResult fail(int step, String reason) { return new VerifyResult(false, step, reason); }
    }

    /**
     * Verify against DESIGN §2.2. Steps run in order; the first failure is returned.
     * <ol>
     *   <li>{@code pubkey} is 64 lowercase hex over a valid x-only point</li>
     *   <li>the recomputed {@code id} equals the stated {@code id} (itself 64 lowercase hex)</li>
     *   <li>the Schnorr signature verifies over the 32 raw {@code id} bytes</li>
     *   <li>kind-specific validation (§3, §4)</li>
     * </ol>
     */
    public VerifyResult verify() {
        if (pubkey == null || !HEX64.matcher(pubkey).matches()) {
            return VerifyResult.fail(1, "pubkey is not 64 lowercase hex chars");
        }
        if (!Bip340.isValidXOnlyPublicKey(NostrKeys.fromHex(pubkey))) {
            return VerifyResult.fail(1, "pubkey is not a valid x-only point");
        }
        if (id == null || !HEX64.matcher(id).matches()) {
            return VerifyResult.fail(2, "id is not 64 lowercase hex chars");
        }
        String recomputed = computeId();
        if (!recomputed.equals(id)) {
            return VerifyResult.fail(2, "id mismatch: computed " + recomputed);
        }
        if (sig == null || !HEX128.matcher(sig).matches()) {
            return VerifyResult.fail(3, "sig is not 128 lowercase hex chars");
        }
        if (!Bip340.verify(NostrKeys.fromHex(sig), NostrKeys.fromHex(id), NostrKeys.fromHex(pubkey))) {
            return VerifyResult.fail(3, "Schnorr signature does not verify");
        }
        NostrKinds.Check kc = NostrKinds.validate(this);
        if (!kc.ok) {
            return VerifyResult.fail(4, kc.reason);
        }
        return VerifyResult.ok();
    }

    public boolean isValid() {
        return verify().ok;
    }

    // --- tag helpers --------------------------------------------

    public String firstTag(String name) {
        for (List<String> t : tags) {
            if (!t.isEmpty() && t.get(0).equals(name)) {
                return t.size() > 1 ? t.get(1) : null;
            }
        }
        return null;
    }

    public boolean hasTag(String name) {
        for (List<String> t : tags) if (!t.isEmpty() && t.get(0).equals(name)) return true;
        return false;
    }

    public List<String> tagValues(String name) {
        List<String> out = new ArrayList<>();
        for (List<String> t : tags) {
            if (t.size() > 1 && t.get(0).equals(name)) out.add(t.get(1));
        }
        return out;
    }

    public List<List<String>> tags(String name) {
        List<List<String>> out = new ArrayList<>();
        for (List<String> t : tags) {
            if (!t.isEmpty() && t.get(0).equals(name)) out.add(t);
        }
        return out;
    }

    public void addTag(String... parts) {
        List<String> tag = new ArrayList<>();
        Collections.addAll(tag, parts);
        tags.add(tag);
    }

    // --- accessors ---------------------------------------------

    public String getId() { return id; }
    public String getPubkey() { return pubkey; }
    public long getCreatedAt() { return createdAt; }
    public int getKind() { return kind; }
    public String getContent() { return content; }
    public String getSig() { return sig; }
    public List<List<String>> getTags() { return tags; }

    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
    public void setContent(String content) { this.content = content == null ? "" : content; }
    public void setKind(int kind) { this.kind = kind; }

    private static List<List<String>> deepCopyTags(List<List<String>> tags) {
        List<List<String>> out = new ArrayList<>(tags.size());
        for (List<String> t : tags) out.add(new ArrayList<>(t));
        return out;
    }
}
