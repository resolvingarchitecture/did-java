package ra.did.nostr;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Encodings of a Nostr identity key (DID {@code DESIGN.md} §1.1):
 *
 * <ul>
 *   <li>lowercase hex (64 chars) — canonical; the only form used in signature preimages</li>
 *   <li>{@code npub1…} / {@code nsec1…} — Bech32 (NIP-19), for display and export only</li>
 *   <li>{@code did:nostr:<hex>} — the W3C view (§5); note this is hex, not npub</li>
 * </ul>
 *
 * Implementations MUST accept hex and {@code npub} on input and normalise to hex.
 * {@code nsec} MUST NOT be surfaced incidentally — {@link #secretToNsec} exists
 * for a deliberate export flow and is never called by the library itself.
 */
public final class NostrKeys {

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern DID_NOSTR = Pattern.compile("^did:nostr:([0-9a-f]{64})$");
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private NostrKeys() {}

    // --- hex ---------------------------------------------------------

    public static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0f];
        }
        return new String(out);
    }

    public static byte[] fromHex(String hex) {
        if (hex == null || (hex.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must have an even length");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("invalid hex character");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static boolean isHex64(String s) {
        return s != null && HEX64.matcher(s).matches();
    }

    // --- npub / nsec (NIP-19) --------------------------------------

    public static String hexToNpub(String pubkeyHex) {
        requireHex64(pubkeyHex, "pubkey");
        return Bech32.encode("npub", fromHex(pubkeyHex));
    }

    public static String npubToHex(String npub) {
        Object[] d = Bech32.decode(npub);
        if (!"npub".equals(d[0])) throw new IllegalArgumentException("expected an npub, got " + d[0]);
        byte[] raw = (byte[]) d[1];
        if (raw.length != 32) throw new IllegalArgumentException("npub does not decode to a 32-byte key");
        return toHex(raw);
    }

    /**
     * secret hex → {@code nsec1…}. Per §1.1 / §6.3, callers MUST gate this behind
     * an explicit, separately-confirmed user action and MUST NOT display the
     * result incidentally.
     */
    public static String secretToNsec(String secretHex) {
        requireHex64(secretHex, "secret key");
        return Bech32.encode("nsec", fromHex(secretHex));
    }

    public static String nsecToSecret(String nsec) {
        Object[] d = Bech32.decode(nsec);
        if (!"nsec".equals(d[0])) throw new IllegalArgumentException("expected an nsec, got " + d[0]);
        byte[] raw = (byte[]) d[1];
        if (raw.length != 32) throw new IllegalArgumentException("nsec does not decode to a 32-byte key");
        return toHex(raw);
    }

    // --- did:nostr (§5.1) -----------------------------------------

    public static String hexToDid(String pubkeyHex) {
        requireHex64(pubkeyHex, "pubkey");
        return "did:nostr:" + pubkeyHex;
    }

    public static String didToHex(String did) {
        java.util.regex.Matcher m = DID_NOSTR.matcher(did == null ? "" : did);
        if (!m.matches()) throw new IllegalArgumentException("expected did:nostr:<64 lowercase hex>");
        return m.group(1);
    }

    // --- normalise ------------------------------------------------

    /** hex or {@code npub1…} → canonical lowercase hex. Accepts what §1.1 says to accept. */
    public static String normalizePubkey(String input) {
        if (input == null) throw new IllegalArgumentException("pubkey required");
        String s = input.trim();
        if (s.startsWith("npub1")) return npubToHex(s);
        String lower = s.toLowerCase(Locale.ROOT);
        if (!HEX64.matcher(lower).matches()) {
            throw new IllegalArgumentException("expected 64 hex chars or an npub");
        }
        return lower;
    }

    private static void requireHex64(String s, String what) {
        if (!isHex64(s)) throw new IllegalArgumentException(what + " must be 64 lowercase hex chars");
    }
}
