package ra.did.nostr;

import fr.acinq.secp256k1.Secp256k1;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * NIP-44 v2 — the Nostr encrypted-DM payload format
 * (<a href="https://github.com/nostr-protocol/nips/blob/master/44.md">spec</a>):
 * ECDH (the raw shared-point X coordinate, <b>not</b> libsecp256k1's default
 * hashed {@code ecdh()}) → HKDF-SHA256 → per-message ChaCha20 + HMAC-SHA256,
 * over a length-hiding padding scheme.
 *
 * <p>Cross-checked against the reference JS implementation
 * ({@code nostr-tools}' {@code nip44.ts}) and verified against the spec's own
 * official test vectors ({@code src/test/resources/vectors/nip44.json}) - see
 * {@code Nip44VectorsTest} - not a from-scratch reading of the prose spec.
 *
 * <p>ChaCha20 (RFC 8439, IETF variant) and HKDF (RFC 5869) are implemented
 * directly here rather than via a JCE provider transformation or
 * BouncyCastle's engine classes: {@code did-java} is embedded on Android by
 * {@code 1m5-remnant}, which excludes the BouncyCastle artifact version this
 * module otherwise depends on (a class-conflict fix against a newer BC family
 * pulled in for Bitcoin support - see that repo's {@code core-host/
 * build.gradle}), and plain-JCE {@code Cipher.getInstance("ChaCha20")}
 * (non-AEAD) support is not guaranteed across Android API levels the way
 * {@code HmacSHA256} - used here for HKDF and the message MAC - reliably is.
 */
public final class Nip44 {

    private static final Secp256k1 SECP = Secp256k1.get();
    private static final byte[] SALT = "nip44-v2".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RNG = new SecureRandom();
    private static final int VERSION = 2;
    private static final int MIN_PAYLOAD_LENGTH = 132; // base64 chars, per spec

    private Nip44() {}

    // -- public API --------------------------------------------------

    /** {@code ECDH(secretKeyA, xOnlyPublicKeyB)} → HKDF-extract - the shared "conversation key" for this pair. */
    public static byte[] getConversationKey(byte[] secretKeyA, byte[] xOnlyPublicKeyB) {
        byte[] sharedX = sharedX(secretKeyA, xOnlyPublicKeyB);
        try {
            return hkdfExtract(SALT, sharedX);
        } finally {
            Arrays.fill(sharedX, (byte) 0);
        }
    }

    /** Encrypts with a fresh random 32-byte nonce. */
    public static String encrypt(String plaintext, byte[] conversationKey) {
        byte[] nonce = new byte[32];
        RNG.nextBytes(nonce);
        return encrypt(plaintext, conversationKey, nonce);
    }

    /**
     * @param nonce32 exactly 32 bytes. Exposed so tests can reproduce the
     *                spec's fixed-nonce vectors; production callers should use
     *                {@link #encrypt(String, byte[])} for a fresh random one.
     */
    public static String encrypt(String plaintext, byte[] conversationKey, byte[] nonce32) {
        if (nonce32 == null || nonce32.length != 32) {
            throw new IllegalArgumentException("nonce must be 32 bytes");
        }
        byte[] plainUtf8 = plaintext.getBytes(StandardCharsets.UTF_8);
        if (plainUtf8.length < 1) {
            throw new IllegalArgumentException("invalid plaintext size: must be at least 1 byte");
        }
        MessageKeys keys = messageKeys(conversationKey, nonce32);
        byte[] padded = pad(plainUtf8);
        byte[] ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, padded);
        byte[] mac = hmacAad(keys.hmacKey, ciphertext, nonce32);

        byte[] payload = new byte[1 + 32 + ciphertext.length + 32];
        payload[0] = (byte) VERSION;
        System.arraycopy(nonce32, 0, payload, 1, 32);
        System.arraycopy(ciphertext, 0, payload, 33, ciphertext.length);
        System.arraycopy(mac, 0, payload, 33 + ciphertext.length, 32);
        return Base64.getEncoder().encodeToString(payload);
    }

    /**
     * @throws IllegalArgumentException on any malformed payload, wrong
     *         version, invalid MAC, or invalid padding - all ordinary outcomes
     *         for tampered, corrupted, or foreign input, not exceptional ones.
     */
    public static String decrypt(String payload, byte[] conversationKey) {
        if (payload == null || payload.length() < MIN_PAYLOAD_LENGTH) {
            throw new IllegalArgumentException("invalid payload length");
        }
        if (payload.charAt(0) == '#') {
            throw new IllegalArgumentException("unknown encryption version");
        }
        byte[] data;
        try {
            data = Base64.getDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid base64", e);
        }
        if (data.length < 99) {
            throw new IllegalArgumentException("invalid data length: " + data.length);
        }
        if ((data[0] & 0xFF) != VERSION) {
            throw new IllegalArgumentException("unknown encryption version " + (data[0] & 0xFF));
        }

        byte[] nonce = Arrays.copyOfRange(data, 1, 33);
        byte[] ciphertext = Arrays.copyOfRange(data, 33, data.length - 32);
        byte[] mac = Arrays.copyOfRange(data, data.length - 32, data.length);

        MessageKeys keys = messageKeys(conversationKey, nonce);
        byte[] expectedMac = hmacAad(keys.hmacKey, ciphertext, nonce);
        if (!constantTimeEquals(expectedMac, mac)) {
            throw new IllegalArgumentException("invalid MAC");
        }
        byte[] padded = chacha20(keys.chachaKey, keys.chachaNonce, ciphertext);
        return unpad(padded);
    }

    // -- ECDH: the raw shared-point X coordinate, not libsecp256k1's hashed ecdh() --

    private static byte[] sharedX(byte[] secretKeyA, byte[] xOnlyPublicKeyB) {
        if (!Bip340.isValidSecretKey(secretKeyA)) {
            throw new IllegalArgumentException("invalid secret key");
        }
        if (!Bip340.isValidXOnlyPublicKey(xOnlyPublicKeyB)) {
            throw new IllegalArgumentException("invalid public key");
        }
        // Lift the x-only key to a point with even Y, per BIP-340 convention.
        byte[] compressed = new byte[33];
        compressed[0] = 0x02;
        System.arraycopy(xOnlyPublicKeyB, 0, compressed, 1, 32);
        byte[] point;
        try {
            point = SECP.pubkeyParse(compressed);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid public key", e);
        }
        byte[] shared;
        try {
            shared = SECP.pubKeyTweakMul(point, secretKeyA);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("invalid secret key or ECDH failure", e);
        }
        byte[] sharedCompressed = SECP.pubKeyCompress(shared);
        return Arrays.copyOfRange(sharedCompressed, 1, 33);
    }

    // -- HKDF (RFC 5869) and the message MAC, both HMAC-SHA256 based --

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt, ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        int hashLen = 32;
        int n = (length + hashLen - 1) / hashLen;
        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; i <= n; i++) {
            byte[] input = new byte[t.length + info.length + 1];
            System.arraycopy(t, 0, input, 0, t.length);
            System.arraycopy(info, 0, input, t.length, info.length);
            input[input.length - 1] = (byte) i;
            t = hmacSha256(prk, input);
            int copyLen = Math.min(hashLen, length - pos);
            System.arraycopy(t, 0, okm, pos, copyLen);
            pos += copyLen;
        }
        return okm;
    }

    private static final class MessageKeys {
        final byte[] chachaKey;
        final byte[] chachaNonce;
        final byte[] hmacKey;

        MessageKeys(byte[] chachaKey, byte[] chachaNonce, byte[] hmacKey) {
            this.chachaKey = chachaKey;
            this.chachaNonce = chachaNonce;
            this.hmacKey = hmacKey;
        }
    }

    private static MessageKeys messageKeys(byte[] conversationKey, byte[] nonce32) {
        byte[] expanded = hkdfExpand(conversationKey, nonce32, 76);
        return new MessageKeys(
                Arrays.copyOfRange(expanded, 0, 32),
                Arrays.copyOfRange(expanded, 32, 44),
                Arrays.copyOfRange(expanded, 44, 76));
    }

    private static byte[] hmacAad(byte[] key, byte[] message, byte[] aad) {
        if (aad.length != 32) throw new IllegalArgumentException("AAD must be 32 bytes");
        byte[] combined = new byte[aad.length + message.length];
        System.arraycopy(aad, 0, combined, 0, aad.length);
        System.arraycopy(message, 0, combined, aad.length, message.length);
        return hmacSha256(key, combined);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    // -- length-hiding padding ----------------------------------------

    /** Package-visible for {@code Nip44VectorsTest}'s direct vectors on this function alone. */
    static int calcPaddedLen(int len) {
        if (len < 1) throw new IllegalArgumentException("expected positive integer");
        if (len <= 32) return 32;
        int nextPower = Integer.highestOneBit(len - 1) << 1;
        int chunk = nextPower <= 256 ? 32 : nextPower / 8;
        return chunk * ((len - 1) / chunk + 1);
    }

    private static byte[] pad(byte[] plainUtf8) {
        int len = plainUtf8.length;
        byte[] prefix = len >= 65536
                ? new byte[]{0, 0, (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len}
                : new byte[]{(byte) (len >>> 8), (byte) len};
        int paddedLen = calcPaddedLen(len);
        byte[] out = new byte[prefix.length + paddedLen];
        System.arraycopy(prefix, 0, out, 0, prefix.length);
        System.arraycopy(plainUtf8, 0, out, prefix.length, len);
        return out;
    }

    private static String unpad(byte[] padded) {
        if (padded.length < 2) throw new IllegalArgumentException("invalid padding");
        int firstTwo = ((padded[0] & 0xFF) << 8) | (padded[1] & 0xFF);
        int unpaddedLen;
        int prefixLen;
        if (firstTwo == 0) {
            if (padded.length < 6) throw new IllegalArgumentException("invalid padding");
            unpaddedLen = ((padded[2] & 0xFF) << 24) | ((padded[3] & 0xFF) << 16)
                    | ((padded[4] & 0xFF) << 8) | (padded[5] & 0xFF);
            if (unpaddedLen < 65536) throw new IllegalArgumentException("invalid padding");
            prefixLen = 6;
        } else {
            unpaddedLen = firstTwo;
            prefixLen = 2;
        }
        if (unpaddedLen < 1 || padded.length < prefixLen + unpaddedLen
                || padded.length != prefixLen + calcPaddedLen(unpaddedLen)) {
            throw new IllegalArgumentException("invalid padding");
        }
        return new String(padded, prefixLen, unpaddedLen, StandardCharsets.UTF_8);
    }

    // -- ChaCha20 (RFC 8439, IETF variant: 96-bit nonce, 32-bit counter starting at 0) --

    private static byte[] chacha20(byte[] key, byte[] nonce12, byte[] data) {
        if (key.length != 32) throw new IllegalArgumentException("key must be 32 bytes");
        if (nonce12.length != 12) throw new IllegalArgumentException("nonce must be 12 bytes");
        int[] key8 = bytesToIntsLE(key, 8);
        int[] nonce3 = bytesToIntsLE(nonce12, 3);
        byte[] out = new byte[data.length];
        int blocks = (data.length + 63) / 64;
        for (int b = 0; b < blocks; b++) {
            byte[] keystream = intsToBytesLE(block(key8, b, nonce3));
            int offset = b * 64;
            int len = Math.min(64, data.length - offset);
            for (int i = 0; i < len; i++) {
                out[offset + i] = (byte) (data[offset + i] ^ keystream[i]);
            }
        }
        return out;
    }

    private static int[] block(int[] key8, int counter, int[] nonce3) {
        int[] state = new int[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        System.arraycopy(key8, 0, state, 4, 8);
        state[12] = counter;
        System.arraycopy(nonce3, 0, state, 13, 3);

        int[] working = state.clone();
        for (int i = 0; i < 10; i++) {
            quarterRound(working, 0, 4, 8, 12);
            quarterRound(working, 1, 5, 9, 13);
            quarterRound(working, 2, 6, 10, 14);
            quarterRound(working, 3, 7, 11, 15);
            quarterRound(working, 0, 5, 10, 15);
            quarterRound(working, 1, 6, 11, 12);
            quarterRound(working, 2, 7, 8, 13);
            quarterRound(working, 3, 4, 9, 14);
        }
        int[] out = new int[16];
        for (int i = 0; i < 16; i++) out[i] = working[i] + state[i];
        return out;
    }

    private static void quarterRound(int[] s, int a, int b, int c, int d) {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = Integer.rotateLeft(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Integer.rotateLeft(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = Integer.rotateLeft(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = Integer.rotateLeft(s[b], 7);
    }

    private static int[] bytesToIntsLE(byte[] bytes, int count) {
        int[] out = new int[count];
        for (int i = 0; i < count; i++) {
            out[i] = (bytes[i * 4] & 0xFF)
                    | ((bytes[i * 4 + 1] & 0xFF) << 8)
                    | ((bytes[i * 4 + 2] & 0xFF) << 16)
                    | ((bytes[i * 4 + 3] & 0xFF) << 24);
        }
        return out;
    }

    private static byte[] intsToBytesLE(int[] ints) {
        byte[] out = new byte[ints.length * 4];
        for (int i = 0; i < ints.length; i++) {
            out[i * 4] = (byte) ints[i];
            out[i * 4 + 1] = (byte) (ints[i] >>> 8);
            out[i * 4 + 2] = (byte) (ints[i] >>> 16);
            out[i * 4 + 3] = (byte) (ints[i] >>> 24);
        }
        return out;
    }
}
