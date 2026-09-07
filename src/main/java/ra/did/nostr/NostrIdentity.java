package ra.did.nostr;

import ra.common.identity.PIIClearable;
import ra.common.identity.PublicKey;

import java.util.Arrays;

/**
 * One Nostr identity: a secp256k1 secret key and its x-only public key
 * (DID {@code DESIGN.md} §1).
 *
 * <p>The secret is held as raw bytes and is <em>sensitive</em> (§6.3): it MUST
 * NOT be logged, MUST NOT appear in {@code toString}, and {@link #clearSensitive}
 * zeroes it. A public-only instance ({@link #publicOnly}) carries no secret and
 * is what a contact or a verify-only path uses.
 *
 * <p>Encryption at rest and persistence are the caller's responsibility for now
 * (a later change wires this through the InfoVault with a memory-hard KDF).
 */
public final class NostrIdentity implements PIIClearable {

    private byte[] secretKey;            // 32 bytes, or null for public-only
    private final String publicKeyHex;   // x-only, 64 lowercase hex

    private NostrIdentity(byte[] secretKey, String publicKeyHex) {
        this.secretKey = secretKey;
        this.publicKeyHex = publicKeyHex;
    }

    /** Wrap an existing 32-byte secret key (defensively copied). */
    public static NostrIdentity fromSecretKey(byte[] secretKey) {
        if (!Bip340.isValidSecretKey(secretKey)) {
            throw new IllegalArgumentException("not a valid 32-byte secp256k1 secret key");
        }
        byte[] copy = Arrays.copyOf(secretKey, 32);
        return new NostrIdentity(copy, NostrKeys.toHex(Bip340.xOnlyPublicKey(copy)));
    }

    public static NostrIdentity fromSecretHex(String secretHex) {
        return fromSecretKey(NostrKeys.fromHex(secretHex));
    }

    /** An identity with no secret — for verification, contacts, and lookups. */
    public static NostrIdentity publicOnly(String pubkeyHexOrNpub) {
        return new NostrIdentity(null, NostrKeys.normalizePubkey(pubkeyHexOrNpub));
    }

    public boolean hasSecret() {
        return secretKey != null;
    }

    /** x-only public key, 64 lowercase hex. The canonical identifier. */
    public String getPublicKeyHex() {
        return publicKeyHex;
    }

    public String npub() {
        return NostrKeys.hexToNpub(publicKeyHex);
    }

    public String didNostr() {
        return NostrKeys.hexToDid(publicKeyHex);
    }

    /**
     * The secret key as lowercase hex. Throws if this is a public-only identity
     * or the secret has been cleared. Used for signing and, deliberately gated by
     * the caller, {@code nsec} export.
     */
    public String secretHex() {
        requireSecret();
        return NostrKeys.toHex(secretKey);
    }

    byte[] secretKeyBytes() {
        requireSecret();
        return secretKey;
    }

    /** A {@link ra.common.identity.PublicKey} view for the {@code DID} model. */
    public PublicKey toPublicKey() {
        PublicKey pk = new PublicKey(publicKeyHex);
        pk.setFingerprint(publicKeyHex);
        pk.setType("BIP340");
        pk.isIdentityKey(true);
        pk.setHex(true);
        pk.addAttribute("npub", npub());
        pk.addAttribute("did", didNostr());
        return pk;
    }

    @Override
    public void clearSensitive() {
        if (secretKey != null) {
            Arrays.fill(secretKey, (byte) 0);
            secretKey = null;
        }
    }

    private void requireSecret() {
        if (secretKey == null) {
            throw new IllegalStateException("no secret key (public-only identity or already cleared)");
        }
    }

    /** Never includes the secret. */
    @Override
    public String toString() {
        return "NostrIdentity{" + publicKeyHex + (hasSecret() ? " +secret}" : "}");
    }
}
