package ra.did.nostr;

import ra.common.identity.PublicKey;

/**
 * {@code GENERATE_NOSTR_IDENTITY} — create (or import) a Nostr identity and hold
 * it in the service for signing.
 *
 * <p>If {@link #importSecretKeyHex} is set the identity is imported from it,
 * otherwise a fresh key is generated. The service keeps the {@link NostrIdentity}
 * in memory keyed by pubkey; the secret is returned once so the caller can
 * persist it (there is no encrypted store yet — §6.3).
 */
public class GenerateNostrIdentityRequest extends NostrRequest {

    /** Optional: import this 32-byte secret (hex) instead of generating one. Not serialised. */
    public String importSecretKeyHex;

    // Response
    public String publicKeyHex;
    public String npub;
    public String did;
    /** Returned once for the caller to persist. Not serialised. */
    public String secretKeyHex;
    public PublicKey publicKey;
}
