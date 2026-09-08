package ra.did.nostr;

import ra.common.identity.PublicKey;

/**
 * {@code LOAD_NOSTR_IDENTITY} — decrypt a persisted identity with its passphrase
 * and hold it in the service for signing.
 */
public class LoadNostrIdentityRequest extends NostrRequest {

    public static final int NOT_PERSISTED = 10;
    public static final int BAD_PASSPHRASE = 11;

    /** x-only pubkey (hex or npub) of the persisted identity. */
    public String pubkey;
    /** Passphrase it was sealed under. Not serialised. */
    public String passphrase;

    // Response
    public String publicKeyHex;
    public String npub;
    public String did;
    public PublicKey publicKey;
}
