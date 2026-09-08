package ra.did.nostr;

/**
 * {@code EXPORT_NPUB} — the {@code npub1…} form of a public key. Stateless: needs
 * no held identity, since {@code npub} is a pure encoding of the public key.
 */
public class ExportNpubRequest extends NostrRequest {

    /** x-only pubkey as hex, {@code npub1…}, or {@code did:nostr:…}. */
    public String pubkey;

    // Response
    public String npub;
    public String pubkeyHex;
    public String did;
}
