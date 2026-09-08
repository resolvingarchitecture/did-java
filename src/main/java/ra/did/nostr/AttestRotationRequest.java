package ra.did.nostr;

/**
 * {@code ATTEST_ROTATION} (§4.2) — a guardian endorses {@code old -> new}: a
 * signed kind 30102 Rotation Attestation.
 */
public class AttestRotationRequest extends NostrRequest {

    /** x-only pubkey (hex) of the endorsing guardian; must be one the service holds. */
    public String guardianPubkey;
    /** x-only pubkey (hex or npub) being rotated away from. */
    public String oldPubkey;
    /** x-only pubkey (hex or npub) the guardian is endorsing. */
    public String newPubkey;
    /** §3.2 method — how the guardian confirmed the request was genuine. */
    public String method;
    public long createdAt = 0;

}
