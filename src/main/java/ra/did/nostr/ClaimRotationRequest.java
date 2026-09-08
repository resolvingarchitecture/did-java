package ra.did.nostr;

/**
 * {@code CLAIM_ROTATION} (§4.2) — the new key announces succession from an old
 * identity: a signed kind 30103 Rotation Claim.
 *
 * <p>If the old key is still held, set {@link #oldPubkeyForPrevSig} and the old
 * identity must also be one the service holds, so a self-authorising
 * {@code prev-sig} can be attached (guardians then not required).
 */
public class ClaimRotationRequest extends NostrRequest {

    /** x-only pubkey (hex) of the NEW identity; must be one the service holds. */
    public String newPubkey;
    /** x-only pubkey (hex or npub) being rotated away from. */
    public String oldPubkey;
    /** {@code lost} | {@code compromised} | {@code planned}. */
    public String reason;
    /** Optional: the old pubkey (hex), also held by the service, to attach a prev-sig. */
    public String oldPubkeyForPrevSig;
    public long createdAt = 0;

}
