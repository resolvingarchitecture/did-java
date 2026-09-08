package ra.did.nostr;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code VOUCH} / {@code ATTEST} — the {@code vouch} primitive (§3): the signer
 * (an identity the service holds) attests one or more attributes of a subject.
 * Produces a signed kind 30100 event.
 */
public class AttestRequest extends NostrRequest {

    /** x-only pubkey (hex) of the attesting identity; must be one the service holds. */
    public String signerPubkey;
    /** x-only pubkey (hex or npub) of the subject being vouched for. */
    public String subjectPubkey;
    /** attribute → value (e.g. {@code {"name":"alice","nip05":"alice@example.com"}}). */
    public Map<String, String> claims = new LinkedHashMap<>();
    /** §3.2 method; defaults to {@code asserted} (the weakest) if unset. */
    public String method;
    /** Optional NIP-40 expiration, unix seconds. */
    public Long expiration;
    /** Optional fixed timestamp; 0 → now. */
    public long createdAt = 0;

}
