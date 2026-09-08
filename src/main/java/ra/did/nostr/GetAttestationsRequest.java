package ra.did.nostr;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET_ATTESTATIONS} — the §3.5 trust query, as an aggregation over a bag
 * of attestation events the caller supplies (from relays, a local cache, …).
 * did-java stores no attestations; this defines only the summary, not a score
 * (scoring is a client concern).
 */
public class GetAttestationsRequest extends NostrRequest {

    /** x-only pubkey (hex or npub) of the subject being asked about. */
    public String subjectPubkey;
    /**
     * Candidate kind 30100 events. A wire caller parses its JSON into maps and
     * calls {@link NostrEvent#fromMap} per event before setting this.
     */
    public List<NostrEvent> attestations = new ArrayList<>();

    // Response
    /** Non-revoked attestations for the subject that verified. */
    public int total;
    /** method (§3.2) → count. */
    public Map<String, Integer> byMethod = new LinkedHashMap<>();
    /** distinct attester pubkeys. */
    public List<String> attesters = new ArrayList<>();
    /** distinct {@code name} claim values asserted for the subject. */
    public List<String> names = new ArrayList<>();
    /** true if any attester issued a {@code not} (impersonation warning). */
    public boolean hasNegative;
    /** attester pubkeys that issued a {@code not}. */
    public List<String> negativeFrom = new ArrayList<>();
    /** count of revocation events seen for the subject. */
    public int revocations;
}
