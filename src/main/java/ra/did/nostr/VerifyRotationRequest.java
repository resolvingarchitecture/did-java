package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code VERIFY_ROTATION} (§4.3) — run the guardian acceptance rule over a bag of
 * events. Stateless: needs no held identity.
 */
public class VerifyRotationRequest extends NostrRequest {

    /**
     * The candidate events. A wire caller parses its JSON into maps and calls
     * {@link NostrEvent#fromMap} per event before setting this.
     */
    public List<NostrEvent> events = new ArrayList<>();
    /** Cool-down in seconds; 0 → {@link NostrRotation#DEFAULT_COOLDOWN_SECONDS}. */
    public long cooldownSeconds = 0;
    /** Optional verifier "now" (unix seconds); a future-dated claim is then rejected. 0 → no check. */
    public long now = 0;

    // Response
    public boolean accepted;
    public String reason;
    public String newKey;
    public String oldKey;
}
