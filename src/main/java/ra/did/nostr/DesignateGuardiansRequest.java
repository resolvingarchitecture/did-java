package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code DESIGNATE_GUARDIANS} (§4.1) — the root identity publishes a signed
 * kind 30101 Guardian Set: who may authorise a rotation, and the threshold.
 */
public class DesignateGuardiansRequest extends NostrRequest {

    /** x-only pubkey (hex) of the root identity; must be one the service holds. */
    public String rootPubkey;
    /** guardian pubkeys (hex or npub), each distinct. */
    public List<String> guardians = new ArrayList<>();
    /** how many guardians must co-sign a rotation; {@code 1 <= M <= N}. */
    public int threshold = 1;
    public long createdAt = 0;

}
