package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * {@code RESOLVE_DID_DOCUMENT} — produce the {@code did:nostr} document for a key
 * (§5.2), offline from the public key alone. Stateless.
 */
public class ResolveDidDocumentRequest extends NostrRequest {

    /** x-only pubkey as hex, {@code npub1…}, or {@code did:nostr:…}. */
    public String pubkey;
    /** Optional relay endpoints for a {@code service} entry. */
    public List<String> relays = new ArrayList<>();

    // Response
    public Map<String, Object> document;
    public String documentJson;
}
