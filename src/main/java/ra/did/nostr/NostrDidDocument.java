package ra.did.nostr;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The {@code did:nostr} view of a key (DID {@code DESIGN.md} §5).
 *
 * <p>RA does not define a DID method — this produces the document offline from
 * the public key alone (the draft's "minimal resolution"), so RA identities are
 * legible to W3C tooling. No HTTP {@code .well-known} tier (§5.3).
 *
 * <p>The {@code did:nostr} method is an unratified community draft; re-verify
 * these details against the current draft before relying on them.
 */
public final class NostrDidDocument {

    private NostrDidDocument() {}

    /**
     * Multikey encoding of an x-only key (§5.2):
     * {@code f} (multibase base16-lower) + {@code e701} (multicodec secp256k1-pub)
     * + {@code 02} (compressed, even-Y) + the x-only hex.
     */
    public static String xOnlyToMultikey(String pubkeyHexOrNpub) {
        return "f" + "e701" + "02" + NostrKeys.normalizePubkey(pubkeyHexOrNpub);
    }

    /** Decode a Multikey string back to x-only hex, or throw if it is not that shape. */
    public static String multikeyToXOnly(String multikey) {
        if (multikey == null || !multikey.matches("^fe70102[0-9a-f]{64}$")) {
            throw new IllegalArgumentException("not an x-only secp256k1 Multikey (f e701 02 <hex>)");
        }
        return multikey.substring(7);
    }

    /** The {@code did:nostr} document for a public key, as an ordered map. */
    public static Map<String, Object> forPubkey(String pubkeyHexOrNpub, List<String> relays) {
        String hex = NostrKeys.normalizePubkey(pubkeyHexOrNpub);
        String did = "did:nostr:" + hex;
        String vmId = did + "#0";

        Map<String, Object> vm = new LinkedHashMap<>();
        vm.put("id", vmId);
        vm.put("type", "Multikey");
        vm.put("controller", did);
        vm.put("publicKeyMultibase", xOnlyToMultikey(hex));

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", asList("https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"));
        doc.put("id", did);
        doc.put("type", "DIDNostr");
        doc.put("verificationMethod", asList(vm));
        doc.put("authentication", asList(vmId));
        doc.put("assertionMethod", asList(vmId));
        if (relays != null && !relays.isEmpty()) {
            Map<String, Object> svc = new LinkedHashMap<>();
            svc.put("id", did + "#relays");
            svc.put("type", "NostrRelays");
            svc.put("serviceEndpoint", relays.size() == 1 ? relays.get(0) : new ArrayList<>(relays));
            doc.put("service", asList(svc));
        }
        return doc;
    }

    @SafeVarargs
    private static <T> List<T> asList(T... items) {
        List<T> l = new ArrayList<>(items.length);
        for (T i : items) l.add(i);
        return l;
    }
}
