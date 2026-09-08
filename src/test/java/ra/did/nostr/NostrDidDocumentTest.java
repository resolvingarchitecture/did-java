package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class NostrDidDocumentTest {

    private static final String HEX = "100f6d8cbf94afb6fc58e9c384b9b3a6516091373a83c869f4e24a9d2bb4a494";

    @Test
    public void multikeyRoundTrips() {
        String mk = NostrDidDocument.xOnlyToMultikey(HEX);
        assertEquals("fe70102" + HEX, mk);
        assertEquals(HEX, NostrDidDocument.multikeyToXOnly(mk));
        assertThrows(IllegalArgumentException.class, () -> NostrDidDocument.multikeyToXOnly("f01" + HEX));
    }

    @Test
    public void documentShape() {
        Map<String, Object> doc = NostrDidDocument.forPubkey(HEX, null);
        assertEquals("did:nostr:" + HEX, doc.get("id"));
        assertEquals("DIDNostr", doc.get("type"));

        List<?> ctx = (List<?>) doc.get("@context");
        assertEquals("https://www.w3.org/ns/did/v1", ctx.get(0));

        List<?> vm = (List<?>) doc.get("verificationMethod");
        Map<?, ?> vm0 = (Map<?, ?>) vm.get(0);
        assertEquals("Multikey", vm0.get("type"));
        assertEquals("did:nostr:" + HEX + "#0", vm0.get("id"));
        assertEquals("did:nostr:" + HEX, vm0.get("controller"));
        assertEquals("fe70102" + HEX, vm0.get("publicKeyMultibase"));

        assertEquals(Arrays.asList("did:nostr:" + HEX + "#0"), doc.get("authentication"));
        assertEquals(Arrays.asList("did:nostr:" + HEX + "#0"), doc.get("assertionMethod"));
        assertFalse(doc.containsKey("service"));
    }

    @Test
    public void acceptsNpubAndAddsRelayService() {
        String npub = NostrKeys.hexToNpub(HEX);
        Map<String, Object> doc = NostrDidDocument.forPubkey(npub, Arrays.asList("wss://a.example", "wss://b.example"));
        assertEquals("did:nostr:" + HEX, doc.get("id"));
        List<?> svc = (List<?>) doc.get("service");
        Map<?, ?> svc0 = (Map<?, ?>) svc.get(0);
        assertEquals("NostrRelays", svc0.get("type"));
        assertTrue(svc0.get("serviceEndpoint") instanceof List);
    }
}
