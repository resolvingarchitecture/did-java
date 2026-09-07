package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class NostrKeyRingTest {

    private static NostrKeyRing ring() {
        NostrKeyRing r = new NostrKeyRing();
        assertTrue(r.init(new Properties()), "BIP-340 backend should load");
        return r;
    }

    @Test
    public void generatesAndEncodesAnIdentity() {
        NostrIdentity id = ring().generateIdentity();
        assertTrue(NostrKeys.isHex64(id.getPublicKeyHex()));
        assertTrue(id.npub().startsWith("npub1"));
        assertTrue(id.didNostr().startsWith("did:nostr:"));
        assertEquals(id.getPublicKeyHex(), NostrKeys.npubToHex(id.npub()));
        assertEquals(id.getPublicKeyHex(), NostrKeys.didToHex(id.didNostr()));
    }

    @Test
    public void signsAndVerifiesAnEvent() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();

        List<List<String>> tags = new ArrayList<>();
        tags.add(new ArrayList<>(java.util.Arrays.asList("t", "did")));
        NostrEvent note = NostrEvent.unsigned(1, tags, "hello 🔑", 1_700_000_000L);

        ring.sign(note, alice);
        assertEquals(alice.getPublicKeyHex(), note.getPubkey());
        assertNotNull(note.getId());
        assertNotNull(note.getSig());

        NostrEvent.VerifyResult r = ring.verify(note);
        assertTrue(r.ok, "step " + r.step + ": " + r.reason);
    }

    @Test
    public void deterministicSignaturesReproduce() {
        Properties p = new Properties();
        p.setProperty(NostrKeyRing.PROP_DETERMINISTIC_SIGNATURES, "true");
        NostrKeyRing ring = new NostrKeyRing();
        ring.init(p);

        NostrIdentity id = NostrIdentity.fromSecretHex(
                "1100000000000000000000000000000000000000000000000000000000000001");
        NostrEvent a = NostrEvent.unsigned(1, new ArrayList<>(), "reproducible", 1_700_000_000L);
        NostrEvent b = NostrEvent.unsigned(1, new ArrayList<>(), "reproducible", 1_700_000_000L);
        ring.sign(a, id);
        ring.sign(b, id);
        assertEquals(a.getSig(), b.getSig());
        assertEquals(a.getId(), b.getId());
    }

    @Test
    public void rejectsTamperedEvent() {
        NostrKeyRing ring = ring();
        NostrIdentity id = ring.generateIdentity();
        NostrEvent e = NostrEvent.unsigned(1, new ArrayList<>(), "original", 1_700_000_000L);
        ring.sign(e, id);
        e.setContent("tampered");
        NostrEvent.VerifyResult r = ring.verify(e);
        assertFalse(r.ok);
        assertEquals(2, r.step); // id no longer matches the content
    }

    @Test
    public void publicOnlyIdentityCannotSign() {
        NostrKeyRing ring = ring();
        NostrIdentity pub = NostrIdentity.publicOnly(ring.generateIdentity().getPublicKeyHex());
        assertFalse(pub.hasSecret());
        NostrEvent e = NostrEvent.unsigned(1, new ArrayList<>(), "x", 1L);
        assertThrows(IllegalArgumentException.class, () -> ring.sign(e, pub));
    }

    @Test
    public void clearSensitiveZeroesTheSecret() {
        NostrIdentity id = ring().generateIdentity();
        assertTrue(id.hasSecret());
        id.clearSensitive();
        assertFalse(id.hasSecret());
        assertThrows(IllegalStateException.class, id::secretHex);
    }
}
