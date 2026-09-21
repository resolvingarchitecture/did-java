package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class NostrProfileTest {

    private static NostrKeyRing ring() {
        NostrKeyRing r = new NostrKeyRing();
        assertTrue(r.init(new Properties()));
        return r;
    }

    @Test
    public void buildsSignsAndParsesRoundTrip() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrEvent ev = ring.sign(NostrProfile.metadata("Alice", "hello", "https://example/pic.png", 1_700_000_000L), alice);

        assertTrue(ev.verify().ok);
        NostrProfile.Parsed p = NostrProfile.parse(ev);
        assertEquals(alice.getPublicKeyHex(), p.pubkey);
        assertEquals("Alice", p.name);
        assertEquals("hello", p.about);
        assertEquals("https://example/pic.png", p.picture);
    }

    @Test
    public void aboutAndPictureAreOptional() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrEvent ev = ring.sign(NostrProfile.metadata("Alice", null, null, 1_700_000_000L), alice);
        NostrProfile.Parsed p = NostrProfile.parse(ev);
        assertEquals("Alice", p.name);
        assertNull(p.about);
        assertNull(p.picture);
    }

    @Test
    public void aNameIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> NostrProfile.metadata("", null, null, 0));
    }

    @Test
    public void malformedContentParsesToEmptyRatherThanThrowing() {
        NostrEvent ev = NostrEvent.unsigned(NostrKinds.PROFILE, new java.util.ArrayList<>(), "not json", 0);
        NostrProfile.Parsed p = NostrProfile.parse(ev);
        assertNull(p.name);
    }
}