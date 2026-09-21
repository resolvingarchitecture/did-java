package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class NostrFollowsTest {

    private static NostrKeyRing ring() {
        NostrKeyRing r = new NostrKeyRing();
        assertTrue(r.init(new Properties()));
        return r;
    }

    @Test
    public void buildsSignsAndParsesRoundTrip() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrIdentity bob = ring.generateIdentity();
        NostrIdentity carol = ring.generateIdentity();

        List<NostrFollows.Follow> follows = Arrays.asList(
                new NostrFollows.Follow(bob.getPublicKeyHex(), "wss://relay.example", "bob"),
                new NostrFollows.Follow(carol.getPublicKeyHex()));
        NostrEvent ev = ring.sign(NostrFollows.list(follows, 1_700_000_000L), alice);

        assertTrue(ev.verify().ok);
        List<NostrFollows.Follow> parsed = NostrFollows.parse(ev);
        assertEquals(2, parsed.size());
        assertEquals(bob.getPublicKeyHex(), parsed.get(0).pubkey);
        assertEquals("wss://relay.example", parsed.get(0).relayUrl);
        assertEquals("bob", parsed.get(0).petname);
        assertEquals(carol.getPublicKeyHex(), parsed.get(1).pubkey);
        assertNull(parsed.get(1).relayUrl);
        assertNull(parsed.get(1).petname);
    }

    @Test
    public void anEmptyListIsAValidWayToUnfollowEveryone() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrEvent ev = ring.sign(NostrFollows.list(List.of(), 1_700_000_000L), alice);
        assertTrue(ev.verify().ok);
        assertTrue(NostrFollows.parse(ev).isEmpty());
    }

    @Test
    public void malformedPubkeyTagsAreSkipped() {
        NostrEvent ev = NostrEvent.unsigned(NostrKinds.FOLLOWS, new java.util.ArrayList<>(), "", 0);
        ev.addTag("p", "not-a-valid-hex-pubkey");
        assertTrue(NostrFollows.parse(ev).isEmpty());
    }
}