package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class NostrNotesTest {

    private static NostrKeyRing ring() {
        NostrKeyRing r = new NostrKeyRing();
        assertTrue(r.init(new Properties()));
        return r;
    }

    @Test
    public void topLevelNoteHasNoThreadRefs() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrEvent ev = ring.sign(NostrNotes.note("hello world", 1_700_000_000L), alice);

        assertTrue(ev.verify().ok);
        assertEquals("hello world", ev.getContent());
        NostrNotes.ThreadRefs refs = NostrNotes.threadRefs(ev);
        assertFalse(refs.isReply());
        assertNull(refs.rootEventId);
        assertNull(refs.parentEventId);
    }

    @Test
    public void topLevelReplyMarksTheSameEventAsRootAndParent() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrIdentity bob = ring.generateIdentity();
        NostrEvent rootByBob = ring.sign(NostrNotes.note("bob's note", 1_700_000_000L), bob);

        NostrEvent replyEv = NostrNotes.reply("nice one", rootByBob.getId(), bob.getPublicKeyHex(),
                rootByBob.getId(), bob.getPublicKeyHex(), 1_700_000_100L);
        NostrEvent reply = ring.sign(replyEv, alice);

        assertTrue(reply.verify().ok);
        NostrNotes.ThreadRefs refs = NostrNotes.threadRefs(reply);
        assertTrue(refs.isReply());
        assertEquals(rootByBob.getId(), refs.rootEventId);
        assertEquals(rootByBob.getId(), refs.parentEventId);
        assertTrue(reply.tagValues("p").contains(bob.getPublicKeyHex()));
    }

    @Test
    public void nestedReplyDistinguishesRootFromDirectParent() {
        NostrKeyRing ring = ring();
        NostrIdentity alice = ring.generateIdentity();
        NostrIdentity bob = ring.generateIdentity();
        NostrIdentity carol = ring.generateIdentity();

        NostrEvent root = ring.sign(NostrNotes.note("root by bob", 1_700_000_000L), bob);
        NostrEvent midEv = NostrNotes.reply("alice replies", root.getId(), bob.getPublicKeyHex(),
                root.getId(), bob.getPublicKeyHex(), 1_700_000_050L);
        NostrEvent mid = ring.sign(midEv, alice);

        NostrEvent leafEv = NostrNotes.reply("carol replies to alice", root.getId(), bob.getPublicKeyHex(),
                mid.getId(), alice.getPublicKeyHex(), 1_700_000_100L);
        NostrEvent leaf = ring.sign(leafEv, carol);

        assertTrue(leaf.verify().ok);
        NostrNotes.ThreadRefs refs = NostrNotes.threadRefs(leaf);
        assertEquals(root.getId(), refs.rootEventId);
        assertEquals(mid.getId(), refs.parentEventId);
        assertNotEquals(refs.rootEventId, refs.parentEventId);
    }

    @Test
    public void emptyContentIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> NostrNotes.note("", 0));
        assertThrows(IllegalArgumentException.class, () -> NostrNotes.reply("", "root", null, "root", null, 0));
    }
}