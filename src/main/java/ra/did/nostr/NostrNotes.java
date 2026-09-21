package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;

/**
 * Kind 1 notes and replies (NIP-01 content, NIP-10 reply/mention tags). The
 * builders return an <em>unsigned</em> {@link NostrEvent}; sign it with
 * {@link NostrKeyRing#sign} or {@link NostrEvent#sign}.
 */
public final class NostrNotes {

    private NostrNotes() {}

    /** A plain, top-level note. */
    public static NostrEvent note(String content, long createdAt) {
        if (content == null || content.isEmpty()) {
            throw new IllegalArgumentException("a note needs content");
        }
        return NostrEvent.unsigned(NostrKinds.NOTE, new ArrayList<>(), content, createdAt);
    }

    /**
     * A reply, tagged per NIP-10's "marked" scheme: an {@code e}-tag for the
     * root, an {@code e}-tag for the direct parent (equal to the root's for a
     * top-level reply), and a {@code p}-tag for the parent's author so they
     * are notified. {@code rootEventId}/{@code rootAuthorPubkey} identify the
     * start of the thread; {@code parentEventId}/{@code parentAuthorPubkey}
     * the note actually being replied to.
     */
    public static NostrEvent reply(String content, String rootEventId, String rootAuthorPubkey,
                                    String parentEventId, String parentAuthorPubkey, long createdAt) {
        if (content == null || content.isEmpty()) {
            throw new IllegalArgumentException("a reply needs content");
        }
        if (rootEventId == null || parentEventId == null) {
            throw new IllegalArgumentException("a reply needs a root and a parent event id");
        }
        List<List<String>> tags = new ArrayList<>();
        tags.add(eTag(rootEventId, "root"));
        if (!rootEventId.equals(parentEventId)) tags.add(eTag(parentEventId, "reply"));
        if (rootAuthorPubkey != null) tags.add(pTag(rootAuthorPubkey));
        if (parentAuthorPubkey != null && !parentAuthorPubkey.equals(rootAuthorPubkey)) tags.add(pTag(parentAuthorPubkey));
        return NostrEvent.unsigned(NostrKinds.NOTE, tags, content, createdAt);
    }

    public static final class ThreadRefs {
        /** Null for a top-level note. */
        public final String rootEventId;
        public final String parentEventId;
        ThreadRefs(String rootEventId, String parentEventId) {
            this.rootEventId = rootEventId;
            this.parentEventId = parentEventId;
        }
        public boolean isReply() { return parentEventId != null; }
    }

    /** The NIP-10 root/parent event ids from a kind 1 event's {@code e} tags, if any. Does not verify - call {@link NostrEvent#verify} first. */
    public static ThreadRefs threadRefs(NostrEvent ev) {
        if (ev.getKind() != NostrKinds.NOTE) {
            throw new IllegalArgumentException("not a kind " + NostrKinds.NOTE + " event");
        }
        String root = null, reply = null, firstUnmarked = null, secondUnmarked = null;
        int unmarkedSeen = 0;
        for (List<String> t : ev.tags("e")) {
            if (t.size() < 2) continue;
            String marker = t.size() > 3 ? t.get(3) : null;
            if ("root".equals(marker)) root = t.get(1);
            else if ("reply".equals(marker)) reply = t.get(1);
            else {
                // NIP-10 deprecated/positional form: first e-tag is root, last is the direct parent.
                if (unmarkedSeen == 0) firstUnmarked = t.get(1);
                secondUnmarked = t.get(1);
                unmarkedSeen++;
            }
        }
        if (root == null && firstUnmarked != null) root = firstUnmarked;
        String parent = reply != null ? reply : (secondUnmarked != null ? secondUnmarked : root);
        return new ThreadRefs(root, parent);
    }

    private static List<String> eTag(String eventId, String marker) {
        List<String> t = new ArrayList<>();
        t.add("e");
        t.add(eventId);
        t.add("");
        t.add(marker);
        return t;
    }

    private static List<String> pTag(String pubkey) {
        List<String> t = new ArrayList<>();
        t.add("p");
        t.add(NostrKeys.normalizePubkey(pubkey));
        return t;
    }
}
