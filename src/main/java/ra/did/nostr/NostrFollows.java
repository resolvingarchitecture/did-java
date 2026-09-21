package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;

/**
 * Kind 3 follow list (NIP-02). Replace-all semantics - the whole list is one
 * event; publishing a new one supersedes the previous one for the same
 * author. The builder returns an <em>unsigned</em> {@link NostrEvent}; sign it
 * with {@link NostrKeyRing#sign} or {@link NostrEvent#sign}.
 */
public final class NostrFollows {

    private NostrFollows() {}

    /** One followed pubkey, with NIP-02's optional relay hint / petname. */
    public static final class Follow {
        public final String pubkey;
        public final String relayUrl;
        public final String petname;

        public Follow(String pubkey) { this(pubkey, null, null); }

        public Follow(String pubkey, String relayUrl, String petname) {
            this.pubkey = NostrKeys.normalizePubkey(pubkey);
            this.relayUrl = relayUrl;
            this.petname = petname;
        }
    }

    /** Build an unsigned kind 3 event carrying exactly {@code follows} - not a merge with any prior list. */
    public static NostrEvent list(List<Follow> follows, long createdAt) {
        List<List<String>> tags = new ArrayList<>();
        for (Follow f : follows) {
            List<String> tag = new ArrayList<>();
            tag.add("p");
            tag.add(f.pubkey);
            tag.add(f.relayUrl == null ? "" : f.relayUrl);
            if (f.petname != null) tag.add(f.petname);
            tags.add(tag);
        }
        return NostrEvent.unsigned(NostrKinds.FOLLOWS, tags, "", createdAt);
    }

    /** The followed pubkeys from a kind 3 event, in tag order. Does not verify - call {@link NostrEvent#verify} first. */
    public static List<Follow> parse(NostrEvent ev) {
        if (ev.getKind() != NostrKinds.FOLLOWS) {
            throw new IllegalArgumentException("not a kind " + NostrKinds.FOLLOWS + " event");
        }
        List<Follow> out = new ArrayList<>();
        for (List<String> t : ev.tags("p")) {
            if (t.size() < 2 || !NostrKeys.isHex64(t.get(1))) continue;
            String relay = t.size() > 2 && !t.get(2).isEmpty() ? t.get(2) : null;
            String petname = t.size() > 3 && !t.get(3).isEmpty() ? t.get(3) : null;
            out.add(new Follow(t.get(1), relay, petname));
        }
        return out;
    }
}
