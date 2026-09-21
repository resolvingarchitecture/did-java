package ra.did.nostr;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Kind 0 profile metadata (NIP-01). The builder returns an <em>unsigned</em>
 * {@link NostrEvent}; sign it with {@link NostrKeyRing#sign} or
 * {@link NostrEvent#sign}.
 *
 * <p>Deliberately just {@code name}/{@code about}/{@code picture} - no
 * {@code nip05} field. Per {@code 1m5-remnant/DESIGN.md} §"Identity", kind
 * 30100 attestations replace NIP-05 verification here; a profile that carried
 * a {@code nip05} claim this app cannot itself verify would contradict that
 * design decision by implying a verification path it does not actually offer.
 */
public final class NostrProfile {

    private NostrProfile() {}

    /** Build an unsigned kind 0 event. {@code about}/{@code picture} may be {@code null} (omitted). */
    public static NostrEvent metadata(String name, String about, String picture, long createdAt) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("a profile needs a name");
        }
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        if (about != null && !about.isEmpty()) o.addProperty("about", about);
        if (picture != null && !picture.isEmpty()) o.addProperty("picture", picture);
        return NostrEvent.unsigned(NostrKinds.PROFILE, new java.util.ArrayList<>(), o.toString(), createdAt);
    }

    public static final class Parsed {
        public final String pubkey;
        public final String name;
        public final String about;
        public final String picture;
        public final long createdAt;
        Parsed(String pubkey, String name, String about, String picture, long createdAt) {
            this.pubkey = pubkey;
            this.name = name;
            this.about = about;
            this.picture = picture;
            this.createdAt = createdAt;
        }
    }

    /** Structured view of a kind 0 event. Does not verify - call {@link NostrEvent#verify} first. Malformed content yields a mostly-empty {@link Parsed}, never a thrown exception - a hostile relay's job is exactly to send junk. */
    public static Parsed parse(NostrEvent ev) {
        if (ev.getKind() != NostrKinds.PROFILE) {
            throw new IllegalArgumentException("not a kind " + NostrKinds.PROFILE + " event");
        }
        String name = null, about = null, picture = null;
        try {
            JsonObject o = JsonParser.parseString(ev.getContent()).getAsJsonObject();
            if (o.has("name")) name = o.get("name").getAsString();
            if (o.has("about")) about = o.get("about").getAsString();
            if (o.has("picture")) picture = o.get("picture").getAsString();
        } catch (RuntimeException ignored) {
            // malformed content from a relay is an ordinary outcome, not exceptional
        }
        return new Parsed(ev.getPubkey(), name, about, picture, ev.getCreatedAt());
    }
}
