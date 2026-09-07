package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;

/**
 * Identity attestations — the {@code vouch} primitive (DID {@code DESIGN.md} §3,
 * {@code drafts/attestations.md}).
 *
 * <p>Kind 30100, signed by the attester, addressable on the subject's pubkey so
 * an attester holds exactly one current attestation per subject.
 *
 * <p>The builders return <em>unsigned</em> {@link NostrEvent}s; sign them with
 * {@link NostrKeyRing#sign} (or {@link NostrEvent#sign}).
 */
public final class NostrAttestations {

    private NostrAttestations() {}

    /** One attested attribute: {@code ["claim", attribute, value]}. */
    public static final class Claim {
        public final String attribute;
        public final String value;
        public Claim(String attribute, String value) {
            this.attribute = attribute;
            this.value = value;
        }
    }

    /**
     * Build an unsigned kind 30100 Identity Attestation.
     *
     * @param subject    the key being vouched for (hex or npub)
     * @param claims     at least one claim
     * @param method     how the attester verified (§3.2)
     * @param expiration optional NIP-40 expiration, unix seconds, or {@code null}
     */
    public static NostrEvent attestation(String subject, List<Claim> claims, String method,
                                         Long expiration, long createdAt) {
        if (claims == null || claims.isEmpty()) {
            throw new IllegalArgumentException("an attestation needs at least one claim");
        }
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("a method is required");
        }
        String s = NostrKeys.normalizePubkey(subject);
        List<List<String>> tags = new ArrayList<>();
        tags.add(tag("d", s));
        tags.add(tag("p", s));
        for (Claim c : claims) tags.add(tag("claim", c.attribute, c.value));
        tags.add(tag("method", method));
        if (expiration != null) tags.add(tag("expiration", String.valueOf(expiration)));
        return NostrEvent.unsigned(NostrKinds.IDENTITY_ATTESTATION, tags, "", createdAt);
    }

    /**
     * Build an unsigned revocation: the addressable event is replaced with one
     * that carries {@code ["revoked", <reason>]} and no {@code claim} tags (§3.4).
     * A verifier MUST treat this differently from a missing attestation.
     */
    public static NostrEvent revocation(String subject, String reason, long createdAt) {
        String s = NostrKeys.normalizePubkey(subject);
        List<List<String>> tags = new ArrayList<>();
        tags.add(tag("d", s));
        tags.add(tag("p", s));
        tags.add(tag("revoked", reason == null ? "" : reason));
        return NostrEvent.unsigned(NostrKinds.IDENTITY_ATTESTATION, tags, "", createdAt);
    }

    // --- reading -------------------------------------------------

    public static final class Parsed {
        public final String attester;
        public final String subject;
        public final List<Claim> claims;
        public final String method;
        public final Long expiration;
        public final String revoked;
        Parsed(String attester, String subject, List<Claim> claims, String method,
               Long expiration, String revoked) {
            this.attester = attester;
            this.subject = subject;
            this.claims = claims;
            this.method = method;
            this.expiration = expiration;
            this.revoked = revoked;
        }
        public boolean isRevocation() { return revoked != null; }
    }

    /** Structured view of a kind 30100 event. Does not verify — call {@link NostrEvent#verify} first. */
    public static Parsed parse(NostrEvent ev) {
        if (ev.getKind() != NostrKinds.IDENTITY_ATTESTATION) {
            throw new IllegalArgumentException("not a kind " + NostrKinds.IDENTITY_ATTESTATION + " event");
        }
        List<Claim> claims = new ArrayList<>();
        for (List<String> t : ev.tags("claim")) {
            if (t.size() >= 3) claims.add(new Claim(t.get(1), t.get(2)));
        }
        String exp = ev.firstTag("expiration");
        return new Parsed(
                ev.getPubkey(),
                ev.firstTag("d"),
                claims,
                ev.firstTag("method"),
                exp == null ? null : Long.valueOf(exp),
                ev.firstTag("revoked"));
    }

    /** Is this attestation past its NIP-40 {@code expiration} at {@code at} (unix seconds)? */
    public static boolean isExpired(NostrEvent ev, long at) {
        String exp = ev.firstTag("expiration");
        return exp != null && Long.parseLong(exp) <= at;
    }

    private static List<String> tag(String... parts) {
        List<String> t = new ArrayList<>(parts.length);
        for (String p : parts) t.add(p);
        return t;
    }
}
