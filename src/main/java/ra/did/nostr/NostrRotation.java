package ra.did.nostr;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Guardians, rotation and recovery (DID {@code DESIGN.md} §4,
 * {@code drafts/social-recovery.md}).
 *
 * <ul>
 *   <li>kind 30101 Guardian Set — signed by the root identity</li>
 *   <li>kind 30103 Rotation Claim — signed by the new key</li>
 *   <li>kind 30102 Rotation Attestation — signed by a guardian, one per guardian</li>
 * </ul>
 *
 * Plus {@link #evaluate}, the normative acceptance rule (§4.3) — a port of
 * {@code did-vectors/acceptance.py}, kept in step with it and with
 * {@code did-ts}'s {@code evaluateRotation}.
 *
 * <p>The builders return <em>unsigned</em> {@link NostrEvent}s.
 */
public final class NostrRotation {

    /** Default guardian-set cool-down: 7 days, in seconds (§4.3 clause 5). */
    public static final long DEFAULT_COOLDOWN_SECONDS = 7L * 24 * 60 * 60;

    /** Allowance for a Rotation Claim dated slightly ahead of the verifier's clock. */
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 5L * 60;

    private NostrRotation() {}

    // --- builders ----------------------------------------------

    /** Build an unsigned kind 30101 Guardian Set (signed by the root identity). */
    public static NostrEvent guardianSet(List<String> guardians, int threshold, long createdAt) {
        if (guardians == null || guardians.isEmpty()) {
            throw new IllegalArgumentException("a guardian set needs at least one guardian");
        }
        List<String> normalized = new ArrayList<>(guardians.size());
        for (String g : guardians) normalized.add(NostrKeys.normalizePubkey(g));
        if (new HashSet<>(normalized).size() != normalized.size()) {
            throw new IllegalArgumentException("duplicate guardian");
        }
        if (threshold < 1 || threshold > normalized.size()) {
            throw new IllegalArgumentException("threshold must be in 1..N");
        }
        List<List<String>> tags = new ArrayList<>();
        tags.add(tag("d", "guardians"));
        for (String g : normalized) tags.add(tag("p", g));
        tags.add(tag("threshold", String.valueOf(threshold)));
        return NostrEvent.unsigned(NostrKinds.GUARDIAN_SET, tags, "", createdAt);
    }

    /**
     * Build an unsigned kind 30103 Rotation Claim (signed by the NEW key).
     *
     * @param prevSigHex a self-authorising {@code prev-sig} (see {@link #prevSig}),
     *                   or {@code null} for the guardian path
     */
    public static NostrEvent rotationClaim(String oldPubkey, String reason, String prevSigHex, long createdAt) {
        String old = NostrKeys.normalizePubkey(oldPubkey);
        if (reason == null || !NostrKinds.ROTATION_REASONS.contains(reason)) {
            throw new IllegalArgumentException("reason must be lost|compromised|planned");
        }
        List<List<String>> tags = new ArrayList<>();
        tags.add(tag("d", old));
        tags.add(tag("p", old));
        tags.add(tag("reason", reason));
        if (prevSigHex != null) tags.add(tag("prev-sig", prevSigHex));
        return NostrEvent.unsigned(NostrKinds.ROTATION_CLAIM, tags, "", createdAt);
    }

    /** Build an unsigned kind 30102 Rotation Attestation (signed by a GUARDIAN). */
    public static NostrEvent rotationAttestation(String oldPubkey, String newPubkey, String method, long createdAt) {
        String old = NostrKeys.normalizePubkey(oldPubkey);
        String next = NostrKeys.normalizePubkey(newPubkey);
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("a method is required");
        }
        List<List<String>> tags = new ArrayList<>();
        tags.add(tag("d", old));
        tags.add(tag("p", old));
        tags.add(tag("new", next));
        tags.add(tag("method", method));
        return NostrEvent.unsigned(NostrKinds.ROTATION_ATTESTATION, tags, "", createdAt);
    }

    /**
     * A {@code prev-sig}: BIP-340 by the old key over the 32 raw bytes of the new
     * x-only pubkey (§4.2). Uses an all-zero aux_rand so it is reproducible.
     */
    public static String prevSig(String newPubkeyHex, String oldSecretHex) {
        byte[] msg = NostrKeys.fromHex(NostrKeys.normalizePubkey(newPubkeyHex));
        byte[] sec = NostrKeys.fromHex(oldSecretHex);
        return NostrKeys.toHex(Bip340.sign(msg, sec, new byte[32]));
    }

    // --- the acceptance rule (§4.3) ---------------------------

    public static final class Verdict {
        public final boolean accepted;
        public final String reason;
        /** On acceptance: the successor key a client should migrate to. */
        public final String newKey;
        /** On acceptance: the key being rotated away from. */
        public final String oldKey;
        Verdict(boolean accepted, String reason, String newKey, String oldKey) {
            this.accepted = accepted;
            this.reason = reason;
            this.newKey = newKey;
            this.oldKey = oldKey;
        }
        static Verdict reject(String reason) { return new Verdict(false, reason, null, null); }
        static Verdict accept(String reason, String newKey, String oldKey) {
            return new Verdict(true, reason, newKey, oldKey);
        }
    }

    public static final class Options {
        public long cooldownSeconds = DEFAULT_COOLDOWN_SECONDS;
        /** Verifier's "now" (unix seconds); a claim dated beyond this + skew is rejected. Null disables the check. */
        public Long now = null;
        public long clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
    }

    public static Verdict evaluate(List<NostrEvent> events) {
        return evaluate(events, new Options());
    }

    /**
     * Decide whether some {@code new} key is the accepted successor of some
     * {@code old} key. Assumes every event is already well-formed and its
     * signature and id verified — run {@link NostrEvent#verify} on each first.
     *
     * Mirrors {@code did-vectors/acceptance.py}.
     */
    public static Verdict evaluate(List<NostrEvent> events, Options opts) {
        // clause 4: a Rotation Claim (kind 30103). Take the earliest.
        NostrEvent claim = null;
        for (NostrEvent e : events) {
            if (e.getKind() != NostrKinds.ROTATION_CLAIM) continue;
            if (claim == null || e.getCreatedAt() < claim.getCreatedAt()) claim = e;
        }
        if (claim == null) return Verdict.reject("clause 4: no kind 30103 Rotation Claim");

        String old = claim.firstTag("d");
        String next = claim.getPubkey();
        long ct = claim.getCreatedAt();
        if (old == null) return Verdict.reject("clause 4: Rotation Claim has no `d` (old pubkey)");
        if (next.equals(old)) {
            return Verdict.reject("clause 4: Rotation Claim does not name a distinct successor key");
        }
        if (opts.now != null && ct > opts.now + opts.clockSkewSeconds) {
            return Verdict.reject("clause 5: Rotation Claim is dated in the future");
        }

        // clause 4 (self-authorised): a valid prev-sig by old over the new pubkey.
        String ps = claim.firstTag("prev-sig");
        if (ps != null) {
            boolean ok;
            try {
                ok = Bip340.verify(NostrKeys.fromHex(ps), NostrKeys.fromHex(next), NostrKeys.fromHex(old));
            } catch (RuntimeException e) {
                ok = false;
            }
            if (ok) return Verdict.accept("self-authorised: valid prev-sig by old over new", next, old);
            // invalid prev-sig -> ignored; fall through to the guardian path
        }

        // clause 1: a Guardian Set (kind 30101, d=guardians) signed by old.
        List<NostrEvent> gsets = new ArrayList<>();
        for (NostrEvent e : events) {
            if (e.getKind() == NostrKinds.GUARDIAN_SET
                    && old.equals(e.getPubkey())
                    && "guardians".equals(e.firstTag("d"))) {
                gsets.add(e);
            }
        }
        if (gsets.isEmpty()) return Verdict.reject("clause 1: no Guardian Set signed by old");

        // clause 5: the most recent set both current at the claim and past its cool-down.
        NostrEvent gset = null;
        for (NostrEvent g : gsets) {
            if (g.getCreatedAt() + opts.cooldownSeconds <= ct
                    && (gset == null || g.getCreatedAt() > gset.getCreatedAt())) {
                gset = g;
            }
        }
        if (gset == null) {
            return Verdict.reject("clause 5: no Guardian Set is both current at the claim and past its cool-down");
        }

        Set<String> guardians = new HashSet<>(gset.tagValues("p"));
        String mRaw = gset.firstTag("threshold");
        int threshold;
        try {
            threshold = Integer.parseInt(mRaw);
        } catch (NumberFormatException e) {
            return Verdict.reject("clause 1: Guardian Set has no valid threshold");
        }
        if (threshold < 1 || threshold > guardians.size()) {
            return Verdict.reject("clause 1: Guardian Set threshold out of range 1..N");
        }

        // clauses 2 + 3: >= M distinct guardians, each signing their own kind 30102
        //                for this old, all naming an identical new.
        Map<String, Set<String>> endorsers = new HashMap<>();
        int ignoredNonGuardian = 0;
        for (NostrEvent a : events) {
            if (a.getKind() != NostrKinds.ROTATION_ATTESTATION || !old.equals(a.firstTag("d"))) continue;
            if (!guardians.contains(a.getPubkey())) {   // clause 3
                ignoredNonGuardian++;
                continue;
            }
            String n = a.firstTag("new");
            if (n == null) continue;
            endorsers.computeIfAbsent(n, k -> new HashSet<>()).add(a.getPubkey());
        }

        int have = endorsers.getOrDefault(next, new HashSet<>()).size();
        if (have >= threshold) {
            return Verdict.accept(
                    have + " of " + threshold + " distinct guardians endorsed new", next, old);
        }
        String note = ignoredNonGuardian > 0
                ? " (" + ignoredNonGuardian + " endorsement(s) ignored: not in guardian set)" : "";
        return Verdict.reject("clause 2: " + have + " distinct guardians endorsed the claimed new key, need "
                + threshold + note);
    }

    private static List<String> tag(String... parts) {
        List<String> t = new ArrayList<>(parts.length);
        for (String p : parts) t.add(p);
        return t;
    }
}
