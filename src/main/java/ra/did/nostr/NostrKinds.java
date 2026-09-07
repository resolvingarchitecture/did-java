package ra.did.nostr;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The four DID event kinds and their kind-specific validation
 * (DID {@code DESIGN.md} §3–§4 — verification step 4).
 *
 * The kind numbers are PROVISIONAL (DESIGN §8) and live here, in one place, so a
 * reassignment through the NIP process is a one-line change.
 */
public final class NostrKinds {

    public static final int IDENTITY_ATTESTATION = 30100;
    public static final int GUARDIAN_SET = 30101;
    public static final int ROTATION_ATTESTATION = 30102;
    public static final int ROTATION_CLAIM = 30103;

    public static final int[] DID_KINDS = {
            IDENTITY_ATTESTATION, GUARDIAN_SET, ROTATION_ATTESTATION, ROTATION_CLAIM
    };

    /** §3.2 verification methods. An unknown method is treated as no stronger than {@code asserted}. */
    public static final List<String> METHODS = unmodifiable(
            "in-person", "qr", "existing-channel", "openpgp-migration", "guardian", "asserted");

    /** §3.3 reserved claim attributes ({@code claim} attributes are otherwise open). */
    public static final List<String> CLAIM_ATTRIBUTES = unmodifiable("name", "same-as", "nip05", "not");

    /** §4.2 rotation reasons. */
    public static final List<String> ROTATION_REASONS = unmodifiable("lost", "compromised", "planned");

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");

    private NostrKinds() {}

    public static boolean isDidKind(int kind) {
        for (int k : DID_KINDS) if (k == kind) return true;
        return false;
    }

    /** Result of step-4 validation: {@code ok}, and a reason when it is not. */
    public static final class Check {
        public final boolean ok;
        public final String reason;
        private Check(boolean ok, String reason) { this.ok = ok; this.reason = reason; }
        static Check ok() { return new Check(true, null); }
        static Check fail(String reason) { return new Check(false, reason); }
    }

    /**
     * Step 4: kind-specific validation. An event whose kind is not a DID kind
     * passes unconditionally — this library does not police generic Nostr events.
     */
    public static Check validate(NostrEvent ev) {
        switch (ev.getKind()) {
            case IDENTITY_ATTESTATION: return validateAttestation(ev);
            case GUARDIAN_SET:         return validateGuardianSet(ev);
            case ROTATION_ATTESTATION: return validateRotationAttestation(ev);
            case ROTATION_CLAIM:       return validateRotationClaim(ev);
            default:                   return Check.ok();
        }
    }

    private static Check validateAttestation(NostrEvent ev) {
        String d = ev.firstTag("d");
        String p = ev.firstTag("p");
        if (!isHex64(d)) return Check.fail("kind 30100: `d` MUST be the subject pubkey (64 lowercase hex)");
        if (!isHex64(p)) return Check.fail("kind 30100: `p` MUST be the subject pubkey (64 lowercase hex)");
        if (!d.equals(p)) return Check.fail("kind 30100: `d` and `p` MUST both be the subject pubkey");

        boolean revoked = ev.hasTag("revoked");
        List<List<String>> claims = ev.tags("claim");
        if (revoked) {
            if (!claims.isEmpty()) return Check.fail("kind 30100: a revocation MUST carry no `claim` tags");
            return Check.ok();
        }
        if (claims.isEmpty()) return Check.fail("kind 30100: requires >=1 `claim` tag");
        for (List<String> c : claims) {
            if (c.size() < 3) return Check.fail("kind 30100: each `claim` tag is [\"claim\", <attribute>, <value>]");
        }
        if (!ev.hasTag("method")) return Check.fail("kind 30100: requires a `method` tag");
        return Check.ok();
    }

    private static Check validateGuardianSet(NostrEvent ev) {
        if (!"guardians".equals(ev.firstTag("d"))) {
            return Check.fail("kind 30101: `d` MUST be the literal \"guardians\"");
        }
        List<String> guardians = ev.tagValues("p");
        if (guardians.isEmpty()) return Check.fail("kind 30101: requires >=1 `p` (guardian) tag");
        for (String g : guardians) {
            if (!isHex64(g)) return Check.fail("kind 30101: guardian pubkeys MUST be 64 lowercase hex");
        }
        if (new java.util.HashSet<>(guardians).size() != guardians.size()) {
            return Check.fail("kind 30101: duplicate guardian pubkey");
        }
        String mRaw = ev.firstTag("threshold");
        if (mRaw == null || !mRaw.matches("\\d+")) {
            return Check.fail("kind 30101: requires an integer `threshold`");
        }
        int m = Integer.parseInt(mRaw);
        if (m < 1 || m > guardians.size()) return Check.fail("kind 30101: requires 1 <= M <= N");
        return Check.ok();
    }

    private static Check validateRotationAttestation(NostrEvent ev) {
        if (!isHex64(ev.firstTag("d"))) return Check.fail("kind 30102: `d` MUST be the old pubkey (64 lowercase hex)");
        if (!isHex64(ev.firstTag("p"))) return Check.fail("kind 30102: `p` MUST be the old pubkey (64 lowercase hex)");
        if (!isHex64(ev.firstTag("new"))) return Check.fail("kind 30102: `new` MUST be the endorsed pubkey (64 lowercase hex)");
        if (!ev.hasTag("method")) return Check.fail("kind 30102: requires a `method` tag");
        return Check.ok();
    }

    private static Check validateRotationClaim(NostrEvent ev) {
        if (!isHex64(ev.firstTag("d"))) return Check.fail("kind 30103: `d` MUST be the old pubkey (64 lowercase hex)");
        if (!isHex64(ev.firstTag("p"))) return Check.fail("kind 30103: `p` MUST be the old pubkey (64 lowercase hex)");
        String reason = ev.firstTag("reason");
        if (reason == null || !ROTATION_REASONS.contains(reason)) {
            return Check.fail("kind 30103: `reason` MUST be lost|compromised|planned");
        }
        return Check.ok();
    }

    private static boolean isHex64(String s) {
        return s != null && HEX64.matcher(s).matches();
    }

    private static List<String> unmodifiable(String... values) {
        List<String> l = new ArrayList<>(values.length);
        for (String v : values) l.add(v);
        return java.util.Collections.unmodifiableList(l);
    }
}
