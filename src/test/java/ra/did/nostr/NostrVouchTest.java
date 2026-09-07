package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The {@code vouch} builders (attestations + guardian rotation), built and signed
 * end to end — not depending on the shared vectors.
 */
public class NostrVouchTest {

    private static NostrKeyRing ring() {
        NostrKeyRing r = new NostrKeyRing();
        r.init(new Properties());
        return r;
    }

    @Test
    public void attestationBuildsVerifiesAndParses() {
        NostrKeyRing ring = ring();
        NostrIdentity attester = ring.generateIdentity();
        NostrIdentity subject = ring.generateIdentity();

        NostrEvent ev = NostrAttestations.attestation(
                subject.getPublicKeyHex(),
                Arrays.asList(
                        new NostrAttestations.Claim("name", "alice"),
                        new NostrAttestations.Claim("nip05", "alice@example.com")),
                "in-person", null, 1_700_000_000L);
        ring.sign(ev, attester);

        NostrEvent.VerifyResult r = ev.verify();
        assertTrue(r.ok, "step " + r.step + ": " + r.reason);

        NostrAttestations.Parsed p = NostrAttestations.parse(ev);
        assertEquals(attester.getPublicKeyHex(), p.attester);
        assertEquals(subject.getPublicKeyHex(), p.subject);
        assertEquals("in-person", p.method);
        assertEquals(2, p.claims.size());
        assertFalse(p.isRevocation());
    }

    @Test
    public void revocationVerifiesAndCarriesNoClaims() {
        NostrKeyRing ring = ring();
        NostrIdentity attester = ring.generateIdentity();
        NostrIdentity subject = ring.generateIdentity();
        NostrEvent ev = NostrAttestations.revocation(subject.getPublicKeyHex(), "key rotated", 1_700_000_000L);
        ring.sign(ev, attester);
        assertTrue(ev.verify().ok);
        NostrAttestations.Parsed p = NostrAttestations.parse(ev);
        assertTrue(p.isRevocation());
        assertEquals("key rotated", p.revoked);
        assertTrue(p.claims.isEmpty());
    }

    @Test
    public void attestationNeedsAtLeastOneClaim() {
        NostrIdentity s = ring().generateIdentity();
        assertThrows(IllegalArgumentException.class, () ->
                NostrAttestations.attestation(s.getPublicKeyHex(), new ArrayList<>(), "asserted", null, 1L));
    }

    @Test
    public void guardianRotationHappyPathAcceptsPastTheCooldown() {
        NostrKeyRing ring = ring();
        NostrIdentity old = ring.generateIdentity();
        NostrIdentity next = ring.generateIdentity();
        NostrIdentity g1 = ring.generateIdentity();
        NostrIdentity g2 = ring.generateIdentity();
        NostrIdentity g3 = ring.generateIdentity();

        long t0 = 1_700_000_000L;
        long claimAt = t0 + NostrRotation.DEFAULT_COOLDOWN_SECONDS + 3600;

        List<NostrEvent> events = new ArrayList<>();
        events.add(sign(ring, NostrRotation.guardianSet(
                Arrays.asList(g1.getPublicKeyHex(), g2.getPublicKeyHex(), g3.getPublicKeyHex()), 2, t0), old));
        events.add(sign(ring, NostrRotation.rotationClaim(old.getPublicKeyHex(), "lost", null, claimAt), next));
        events.add(sign(ring, NostrRotation.rotationAttestation(
                old.getPublicKeyHex(), next.getPublicKeyHex(), "in-person", claimAt + 60), g1));
        events.add(sign(ring, NostrRotation.rotationAttestation(
                old.getPublicKeyHex(), next.getPublicKeyHex(), "existing-channel", claimAt + 120), g2));

        for (NostrEvent e : events) assertTrue(e.verify().ok, e.verify().reason);

        NostrRotation.Verdict v = NostrRotation.evaluate(events);
        assertTrue(v.accepted, v.reason);
        assertEquals(next.getPublicKeyHex(), v.newKey);
        assertEquals(old.getPublicKeyHex(), v.oldKey);
    }

    @Test
    public void freshGuardianSetInsideCooldownDoesNotCount() {
        NostrKeyRing ring = ring();
        NostrIdentity old = ring.generateIdentity();
        NostrIdentity next = ring.generateIdentity();
        NostrIdentity g1 = ring.generateIdentity();
        NostrIdentity g2 = ring.generateIdentity();

        long claimAt = 1_800_000_000L;
        List<NostrEvent> events = new ArrayList<>();
        events.add(sign(ring, NostrRotation.guardianSet(
                Arrays.asList(g1.getPublicKeyHex(), g2.getPublicKeyHex()), 2, claimAt - 3600), old));
        events.add(sign(ring, NostrRotation.rotationClaim(old.getPublicKeyHex(), "compromised", null, claimAt), next));
        events.add(sign(ring, NostrRotation.rotationAttestation(
                old.getPublicKeyHex(), next.getPublicKeyHex(), "existing-channel", claimAt + 60), g1));
        events.add(sign(ring, NostrRotation.rotationAttestation(
                old.getPublicKeyHex(), next.getPublicKeyHex(), "existing-channel", claimAt + 90), g2));

        assertFalse(NostrRotation.evaluate(events).accepted);
    }

    @Test
    public void selfAuthorisedRotationViaPrevSigNeedsNoGuardians() {
        NostrKeyRing ring = ring();
        NostrIdentity old = ring.generateIdentity();
        NostrIdentity next = ring.generateIdentity();

        String ps = NostrRotation.prevSig(next.getPublicKeyHex(), old.secretHex());
        NostrEvent claim = sign(ring,
                NostrRotation.rotationClaim(old.getPublicKeyHex(), "planned", ps, 1_700_000_000L), next);

        assertTrue(claim.verify().ok);
        NostrRotation.Verdict v = NostrRotation.evaluate(Arrays.asList(claim));
        assertTrue(v.accepted, v.reason);
        assertEquals(next.getPublicKeyHex(), v.newKey);
    }

    private static NostrEvent sign(NostrKeyRing ring, NostrEvent e, NostrIdentity signer) {
        return ring.sign(e, signer);
    }
}
