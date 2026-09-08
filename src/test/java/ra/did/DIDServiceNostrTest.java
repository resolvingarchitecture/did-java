package ra.did;

import org.junit.jupiter.api.*;
import ra.common.Envelope;
import ra.did.nostr.*;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The ra.did.nostr bus operations through {@link DIDService}: generate identity,
 * attest (vouch), designate guardians, claim + attest a rotation, verify it.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DIDServiceNostrTest {

    private static DIDService service;

    @BeforeAll
    public static void init() {
        service = new DIDService(new MockProducer(), null);
        assertTrue(service.start(new Properties()));
        // clean the encrypted identity store so persistence tests are idempotent
        File nostrDir = new File(service.getServiceDirectory(), "NOSTR");
        File[] files = nostrDir.listFiles();
        if (files != null) for (File f : files) f.delete();
    }

    @AfterAll
    public static void tearDown() {
        service.gracefulShutdown();
    }

    @SuppressWarnings("unchecked")
    private static <T> T call(String op, Class<T> type, T req) {
        Envelope e = Envelope.documentFactory();
        e.addData(type, req);
        e.addRoute(DIDService.class.getName(), op);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        service.handleDocument(e);
        return (T) e.getData(type);
    }

    private static String newIdentity() {
        GenerateNostrIdentityRequest r = call(DIDService.OPERATION_GENERATE_NOSTR_IDENTITY,
                GenerateNostrIdentityRequest.class, new GenerateNostrIdentityRequest());
        assertTrue(r.successful, "generate failed: " + r.statusCode);
        assertNotNull(r.publicKeyHex);
        assertTrue(r.npub.startsWith("npub1"));
        assertTrue(r.did.startsWith("did:nostr:"));
        assertNotNull(r.secretKeyHex);
        return r.publicKeyHex;
    }

    @Test
    @Order(1)
    public void generateIdentity() {
        newIdentity();
    }

    @Test
    @Order(2)
    public void attestProducesAVerifiableKind30100() {
        String attester = newIdentity();
        String subject = newIdentity();

        AttestRequest r = new AttestRequest();
        r.signerPubkey = attester;
        r.subjectPubkey = subject;
        r.claims = new LinkedHashMap<>();
        r.claims.put("name", "alice");
        r.claims.put("nip05", "alice@example.com");
        r.method = "in-person";
        r = call(DIDService.OPERATION_VOUCH, AttestRequest.class, r);

        assertTrue(r.successful, "attest failed: " + r.statusCode + " " + r.errorMessage);
        assertEquals(NostrKinds.IDENTITY_ATTESTATION, r.event.getKind());
        assertEquals(attester, r.event.getPubkey());
        assertTrue(r.event.verify().ok);
        assertNotNull(r.eventJson);

        NostrAttestations.Parsed p = NostrAttestations.parse(r.event);
        assertEquals(subject, p.subject);
        assertEquals("in-person", p.method);
        assertEquals(2, p.claims.size());
    }

    @Test
    @Order(3)
    public void attestRejectsUnknownSigner() {
        AttestRequest r = new AttestRequest();
        r.signerPubkey = "0000000000000000000000000000000000000000000000000000000000000000";
        r.subjectPubkey = newIdentity();
        r.claims.put("name", "x");
        r = call(DIDService.OPERATION_ATTEST, AttestRequest.class, r);
        assertFalse(r.successful);
        assertEquals(NostrRequest.SIGNER_NOT_FOUND, r.statusCode);
    }

    @Test
    @Order(4)
    public void guardianRotationEndToEnd() {
        String oldKey = newIdentity();
        String newKey = newIdentity();
        String g1 = newIdentity();
        String g2 = newIdentity();
        String g3 = newIdentity();

        long t0 = 1_700_000_000L;
        long claimAt = t0 + NostrRotation.DEFAULT_COOLDOWN_SECONDS + 3600;

        DesignateGuardiansRequest gs = new DesignateGuardiansRequest();
        gs.rootPubkey = oldKey;
        gs.guardians = new ArrayList<>(Arrays.asList(g1, g2, g3));
        gs.threshold = 2;
        gs.createdAt = t0;
        gs = call(DIDService.OPERATION_DESIGNATE_GUARDIANS, DesignateGuardiansRequest.class, gs);
        assertTrue(gs.successful, "guardian set failed: " + gs.statusCode);

        ClaimRotationRequest claim = new ClaimRotationRequest();
        claim.newPubkey = newKey;
        claim.oldPubkey = oldKey;
        claim.reason = "lost";
        claim.createdAt = claimAt;
        claim = call(DIDService.OPERATION_CLAIM_ROTATION, ClaimRotationRequest.class, claim);
        assertTrue(claim.successful, "claim failed: " + claim.statusCode);

        List<NostrEvent> bag = new ArrayList<>();
        bag.add(gs.event);
        bag.add(claim.event);
        for (String g : new String[]{g1, g2}) {
            AttestRotationRequest ar = new AttestRotationRequest();
            ar.guardianPubkey = g;
            ar.oldPubkey = oldKey;
            ar.newPubkey = newKey;
            ar.method = "in-person";
            ar.createdAt = claimAt + 60;
            ar = call(DIDService.OPERATION_ATTEST_ROTATION, AttestRotationRequest.class, ar);
            assertTrue(ar.successful, "rotation attestation failed: " + ar.statusCode);
            bag.add(ar.event);
        }

        VerifyRotationRequest v = new VerifyRotationRequest();
        v.events = bag;
        v = call(DIDService.OPERATION_VERIFY_ROTATION, VerifyRotationRequest.class, v);
        assertTrue(v.successful, v.errorMessage);
        assertTrue(v.accepted, v.reason);
        assertEquals(newKey, v.newKey);
        assertEquals(oldKey, v.oldKey);
    }

    @Test
    @Order(5)
    public void selfAuthorisedRotationViaPrevSig() {
        String oldKey = newIdentity();
        String newKey = newIdentity();

        ClaimRotationRequest claim = new ClaimRotationRequest();
        claim.newPubkey = newKey;
        claim.oldPubkey = oldKey;
        claim.reason = "planned";
        claim.oldPubkeyForPrevSig = oldKey; // old identity is held, so a prev-sig can be attached
        claim.createdAt = 1_700_000_000L;
        claim = call(DIDService.OPERATION_CLAIM_ROTATION, ClaimRotationRequest.class, claim);
        assertTrue(claim.successful, "claim failed: " + claim.statusCode);

        VerifyRotationRequest v = new VerifyRotationRequest();
        v.events = new ArrayList<>(Arrays.asList(claim.event));
        v = call(DIDService.OPERATION_VERIFY_ROTATION, VerifyRotationRequest.class, v);
        assertTrue(v.accepted, v.reason);
        assertEquals(newKey, v.newKey);
    }

    @Test
    @Order(6)
    public void importedSecretRoundTrips() {
        GenerateNostrIdentityRequest a = call(DIDService.OPERATION_GENERATE_NOSTR_IDENTITY,
                GenerateNostrIdentityRequest.class, new GenerateNostrIdentityRequest());

        GenerateNostrIdentityRequest b = new GenerateNostrIdentityRequest();
        b.importSecretKeyHex = a.secretKeyHex;
        b = call(DIDService.OPERATION_GENERATE_NOSTR_IDENTITY, GenerateNostrIdentityRequest.class, b);
        assertTrue(b.successful);
        assertEquals(a.publicKeyHex, b.publicKeyHex);
    }

    @Test
    @Order(7)
    public void generateWithPassphrasePersistsAndReloadsInAFreshService() {
        GenerateNostrIdentityRequest g = new GenerateNostrIdentityRequest();
        g.passphrase = "unlock me";
        g = call(DIDService.OPERATION_GENERATE_NOSTR_IDENTITY, GenerateNostrIdentityRequest.class, g);
        assertTrue(g.successful);
        assertTrue(g.persisted, "should have been sealed to disk");
        String pub = g.publicKeyHex;
        assertNull(g.passphrase, "passphrase must be cleared from the request");

        // a brand-new service instance over the same directory
        DIDService fresh = new DIDService(new MockProducer(), null);
        assertTrue(fresh.start(new Properties()));

        LoadNostrIdentityRequest bad = new LoadNostrIdentityRequest();
        bad.pubkey = pub;
        bad.passphrase = "wrong";
        Envelope e1 = Envelope.documentFactory();
        e1.addData(LoadNostrIdentityRequest.class, bad);
        e1.addRoute(DIDService.class.getName(), DIDService.OPERATION_LOAD_NOSTR_IDENTITY);
        e1.setRoute(e1.getDynamicRoutingSlip().nextRoute());
        fresh.handleDocument(e1);
        bad = (LoadNostrIdentityRequest) e1.getData(LoadNostrIdentityRequest.class);
        assertFalse(bad.successful);
        assertEquals(LoadNostrIdentityRequest.BAD_PASSPHRASE, bad.statusCode);

        LoadNostrIdentityRequest ok = new LoadNostrIdentityRequest();
        ok.pubkey = pub;
        ok.passphrase = "unlock me";
        Envelope e2 = Envelope.documentFactory();
        e2.addData(LoadNostrIdentityRequest.class, ok);
        e2.addRoute(DIDService.class.getName(), DIDService.OPERATION_LOAD_NOSTR_IDENTITY);
        e2.setRoute(e2.getDynamicRoutingSlip().nextRoute());
        fresh.handleDocument(e2);
        ok = (LoadNostrIdentityRequest) e2.getData(LoadNostrIdentityRequest.class);
        assertTrue(ok.successful, "load failed: " + ok.statusCode);
        assertEquals(pub, ok.publicKeyHex);

        // the loaded identity can now sign on the fresh service
        AttestRequest at = new AttestRequest();
        at.signerPubkey = pub;
        at.subjectPubkey = pub;
        at.claims.put("name", "self");
        Envelope e3 = Envelope.documentFactory();
        e3.addData(AttestRequest.class, at);
        e3.addRoute(DIDService.class.getName(), DIDService.OPERATION_ATTEST);
        e3.setRoute(e3.getDynamicRoutingSlip().nextRoute());
        fresh.handleDocument(e3);
        at = (AttestRequest) e3.getData(AttestRequest.class);
        assertTrue(at.successful, "attest on reloaded identity failed: " + at.statusCode);
        assertTrue(at.event.verify().ok);

        fresh.gracefulShutdown();
    }

    @Test
    @Order(8)
    public void deleteRemovesFromMemoryAndDisk() {
        GenerateNostrIdentityRequest g = new GenerateNostrIdentityRequest();
        g.passphrase = "pw";
        g = call(DIDService.OPERATION_GENERATE_NOSTR_IDENTITY, GenerateNostrIdentityRequest.class, g);
        String pub = g.publicKeyHex;

        DeleteNostrIdentityRequest d = new DeleteNostrIdentityRequest();
        d.pubkey = pub;
        d = call(DIDService.OPERATION_DELETE_NOSTR_IDENTITY, DeleteNostrIdentityRequest.class, d);
        assertTrue(d.successful);
        assertTrue(d.removedFromMemory);
        assertTrue(d.deletedFromDisk);

        // signing with it now fails
        AttestRequest at = new AttestRequest();
        at.signerPubkey = pub;
        at.subjectPubkey = pub;
        at.claims.put("name", "x");
        at = call(DIDService.OPERATION_ATTEST, AttestRequest.class, at);
        assertFalse(at.successful);
        assertEquals(NostrRequest.SIGNER_NOT_FOUND, at.statusCode);
    }
}
