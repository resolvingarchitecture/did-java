package ra.did;

import org.junit.jupiter.api.Test;
import ra.common.Envelope;
import ra.common.identity.DID;
import ra.did.openpgp.EncryptRequest;
import ra.did.openpgp.GenerateKeyRingCollectionsRequest;
import ra.did.openpgp.OpenPGPKeyRing;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static ra.did.HashStrength.HASH_STRENGTH_64;

/**
 * {@code loadKeyRingImplementations()} reads {@code ra.did.KeyRings} (the key
 * {@code ra-did.config} actually sets) and tolerates an implementation that will
 * not load rather than failing service start.
 */
public class DIDServiceKeyRingConfigTest {

    private static DIDService started(Properties p) {
        DIDService s = new DIDService(new MockProducer(), null);
        assertTrue(s.start(p));
        return s;
    }

    @Test
    public void readsRaDidKeyRingsProperty() {
        Properties p = new Properties();
        p.setProperty(DIDService.PROP_KEY_RINGS, OpenPGPKeyRing.class.getName());
        DIDService s = started(p);

        // a keyring op works -> the configured implementation was loaded and cached
        GenerateKeyRingCollectionsRequest r = new GenerateKeyRingCollectionsRequest();
        r.keyRingImplementation = OpenPGPKeyRing.class.getName();
        r.keyRingUsername = "KRConfigTest";
        r.keyRingPassphrase = "pw";
        r.hashStrength = HASH_STRENGTH_64;
        r.didType = DID.DIDType.NODE;
        java.io.File pkr = new java.io.File(s.getServiceDirectory() + "/" + r.didType.name(), r.keyRingUsername + ".pkr");
        java.io.File skr = new java.io.File(s.getServiceDirectory() + "/" + r.didType.name(), r.keyRingUsername + ".skr");
        pkr.delete();
        skr.delete();

        Envelope e = Envelope.documentFactory();
        e.addData(GenerateKeyRingCollectionsRequest.class, r);
        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_GENERATE_KEY_RINGS_COLLECTIONS);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        s.handleDocument(e);
        assertTrue(r.successful, "keyring op should succeed -> impl was loaded from ra.did.KeyRings");
        s.gracefulShutdown();
    }

    @Test
    public void toleratesAnUnloadableImplementationAndFallsBack() {
        Properties p = new Properties();
        p.setProperty(DIDService.PROP_KEY_RINGS, "ra.did.openpgp.NoSuchKeyRing," + OpenPGPKeyRing.class.getName());
        DIDService s = started(p); // must not throw despite the bogus class

        EncryptRequest r = new EncryptRequest();
        r.keyRingImplementation = OpenPGPKeyRing.class.getName();
        assertNotNull(r); // the good impl is still available
        s.gracefulShutdown();
    }
}
