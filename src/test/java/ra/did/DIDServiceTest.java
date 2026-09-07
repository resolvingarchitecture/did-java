package ra.did;

import org.junit.jupiter.api.*;
import ra.did.openpgp.*;
import ra.common.Envelope;
import ra.common.content.Text;
import ra.common.identity.DID;
import ra.common.identity.PublicKey;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static ra.did.HashStrength.HASH_STRENGTH_64;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DIDServiceTest {

    private static final Logger LOG = Logger.getLogger(DIDServiceTest.class.getName());

    private static MockProducer producer;
    private static DIDService service;
    private static Properties props;
    private static boolean serviceRunning = false;

    private static String username = "AnonMasterTest";
    private static String passphrase = "1234";
    private static String content = "Key Ring Service Test";

    @BeforeAll
    public static void init() {
        LOG.info("Init...");
        props = new Properties();
        producer = new MockProducer();
        service = new DIDService(producer, null);
        serviceRunning = service.start(props);
    }

    @AfterAll
    public static void tearDown() {
        LOG.info("Teardown...");
        service.gracefulShutdown();
    }

    @Test
    @Order(1)
    public void verifyInitializedTest() {
        assertTrue(serviceRunning);
    }

    @Test
    @Order(2)
    public void generateKeyRingsCollectionTest() {
        GenerateKeyRingCollectionsRequest req = new GenerateKeyRingCollectionsRequest();
        req.keyRingImplementation = OpenPGPKeyRing.class.getName();
        req.keyRingUsername = username;
        req.keyRingPassphrase = passphrase;
        req.hashStrength = HASH_STRENGTH_64;
        req.didType = DID.DIDType.NODE;
        Envelope e = Envelope.documentFactory();
        e.addData(GenerateKeyRingCollectionsRequest.class, req);
        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_GENERATE_KEY_RINGS_COLLECTIONS);
        // Ratchet route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        File pkf = new File(service.getServiceDirectory()+"/"+req.didType.name(), req.keyRingUsername+".pkr");
        if(pkf.exists()) {
            assertTrue(pkf.delete());
        }
        File skf = new File(service.getServiceDirectory()+"/"+req.didType.name(), req.keyRingUsername+".skr");
        if(skf.exists()) {
            assertTrue(skf.delete());
        }
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        LOG.info("Key generation took: "+(end-start)+" ms.");
        assert(req.successful);
        assert(pkf.exists());
        assert(skf.exists());
        assert((end-start) < 30000); // < 30 seconds
    }

//    @Test
//    @Order(3)
//    public void generateKeyRingsTest() {
//        GenerateKeyRingRequest req = new GenerateKeyRingRequest();
//        req.keyRingImplementation = OpenPGPKeyRing.class.getName();
//        req.keyRingUsername = username;
//        req.keyRingPassphrase = passphrase;
//        req.alias = username;
//        req.aliasPassphrase = passphrase;
//        req.type = DID.Type.IDENTITY;
//        Envelope e = Envelope.documentFactory();
//        e.addData(GenerateKeyRingRequest.class, req);
//        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_GENERATE_KEY_RINGS);
//        // Ratchet Route
//        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
//        long start = new Date().getTime();
//        service.handleDocument(e);
//        long end = new Date().getTime();
//        assert(req.successful);
//        LOG.info("Key generation took: "+(end-start)+" ms.");
//        assert((end-start) < 30000); // < 30 seconds
//    }

    @Test
    @Order(4)
    public void encryptionTest() {
        EncryptRequest encReq = new EncryptRequest();
        encReq.keyRingImplementation = OpenPGPKeyRing.class.getName();
        encReq.keyRingUsername = username;
        encReq.keyRingPassphrase = passphrase;
        encReq.publicKeyAlias = username;
        encReq.didType = DID.DIDType.NODE;
        encReq.content = new Text();
        encReq.content.setBody(content.getBytes(), false, false);
        Envelope e = Envelope.documentFactory();
        e.addData(EncryptRequest.class, encReq);
        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_ENCRYPT);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        assert(encReq.successful);
        LOG.info("Encryption took: "+(end-start)+" ms.");
        String encContent = new String(encReq.content.getBody());
        LOG.info("Content: "+content+"; Encrypted: \n"+encContent);
        assertNotEquals(encContent, content);
        assert((end-start) < 30000); // < 30 seconds

        DecryptRequest decReq = new DecryptRequest();
        decReq.keyRingImplementation = OpenPGPKeyRing.class.getName();
        decReq.keyRingUsername = username;
        decReq.keyRingPassphrase = passphrase;
        decReq.alias = username;
        decReq.didType = DID.DIDType.NODE;
        decReq.content = encReq.content;
        Envelope e2 = Envelope.documentFactory();
        e2.addData(DecryptRequest.class, decReq);
        e2.addRoute(DIDService.class.getName(), DIDService.OPERATION_DECRYPT);
        // Ratchet Route
        e2.setRoute(e2.getDynamicRoutingSlip().nextRoute());
        start = new Date().getTime();
        service.handleDocument(e2);
        end = new Date().getTime();
        assert(decReq.successful);
        LOG.info("Decryption took: "+(end-start)+" ms.");
        assertEquals(new String(decReq.content.getBody()), content);
        assert((end-start) < 30000); // < 30 seconds
    }

    @Test
    @Order(5)
    public void signageTest() {
        SignRequest signRequest = new SignRequest();
        signRequest.keyRingImplementation = OpenPGPKeyRing.class.getName();
        signRequest.keyRingUsername = username;
        signRequest.keyRingPassphrase = passphrase;
        signRequest.alias = username;
        signRequest.passphrase = passphrase;
        signRequest.didType = DID.DIDType.NODE;
        signRequest.contentToSign = content.getBytes(StandardCharsets.UTF_8);
        Envelope e = Envelope.documentFactory();
        e.addData(SignRequest.class, signRequest);
        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_SIGN);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        assert(signRequest.successful);
        LOG.info("Signing took: "+(end-start)+" ms.");
        assertNotNull(signRequest.signature);

        VerifySignatureRequest verifySignatureRequest = new VerifySignatureRequest();
        verifySignatureRequest.keyRingImplementation = OpenPGPKeyRing.class.getName();
        verifySignatureRequest.keyRingUsername = username;
        verifySignatureRequest.keyRingPassphrase = passphrase;
        verifySignatureRequest.alias = username;
        verifySignatureRequest.type = DID.DIDType.NODE;
        verifySignatureRequest.contentSigned = content.getBytes(StandardCharsets.UTF_8);
        verifySignatureRequest.signature = signRequest.signature;
        Envelope e2 = Envelope.documentFactory();
        e2.addData(VerifySignatureRequest.class, verifySignatureRequest);
        e2.addRoute(DIDService.class.getName(), DIDService.OPERATION_VERIFY_SIGNATURE);
        // Ratchet Route
        e2.setRoute(e2.getDynamicRoutingSlip().nextRoute());
        start = new Date().getTime();
        service.handleDocument(e2);
        end = new Date().getTime();
        assert(verifySignatureRequest.successful);
        LOG.info("Signature verification took: "+(end-start)+" ms.");
        assert(verifySignatureRequest.verified);
    }

    @Test
    @Order(6)
    public void symmetricEncryptionTest() {
        EncryptSymmetricRequest req1 = new EncryptSymmetricRequest();
        req1.keyRingImplementation = OpenPGPKeyRing.class.getName();
        Text txt = new Text(content.getBytes(StandardCharsets.UTF_8));
        txt.setEncryptionPassphrase(passphrase);
        req1.content = txt;
        Envelope e = Envelope.documentFactory();
        e.addData(EncryptSymmetricRequest.class, req1);
        e.addRoute(DIDService.class.getName(), DIDService.OPERATION_ENCRYPT_SYMMETRIC);
        // Ratchet Route
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        long start = new Date().getTime();
        service.handleDocument(e);
        long end = new Date().getTime();
        assert(req1.successful);
        LOG.info("Symmetric encryption took: "+(end-start)+" ms.");
        assertNotEquals(req1.content.getBody(), content.getBytes(StandardCharsets.UTF_8));
        LOG.info("Encrypted body: \n\t"+new String(req1.content.getBody()));

        DecryptSymmetricRequest req2 = new DecryptSymmetricRequest();
        req2.keyRingImplementation = OpenPGPKeyRing.class.getName();
        req2.content = txt;
        Envelope e2 = Envelope.documentFactory();
        e2.addData(DecryptSymmetricRequest.class, req2);
        e2.addRoute(DIDService.class.getName(), DIDService.OPERATION_DECRYPT_SYMMETRIC);
        // Ratchet Route
        e2.setRoute(e2.getDynamicRoutingSlip().nextRoute());
        start = new Date().getTime();
        service.handleDocument(e2);
        end = new Date().getTime();
        assert(req2.successful);
        LOG.info("Symmetric decryption took: "+(end-start)+" ms.");
        assertEquals(new String(req1.content.getBody()), content);
        LOG.info("Decrypted body: \n\t"+new String(req1.content.getBody()));
    }

//    @Test
//    @Order(7)
//    public void vouchTest() {
//
//    }
//
//    @Test
//    @Order(8)
//    public void yubiKeyFindTest() {
//        Properties p = new Properties();
//        YubiKeyRing ring = new YubiKeyRing();
//        ring.init(p);
//
//    }

    @Test
    @Order(8)
    public void createIdentity() {
        // The service persists identities under ~/.ra; clear any Bob from a prior run
        // (the .json record and the OpenPGP key rings) so this test is idempotent.
        File identityDir = new File(service.getServiceDirectory(), DID.DIDType.IDENTITY.name());
        for (String f : new String[]{"Bob.json", "Bob.pkr", "Bob.skr"}) {
            File file = new File(identityDir, f);
            if (file.exists()) assertTrue(file.delete());
        }

        DID did = new DID();
        did.setUsername("Bob");
        did.setPassphrase("1234");
        did.setDidType(DID.DIDType.IDENTITY);
        Envelope e = Envelope.documentFactory();
        e.addData(DID.class, did);
        e.addNVP("identityType", DID.DIDType.IDENTITY.name());
        e.addRoute(DIDService.class, DIDService.OPERATION_SAVE_IDENTITY);
        service.handleDocument(e);
        assertNotNull(did.getPublicKey());
        assert(did.getPublicKey().isIdentityKey());
        assertNotNull(did.getPublicKey().getAddress());
        assertNotNull(did.getPublicKey().getFingerprint());
    }

//    @Test
//    @Order(9)
//    public void createContact() {
//        DID did = new DID();
//        did.setUsername("Charlie");
//        did.setDidType(DID.DIDType.CONTACT);
//
//    }

}
