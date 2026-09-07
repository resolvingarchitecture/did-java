package ra.did.openpgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import java.io.IOException;
import java.util.Properties;

/**
 * Interface for implementing all KeyRings.
 * Ensure they are thread safe as they are cached in {@link ra.did.DIDService} on startup and shared across all incoming threads.
 */
public interface KeyRing {

    boolean init(Properties properties);

    void generateKeyRingCollections(GenerateKeyRingCollectionsRequest r) throws IOException, PGPException;

    PGPPublicKeyRingCollection getPublicKeyRingCollection(String location, String username) throws IOException, PGPException;

    void createKeyRings(String location, String keyRingUsername, String keyRingPassphrase, String alias, String aliasPassphrase, int hashStrength, String keyRingImplementation) throws IOException, PGPException;

    PGPPublicKey getPublicKey(PGPPublicKeyRingCollection c, String keyAlias, boolean master) throws PGPException;

    void encrypt(EncryptRequest r) throws IOException, PGPException;

    void decrypt(DecryptRequest r) throws IOException, PGPException;

    void sign(SignRequest r) throws IOException, PGPException;

    void verifySignature(VerifySignatureRequest r) throws IOException, PGPException;

}
