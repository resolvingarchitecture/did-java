package ra.did.nostr;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * {@link IdentityKeyRing} backed by BIP-340 Schnorr over secp256k1
 * (ACINQ {@code secp256k1-kmp} / Bitcoin Core libsecp256k1), the Nostr-compatible
 * identity primitive from DID {@code DESIGN.md}.
 *
 * <p>This is the successor to {@link ra.did.openpgp.OpenPGPKeyRing}. It is additive:
 * {@code DIDService} caches key-ring implementations by class name, so the OpenPGP
 * keyring (encrypt/decrypt/sign of legacy material) can still run alongside it.
 *
 * <p>Covers keygen, signing and verification, the NIP-19 / {@code did:nostr}
 * encodings, and — once {@link #setStore} is called — encrypted-at-rest
 * persistence (§6.3) via {@link NostrIdentityStore}. Still open: the remaining
 * query/export bus operations and Android Keystore wrapping.
 */
public class NostrKeyRing implements IdentityKeyRing {

    private static final Logger LOG = Logger.getLogger(NostrKeyRing.class.getName());

    /**
     * When {@code true}, {@link #sign} uses an all-zero BIP-340 aux_rand, making
     * signatures byte-for-byte reproducible (this is how {@code did-vectors} is
     * generated). Default {@code false} — production signs with fresh randomness.
     */
    public static final String PROP_DETERMINISTIC_SIGNATURES = "ra.did.nostr.deterministicSignatures";

    private volatile boolean deterministicSignatures = false;
    private volatile NostrIdentityStore store;

    @Override
    public boolean init(Properties properties) {
        if (properties != null) {
            deterministicSignatures = Boolean.parseBoolean(
                    properties.getProperty(PROP_DETERMINISTIC_SIGNATURES, "false"));
        }
        // Touch the native library early so a load failure surfaces at start-up.
        try {
            Bip340.generateSecretKey();
        } catch (Throwable t) {
            LOG.severe("BIP-340 backend unavailable: " + t.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public NostrIdentity generateIdentity() {
        return NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
    }

    @Override
    public NostrEvent sign(NostrEvent event, NostrIdentity signer) {
        if (event == null) throw new IllegalArgumentException("event required");
        if (signer == null || !signer.hasSecret()) {
            throw new IllegalArgumentException("a signer with a secret key is required");
        }
        byte[] aux = deterministicSignatures ? new byte[32] : null;
        return event.sign(signer.secretHex(), aux);
    }

    @Override
    public NostrEvent.VerifyResult verify(NostrEvent event) {
        if (event == null) return NostrEvent.VerifyResult.fail(1, "event is null");
        return event.verify();
    }

    @Override
    public String npub(NostrIdentity identity) {
        return identity.npub();
    }

    @Override
    public String nsec(NostrIdentity identity) {
        return NostrKeys.secretToNsec(identity.secretHex());
    }

    @Override
    public String didNostr(NostrIdentity identity) {
        return identity.didNostr();
    }

    // --- encrypted-at-rest persistence (§6.3) ------------------

    /** Attach the on-disk store. Until this is set, persistence is unavailable. */
    public void setStore(NostrIdentityStore store) {
        this.store = store;
    }

    public boolean hasStore() {
        return store != null;
    }

    /**
     * Seal {@code identity}'s secret under {@code passphrase} and persist it. The
     * caller-supplied passphrase string cannot be zeroed here (it lives in the
     * String pool); pass a value you are willing to have linger for the JVM's
     * lifetime, or a per-call throwaway.
     */
    public void persist(NostrIdentity identity, String passphrase) {
        requireStore();
        char[] p = passphrase == null ? null : passphrase.toCharArray();
        try {
            store.save(identity, p);
        } finally {
            if (p != null) Arrays.fill(p, '\0');
        }
    }

    /** Load and decrypt a persisted identity, or {@code null} if none is stored. */
    public NostrIdentity loadIdentity(String pubkeyHex, String passphrase) throws GeneralSecurityException {
        requireStore();
        char[] p = passphrase == null ? null : passphrase.toCharArray();
        try {
            return store.load(pubkeyHex, p);
        } finally {
            if (p != null) Arrays.fill(p, '\0');
        }
    }

    public boolean isPersisted(String pubkeyHex) {
        return store != null && store.exists(pubkeyHex);
    }

    public boolean deletePersisted(String pubkeyHex) {
        requireStore();
        return store.delete(pubkeyHex);
    }

    public List<String> persistedIdentities() {
        requireStore();
        return store.list();
    }

    private void requireStore() {
        if (store == null) {
            throw new IllegalStateException("no NostrIdentityStore configured (call setStore)");
        }
    }
}
