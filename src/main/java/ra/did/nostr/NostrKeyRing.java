package ra.did.nostr;

import java.util.Properties;
import java.util.logging.Logger;

/**
 * {@link IdentityKeyRing} backed by BIP-340 Schnorr over secp256k1
 * (ACINQ {@code secp256k1-kmp} / Bitcoin Core libsecp256k1), the Nostr-compatible
 * identity primitive from DID {@code DESIGN.md}.
 *
 * <p>This is the successor to {@link ra.did.openpgp.OpenPGPKeyRing}. It is additive:
 * {@code DIDService} caches key-ring implementations by class name, so this can
 * run alongside the OpenPGP one during migration (§6.4).
 *
 * <p>Scope of this first cut: keygen, event signing and verification, and the
 * NIP-19 / {@code did:nostr} encodings. Persistence and encryption at rest (§6.3),
 * the attestation / guardian / rotation builders (§3–§4), and the new
 * {@code DIDService} bus operations (§7.3) are separate, still-open items.
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
}
