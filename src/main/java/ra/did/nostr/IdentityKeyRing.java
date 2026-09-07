package ra.did.nostr;

import java.util.Properties;

/**
 * The narrower successor to {@link ra.did.openpgp.KeyRing} (DID {@code DESIGN.md} §7.3):
 * keygen, sign, verify, encode — over a single secp256k1 / BIP-340 identity,
 * with no OpenPGP types in the signature.
 *
 * <p>The legacy {@code KeyRing} interface is PGP-typed
 * ({@code PGPPublicKeyRingCollection}, {@code throws PGPException}) and cannot
 * express a Nostr keyring. During migration an implementation may implement both;
 * new code should depend only on this.
 *
 * <p>Implementations are cached by the service at start-up and shared across
 * threads, so they MUST be thread-safe.
 */
public interface IdentityKeyRing {

    boolean init(Properties properties);

    /** A fresh identity from the platform CSPRNG. */
    NostrIdentity generateIdentity();

    /**
     * Sign {@code event} in place with {@code signer}'s key, (re)computing
     * {@code pubkey}, {@code id} and {@code sig}. {@code signer} MUST hold a secret.
     */
    NostrEvent sign(NostrEvent event, NostrIdentity signer);

    /** Verify an event against the four-step order (§2.2). */
    NostrEvent.VerifyResult verify(NostrEvent event);

    /** x-only hex → {@code npub1…} (NIP-19). */
    String npub(NostrIdentity identity);

    /**
     * secret → {@code nsec1…} (NIP-19). Export only: the caller MUST require an
     * explicit, separately-confirmed user action (§6.3) and MUST NOT surface the
     * result incidentally.
     */
    String nsec(NostrIdentity identity);

    /** x-only hex → {@code did:nostr:<hex>} (§5.1). */
    String didNostr(NostrIdentity identity);
}
