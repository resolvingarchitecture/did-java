package ra.did.nostr;

import fr.acinq.secp256k1.Secp256k1;

import java.security.SecureRandom;

/**
 * The identity primitive (DID {@code DESIGN.md} §1): one secp256k1 keypair,
 * x-only public key per BIP-340, 64-byte Schnorr signatures.
 *
 * A thin wrapper over ACINQ's {@code secp256k1-kmp} JNI binding to Bitcoin Core's
 * libsecp256k1 — the reviewed implementation DESIGN §1.2 requires. No BIP-340 is
 * implemented here by hand.
 *
 * All byte arrays are raw (not hex). {@link NostrKeys} handles encodings.
 */
public final class Bip340 {

    private static final Secp256k1 SECP = Secp256k1.get();
    private static final SecureRandom RNG = new SecureRandom();

    private Bip340() {}

    /** A fresh 32-byte secret scalar (1 <= d < n), from the platform CSPRNG. */
    public static byte[] generateSecretKey() {
        byte[] sk = new byte[32];
        do {
            RNG.nextBytes(sk);
        } while (!SECP.secKeyVerify(sk));
        return sk;
    }

    /** @return true if {@code secretKey} is 32 bytes and a valid scalar. */
    public static boolean isValidSecretKey(byte[] secretKey) {
        return secretKey != null && secretKey.length == 32 && SECP.secKeyVerify(secretKey);
    }

    /** The 32-byte x-only public key for a secret key. */
    public static byte[] xOnlyPublicKey(byte[] secretKey) {
        byte[] compressed = SECP.pubKeyCompress(SECP.pubkeyCreate(secretKey));
        byte[] xOnly = new byte[32];
        System.arraycopy(compressed, 1, xOnly, 0, 32);
        return xOnly;
    }

    /** @return true if {@code xOnlyPublicKey} is 32 bytes over a valid curve point. */
    public static boolean isValidXOnlyPublicKey(byte[] xOnlyPublicKey) {
        if (xOnlyPublicKey == null || xOnlyPublicKey.length != 32) return false;
        try {
            // lift to a compressed even-Y key; throws for an invalid x
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            System.arraycopy(xOnlyPublicKey, 0, compressed, 1, 32);
            SECP.pubkeyParse(compressed);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * BIP-340 sign of a 32-byte message.
     *
     * @param auxRand32 32 bytes of randomness, or {@code null}. Passing 32 zero
     *                  bytes makes the signature reproducible, which is how
     *                  {@code did-vectors} is generated; production callers should
     *                  pass fresh randomness. Verification never depends on this.
     */
    public static byte[] sign(byte[] message32, byte[] secretKey, byte[] auxRand32) {
        return SECP.signSchnorr(message32, secretKey, auxRand32);
    }

    /** BIP-340 sign with fresh randomness. */
    public static byte[] sign(byte[] message32, byte[] secretKey) {
        byte[] aux = new byte[32];
        RNG.nextBytes(aux);
        return SECP.signSchnorr(message32, secretKey, aux);
    }

    /** BIP-340 verify of a 64-byte signature over a 32-byte message. */
    public static boolean verify(byte[] signature64, byte[] message32, byte[] xOnlyPublicKey) {
        if (signature64 == null || signature64.length != 64
                || message32 == null || message32.length != 32
                || xOnlyPublicKey == null || xOnlyPublicKey.length != 32) {
            return false;
        }
        try {
            return SECP.verifySchnorr(signature64, message32, xOnlyPublicKey);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
