package ra.did.nostr;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A secret sealed at rest (DID {@code DESIGN.md} §6.3): a memory-hard KDF
 * (Argon2id) over a user passphrase derives a 256-bit key, which an AEAD
 * (AES-256-GCM) uses to seal the plaintext. The salt, nonce and KDF parameters
 * travel with the ciphertext; the passphrase never does.
 *
 * <p>Used for the 32-byte Nostr identity secret, but takes any byte array.
 */
public final class EncryptedSecret {

    static final int VERSION = 1;
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    /**
     * Argon2id defaults — 19 MiB, 2 passes, 1 lane (the OWASP minimum for
     * Argon2id). Memory-hard and fast enough for interactive unlock; raise via
     * the {@link #seal(byte[], char[], int, int, int)} overload where the threat
     * model warrants it. The parameters are stored with the ciphertext, so a
     * later default change does not break old files.
     */
    public static final int DEFAULT_MEMORY_KB = 19 * 1024;
    public static final int DEFAULT_ITERATIONS = 2;
    public static final int DEFAULT_PARALLELISM = 1;

    private static final SecureRandom RNG = new SecureRandom();

    private final int memoryKb;
    private final int iterations;
    private final int parallelism;
    private final byte[] salt;
    private final byte[] nonce;
    private final byte[] ciphertext; // includes the 16-byte GCM tag

    private EncryptedSecret(int memoryKb, int iterations, int parallelism,
                            byte[] salt, byte[] nonce, byte[] ciphertext) {
        this.memoryKb = memoryKb;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.salt = salt;
        this.nonce = nonce;
        this.ciphertext = ciphertext;
    }

    public static EncryptedSecret seal(byte[] plaintext, char[] passphrase) {
        return seal(plaintext, passphrase, DEFAULT_MEMORY_KB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
    }

    public static EncryptedSecret seal(byte[] plaintext, char[] passphrase,
                                       int memoryKb, int iterations, int parallelism) {
        if (plaintext == null || plaintext.length == 0) throw new IllegalArgumentException("nothing to seal");
        if (passphrase == null || passphrase.length == 0) throw new IllegalArgumentException("passphrase required");
        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        RNG.nextBytes(salt);
        RNG.nextBytes(nonce);
        byte[] key = deriveKey(passphrase, salt, memoryKb, iterations, parallelism);
        try {
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            gcm.init(true, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce));
            byte[] out = new byte[gcm.getOutputSize(plaintext.length)];
            int off = gcm.processBytes(plaintext, 0, plaintext.length, out, 0);
            gcm.doFinal(out, off);
            return new EncryptedSecret(memoryKb, iterations, parallelism, salt, nonce, out);
        } catch (Exception e) {
            throw new IllegalStateException("AEAD seal failed", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    /** @throws GeneralSecurityException on a wrong passphrase or tampered ciphertext. */
    public byte[] open(char[] passphrase) throws GeneralSecurityException {
        if (passphrase == null || passphrase.length == 0) throw new IllegalArgumentException("passphrase required");
        byte[] key = deriveKey(passphrase, salt, memoryKb, iterations, parallelism);
        try {
            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            gcm.init(false, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce));
            byte[] out = new byte[gcm.getOutputSize(ciphertext.length)];
            int off = gcm.processBytes(ciphertext, 0, ciphertext.length, out, 0);
            off += gcm.doFinal(out, off);
            return Arrays.copyOf(out, off);
        } catch (org.bouncycastle.crypto.InvalidCipherTextException e) {
            throw new GeneralSecurityException("wrong passphrase or corrupt data", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] deriveKey(char[] passphrase, byte[] salt, int memKb, int iters, int par) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memKb)
                .withIterations(iters)
                .withParallelism(par)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] key = new byte[32];
        gen.generateBytes(passphrase, key);
        return key;
    }

    // --- persistence form (no plaintext, no passphrase) --------

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", VERSION);
        m.put("kdf", "argon2id");
        m.put("m", memoryKb);
        m.put("t", iterations);
        m.put("p", parallelism);
        m.put("salt", b64(salt));
        m.put("nonce", b64(nonce));
        m.put("ct", b64(ciphertext));
        return m;
    }

    @SuppressWarnings("unchecked")
    public static EncryptedSecret fromMap(Map<String, Object> m) {
        int v = num(m.get("v"));
        if (v != VERSION) throw new IllegalArgumentException("unsupported EncryptedSecret version " + v);
        return new EncryptedSecret(
                num(m.get("m")), num(m.get("t")), num(m.get("p")),
                unb64(m.get("salt")), unb64(m.get("nonce")), unb64(m.get("ct")));
    }

    private static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    private static byte[] unb64(Object s) { return Base64.getDecoder().decode((String) s); }
    private static int num(Object o) { return ((Number) o).intValue(); }
}
