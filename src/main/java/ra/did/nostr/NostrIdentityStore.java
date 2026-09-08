package ra.did.nostr;

import ra.common.JSONParser;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * On-disk store for {@link NostrIdentity} secrets, encrypted at rest
 * (DID {@code DESIGN.md} §6.3). One file per identity —
 * {@code <dir>/<pubkey-hex>.json} — holding the public key in the clear and the
 * secret as an {@link EncryptedSecret} envelope. The passphrase is never stored.
 *
 * <p>Not built on {@code InfoVaultFileDB}: that round-trips a JSON body through a
 * non-unescaping parser, which corrupts nested JSON. This writes the file
 * directly; every stored string is hex or base64, so it needs no escaping.
 */
public final class NostrIdentityStore {

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");

    private final File dir;

    public NostrIdentityStore(File dir) {
        this.dir = dir;
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("could not create " + dir);
        }
    }

    /** Seal {@code id}'s secret under {@code passphrase} and write it. Overwrites any existing file. */
    public void save(NostrIdentity id, char[] passphrase) {
        if (!id.hasSecret()) throw new IllegalArgumentException("identity has no secret to persist");
        byte[] sec = id.secretKeyBytes();
        EncryptedSecret enc = EncryptedSecret.seal(sec, passphrase);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", 1);
        m.put("pub", id.getPublicKeyHex());
        m.put("enc", enc.toMap());
        try {
            Files.write(file(id.getPublicKeyHex()).toPath(),
                    JSONParser.toString(m).getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("could not write identity " + id.getPublicKeyHex(), e);
        }
    }

    /**
     * Load and decrypt an identity.
     *
     * @return the identity, or {@code null} if no file exists for {@code pubkeyHex}
     * @throws GeneralSecurityException on a wrong passphrase or tampered file
     */
    @SuppressWarnings("unchecked")
    public NostrIdentity load(String pubkeyHex, char[] passphrase) throws GeneralSecurityException {
        File f = file(pubkeyHex);
        if (!f.exists()) return null;
        Map<String, Object> m;
        try {
            m = (Map<String, Object>) JSONParser.parse(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new IllegalStateException("could not read identity " + pubkeyHex, e);
        }
        EncryptedSecret enc = EncryptedSecret.fromMap((Map<String, Object>) m.get("enc"));
        byte[] sec = enc.open(passphrase);
        try {
            NostrIdentity id = NostrIdentity.fromSecretKey(sec);
            if (!id.getPublicKeyHex().equals(pubkeyHex)) {
                throw new GeneralSecurityException("decrypted secret does not derive " + pubkeyHex);
            }
            return id;
        } finally {
            Arrays.fill(sec, (byte) 0);
        }
    }

    public boolean exists(String pubkeyHex) {
        return file(pubkeyHex).exists();
    }

    public boolean delete(String pubkeyHex) {
        File f = file(pubkeyHex);
        return f.exists() && f.delete();
    }

    /** Pubkeys (hex) of the persisted identities — read from filenames, no decryption. */
    public List<String> list() {
        List<String> out = new ArrayList<>();
        File[] files = dir.listFiles((d, n) -> n.endsWith(".json") && HEX64.matcher(n.substring(0, n.length() - 5)).matches());
        if (files != null) {
            for (File f : files) out.add(f.getName().substring(0, f.getName().length() - 5));
        }
        return out;
    }

    private File file(String pubkeyHex) {
        if (pubkeyHex == null || !HEX64.matcher(pubkeyHex).matches()) {
            throw new IllegalArgumentException("pubkey must be 64 lowercase hex chars");
        }
        return new File(dir, pubkeyHex + ".json");
    }
}
