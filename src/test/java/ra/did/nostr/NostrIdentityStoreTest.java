package ra.did.nostr;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class NostrIdentityStoreTest {

    @Test
    public void saveLoadRoundTrip(@TempDir Path dir) throws GeneralSecurityException {
        NostrIdentityStore store = new NostrIdentityStore(dir.toFile());
        NostrIdentity id = NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
        String secretHex = id.secretHex();

        store.save(id, "pass-phrase".toCharArray());
        assertTrue(store.exists(id.getPublicKeyHex()));
        assertTrue(new File(dir.toFile(), id.getPublicKeyHex() + ".json").exists());

        NostrIdentity loaded = store.load(id.getPublicKeyHex(), "pass-phrase".toCharArray());
        assertNotNull(loaded);
        assertEquals(id.getPublicKeyHex(), loaded.getPublicKeyHex());
        assertEquals(secretHex, loaded.secretHex());
    }

    @Test
    public void wrongPassphraseThrows(@TempDir Path dir) {
        NostrIdentityStore store = new NostrIdentityStore(dir.toFile());
        NostrIdentity id = NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
        store.save(id, "right".toCharArray());
        assertThrows(GeneralSecurityException.class, () -> store.load(id.getPublicKeyHex(), "wrong".toCharArray()));
    }

    @Test
    public void missingIdentityLoadsAsNull(@TempDir Path dir) throws GeneralSecurityException {
        NostrIdentityStore store = new NostrIdentityStore(dir.toFile());
        String pub = NostrIdentity.fromSecretKey(Bip340.generateSecretKey()).getPublicKeyHex();
        assertNull(store.load(pub, "pw".toCharArray()));
        assertFalse(store.exists(pub));
    }

    @Test
    public void listAndDelete(@TempDir Path dir) {
        NostrIdentityStore store = new NostrIdentityStore(dir.toFile());
        NostrIdentity a = NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
        NostrIdentity b = NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
        store.save(a, "pw".toCharArray());
        store.save(b, "pw".toCharArray());

        List<String> pubs = store.list();
        assertEquals(2, pubs.size());
        assertTrue(pubs.contains(a.getPublicKeyHex()));

        assertTrue(store.delete(a.getPublicKeyHex()));
        assertFalse(store.delete(a.getPublicKeyHex()));
        assertEquals(1, store.list().size());
    }

    @Test
    public void theStoredFileHoldsNoPlaintextSecret(@TempDir Path dir) throws Exception {
        NostrIdentityStore store = new NostrIdentityStore(dir.toFile());
        NostrIdentity id = NostrIdentity.fromSecretKey(Bip340.generateSecretKey());
        String secretHex = id.secretHex();
        store.save(id, "pw".toCharArray());
        String contents = new String(java.nio.file.Files.readAllBytes(
                new File(dir.toFile(), id.getPublicKeyHex() + ".json").toPath()));
        assertFalse(contents.contains(secretHex), "the secret hex must not appear in the file");
        assertTrue(contents.contains(id.getPublicKeyHex()), "the public key is stored in the clear");
    }
}
