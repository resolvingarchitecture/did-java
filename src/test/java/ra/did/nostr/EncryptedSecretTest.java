package ra.did.nostr;

import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class EncryptedSecretTest {

    private static byte[] secret() {
        byte[] s = new byte[32];
        for (int i = 0; i < 32; i++) s[i] = (byte) (i + 1);
        return s;
    }

    @Test
    public void sealOpenRoundTrip() throws GeneralSecurityException {
        byte[] sec = secret();
        EncryptedSecret env = EncryptedSecret.seal(sec, "correct horse battery staple".toCharArray());
        assertArrayEquals(sec, env.open("correct horse battery staple".toCharArray()));
    }

    @Test
    public void wrongPassphraseThrows() {
        EncryptedSecret env = EncryptedSecret.seal(secret(), "right".toCharArray());
        assertThrows(GeneralSecurityException.class, () -> env.open("wrong".toCharArray()));
    }

    @Test
    public void mapRoundTripPreservesEverything() throws GeneralSecurityException {
        byte[] sec = secret();
        EncryptedSecret env = EncryptedSecret.seal(sec, "pw".toCharArray());
        Map<String, Object> m = env.toMap();
        assertEquals("argon2id", m.get("kdf"));
        EncryptedSecret restored = EncryptedSecret.fromMap(m);
        assertArrayEquals(sec, restored.open("pw".toCharArray()));
        assertThrows(GeneralSecurityException.class, () -> restored.open("nope".toCharArray()));
    }

    @Test
    public void tamperedCiphertextIsRejected() {
        EncryptedSecret env = EncryptedSecret.seal(secret(), "pw".toCharArray());
        Map<String, Object> m = env.toMap();
        String ct = (String) m.get("ct");
        // flip a character in the base64 ciphertext
        char[] cs = ct.toCharArray();
        cs[0] = cs[0] == 'A' ? 'B' : 'A';
        m.put("ct", new String(cs));
        EncryptedSecret bad = EncryptedSecret.fromMap(m);
        assertThrows(GeneralSecurityException.class, () -> bad.open("pw".toCharArray()));
    }

    @Test
    public void distinctSaltAndNoncePerSeal() {
        EncryptedSecret a = EncryptedSecret.seal(secret(), "pw".toCharArray());
        EncryptedSecret b = EncryptedSecret.seal(secret(), "pw".toCharArray());
        assertNotEquals(a.toMap().get("ct"), b.toMap().get("ct"));
        assertNotEquals(a.toMap().get("salt"), b.toMap().get("salt"));
        assertNotEquals(a.toMap().get("nonce"), b.toMap().get("nonce"));
    }
}
