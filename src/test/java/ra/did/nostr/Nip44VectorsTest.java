package ra.did.nostr;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Conformance against the official NIP-44 spec's own test vectors
 * (src/test/resources/vectors/nip44.json - different provenance from the
 * did-vectors-sourced files in that directory, see VENDORED.md there).
 *
 * <p>Two "invalid" vector arrays are deliberately not turned into tests here:
 * {@code encrypt_msg_lengths} and {@code decrypt_msg_lengths} give only bare
 * byte-length integers (0, 65536, 100000, 10000000) with no plaintext content
 * or stated reason, and 65536/100000/10000000 are all well under NIP-44's own
 * stated 4294967295-byte maximum - unlike every other vector category here,
 * which fully specifies inputs and expected outputs. Implementing exclusions
 * to satisfy an under-specified vector risks adding a restriction the spec
 * does not actually require.
 */
public class Nip44VectorsTest {

    private static final JsonObject V2 = load("nip44.json").getAsJsonObject("v2");

    private static JsonObject load(String name) {
        try (InputStreamReader r = new InputStreamReader(
                Nip44VectorsTest.class.getResourceAsStream("/vectors/" + name), StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(r).getAsJsonObject();
        } catch (Exception e) {
            throw new RuntimeException("could not load /vectors/" + name, e);
        }
    }

    private static byte[] hex(String s) {
        return NostrKeys.fromHex(s);
    }

    // -- valid: get_conversation_key -----------------------------

    @TestFactory
    List<DynamicTest> validGetConversationKey() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : V2.getAsJsonObject("valid").getAsJsonArray("get_conversation_key")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("note").getAsString(), () -> {
                byte[] key = Nip44.getConversationKey(hex(c.get("sec1").getAsString()), hex(c.get("pub2").getAsString()));
                assertEquals(c.get("conversation_key").getAsString(), NostrKeys.toHex(key));
            }));
        }
        return tests;
    }

    // -- valid: calc_padded_len -----------------------------------

    @TestFactory
    List<DynamicTest> validCalcPaddedLen() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : V2.getAsJsonObject("valid").getAsJsonArray("calc_padded_len")) {
            JsonArray pair = el.getAsJsonArray();
            int in = pair.get(0).getAsInt();
            int expected = pair.get(1).getAsInt();
            tests.add(DynamicTest.dynamicTest(in + " -> " + expected,
                    () -> assertEquals(expected, Nip44.calcPaddedLen(in))));
        }
        return tests;
    }

    // -- valid: encrypt_decrypt ------------------------------------

    @TestFactory
    List<DynamicTest> validEncryptDecrypt() {
        List<DynamicTest> tests = new ArrayList<>();
        int i = 0;
        for (JsonElement el : V2.getAsJsonObject("valid").getAsJsonArray("encrypt_decrypt")) {
            JsonObject c = el.getAsJsonObject();
            String name = "vector " + (i++) + ": " + trim(c.get("plaintext").getAsString());
            tests.add(DynamicTest.dynamicTest(name, () -> {
                byte[] conversationKey = hex(c.get("conversation_key").getAsString());
                byte[] nonce = hex(c.get("nonce").getAsString());
                String plaintext = c.get("plaintext").getAsString();
                String expectedCiphertext = c.get("ciphertext").getAsString();

                assertEquals(expectedCiphertext, Nip44.encrypt(plaintext, conversationKey, nonce),
                        "encrypt should reproduce the vector's ciphertext with its given nonce");
                assertEquals(plaintext, Nip44.decrypt(expectedCiphertext, conversationKey),
                        "decrypt should recover the original plaintext");
            }));
        }
        return tests;
    }

    private static String trim(String s) {
        return s.length() > 24 ? s.substring(0, 24) + "..." : s;
    }

    // -- valid: encrypt_decrypt_long_msg ----------------------------

    @TestFactory
    List<DynamicTest> validEncryptDecryptLongMsg() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : V2.getAsJsonObject("valid").getAsJsonArray("encrypt_decrypt_long_msg")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("note").getAsString(), () -> {
                byte[] conversationKey = hex(c.get("conversation_key").getAsString());
                byte[] nonce = hex(c.get("nonce").getAsString());
                String letter = c.get("letter").getAsString();
                int repeat = c.get("repeat").getAsInt();
                StringBuilder sb = new StringBuilder(letter.length() * repeat);
                for (int i = 0; i < repeat; i++) sb.append(letter);
                String plaintext = sb.toString();

                String ciphertext = Nip44.encrypt(plaintext, conversationKey, nonce);
                assertEquals(plaintext, Nip44.decrypt(ciphertext, conversationKey));
            }));
        }
        return tests;
    }

    // -- invalid: get_conversation_key ------------------------------

    @TestFactory
    List<DynamicTest> invalidGetConversationKeyRejected() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : V2.getAsJsonObject("invalid").getAsJsonArray("get_conversation_key")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("note").getAsString(), () ->
                    assertThrows(IllegalArgumentException.class, () ->
                            Nip44.getConversationKey(hex(c.get("sec1").getAsString()), hex(c.get("pub2").getAsString())))));
        }
        return tests;
    }

    // -- invalid: decrypt (bad MAC / bad padding) --------------------

    @TestFactory
    List<DynamicTest> invalidDecryptRejected() {
        List<DynamicTest> tests = new ArrayList<>();
        int i = 0;
        for (JsonElement el : V2.getAsJsonObject("invalid").getAsJsonArray("decrypt")) {
            JsonObject c = el.getAsJsonObject();
            String name = (i++) + " (" + c.get("note").getAsString() + ")";
            tests.add(DynamicTest.dynamicTest(name, () ->
                    assertThrows(IllegalArgumentException.class, () ->
                            Nip44.decrypt(c.get("ciphertext").getAsString(), hex(c.get("conversation_key").getAsString())))));
        }
        return tests;
    }
}
