package ra.did.nostr;

import com.google.gson.Gson;
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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Conformance against did-vectors/events.json — the interoperability contract
 * (DID DESIGN.md §2.3). Vendored copy in src/test/resources/vectors/.
 */
public class NostrEventVectorsTest {

    private static final Gson GSON = new Gson();
    private static final JsonObject VECTORS = load("events.json");

    private static JsonObject load(String name) {
        try (InputStreamReader r = new InputStreamReader(
                NostrEventVectorsTest.class.getResourceAsStream("/vectors/" + name), StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(r).getAsJsonObject();
        } catch (Exception e) {
            throw new RuntimeException("could not load /vectors/" + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static NostrEvent event(JsonObject o) {
        return NostrEvent.fromMap((Map<String, Object>) GSON.fromJson(o, Map.class));
    }

    private static List<List<String>> tags(JsonArray arr) {
        List<List<String>> tags = new ArrayList<>();
        for (int i = 0; i < arr.size(); i++) {
            JsonArray t = arr.get(i).getAsJsonArray();
            List<String> tag = new ArrayList<>();
            for (int j = 0; j < t.size(); j++) tag.add(t.get(j).getAsString());
            tags.add(tag);
        }
        return tags;
    }

    // --- §2.1 canonical serialisation --------------------------

    @TestFactory
    List<DynamicTest> canonicalSerialisation() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("serialization")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("name").getAsString(), () -> {
                NostrEvent e = event(c.getAsJsonObject("input"));
                String preimage = e.canonicalPreimage();
                assertEquals(c.get("preimage").getAsString(), preimage, "preimage");
                assertEquals(c.get("preimage_utf8_bytes").getAsInt(),
                        preimage.getBytes(StandardCharsets.UTF_8).length, "preimage byte count");
                assertEquals(c.get("id").getAsString(), e.computeId(), "id");
            }));
        }
        return tests;
    }

    // --- §2.2 valid events -------------------------------------

    @TestFactory
    List<DynamicTest> validEventsVerify() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("valid_events")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("name").getAsString(), () -> {
                NostrEvent.VerifyResult r = event(c.getAsJsonObject("event")).verify();
                assertTrue(r.ok, "expected valid, got step " + r.step + ": " + r.reason);
            }));
        }
        return tests;
    }

    // --- signature reproduction (aux_rand = 0) -----------------

    @TestFactory
    List<DynamicTest> validEventSignaturesReproduce() {
        Map<String, String> secByPub = new java.util.HashMap<>();
        for (Map.Entry<String, JsonElement> e : VECTORS.getAsJsonObject("keys").entrySet()) {
            JsonObject k = e.getValue().getAsJsonObject();
            secByPub.put(k.get("pub").getAsString(), k.get("sec").getAsString());
        }
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("valid_events")) {
            JsonObject ev = el.getAsJsonObject().getAsJsonObject("event");
            String sec = secByPub.get(ev.get("pubkey").getAsString());
            if (sec == null) continue;
            tests.add(DynamicTest.dynamicTest(el.getAsJsonObject().get("name").getAsString(), () -> {
                NostrEvent re = NostrEvent.unsigned(
                        ev.get("kind").getAsInt(),
                        tags(ev.getAsJsonArray("tags")),
                        ev.get("content").getAsString(),
                        ev.get("created_at").getAsLong());
                re.sign(sec, new byte[32]);
                assertEquals(ev.get("id").getAsString(), re.getId(), "id");
                assertEquals(ev.get("sig").getAsString(), re.getSig(), "sig");
            }));
        }
        return tests;
    }

    // --- §2.2 invalid events ----------------------------------

    @TestFactory
    List<DynamicTest> invalidEventsRejectedAtStatedStep() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("invalid_events")) {
            JsonObject c = el.getAsJsonObject();
            int failsStep = c.get("fails_step").getAsInt();
            String label = c.get("name").getAsString()
                    + " (fails_step " + failsStep + ", rejected_by " + c.get("rejected_by").getAsString() + ")";
            tests.add(DynamicTest.dynamicTest(label, () -> {
                NostrEvent.VerifyResult r = event(c.getAsJsonObject("event")).verify();
                assertFalse(r.ok, "expected rejection");
                assertEquals(failsStep, r.step, "expected failure at step " + failsStep + ", got " + r.step);
            }));
        }
        return tests;
    }
}
