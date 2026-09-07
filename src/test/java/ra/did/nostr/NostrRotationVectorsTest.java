package ra.did.nostr;

import com.google.gson.Gson;
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
 * Conformance against did-vectors/rotation.json — the guardian rotation
 * acceptance rule (DID DESIGN.md §4.3). Vendored copy in src/test/resources/vectors/.
 */
public class NostrRotationVectorsTest {

    private static final Gson GSON = new Gson();
    private static final JsonObject VECTORS = load();

    private static JsonObject load() {
        try (InputStreamReader r = new InputStreamReader(
                NostrRotationVectorsTest.class.getResourceAsStream("/vectors/rotation.json"),
                StandardCharsets.UTF_8)) {
            return JsonParser.parseReader(r).getAsJsonObject();
        } catch (Exception e) {
            throw new RuntimeException("could not load /vectors/rotation.json", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<NostrEvent> events(JsonObject caseObj) {
        List<NostrEvent> out = new ArrayList<>();
        for (JsonElement el : caseObj.getAsJsonArray("events")) {
            out.add(NostrEvent.fromMap((Map<String, Object>) GSON.fromJson(el, Map.class)));
        }
        return out;
    }

    private static NostrRotation.Options opts() {
        NostrRotation.Options o = new NostrRotation.Options();
        o.cooldownSeconds = VECTORS.get("cooldown_seconds").getAsLong();
        return o;
    }

    @TestFactory
    List<DynamicTest> everyEventIsWellFormed() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("cases")) {
            JsonObject c = el.getAsJsonObject();
            tests.add(DynamicTest.dynamicTest(c.get("name").getAsString(), () -> {
                for (NostrEvent ev : events(c)) {
                    NostrEvent.VerifyResult r = ev.verify();
                    assertTrue(r.ok, "event " + ev.getId() + " failed at step " + r.step + ": " + r.reason);
                }
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> acceptanceRuleReachesTheStatedVerdict() {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonElement el : VECTORS.getAsJsonArray("cases")) {
            JsonObject c = el.getAsJsonObject();
            boolean expected = c.get("accept").getAsBoolean();
            tests.add(DynamicTest.dynamicTest(
                    c.get("name").getAsString() + " -> " + (expected ? "accept" : "reject"), () -> {
                NostrRotation.Verdict v = NostrRotation.evaluate(events(c), opts());
                assertEquals(expected, v.accepted, v.reason);
                if (expected) {
                    assertNotNull(v.newKey, "an accepted rotation names a successor key");
                    assertNotNull(v.oldKey, "an accepted rotation names the old key");
                }
            }));
        }
        return tests;
    }
}
