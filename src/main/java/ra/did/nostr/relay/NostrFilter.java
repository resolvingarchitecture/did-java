package ra.did.nostr.relay;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A NIP-01 {@code REQ} filter: {@code ids}/{@code authors}/{@code kinds}/{@code since}/{@code until}/{@code limit}, plus tag filters ({@code #e}, {@code #p}, {@code #d}, ...). */
public final class NostrFilter {

    private final List<String> ids = new ArrayList<>();
    private final List<String> authors = new ArrayList<>();
    private final List<Integer> kinds = new ArrayList<>();
    private final Map<String, List<String>> tags = new LinkedHashMap<>();
    private Long since;
    private Long until;
    private Integer limit;

    public NostrFilter ids(String... v) { Collections.addAll(ids, v); return this; }
    public NostrFilter authors(String... v) { Collections.addAll(authors, v); return this; }
    public NostrFilter kinds(int... v) { for (int k : v) kinds.add(k); return this; }
    public NostrFilter since(long v) { since = v; return this; }
    public NostrFilter until(long v) { until = v; return this; }
    public NostrFilter limit(int v) { limit = v; return this; }

    /** {@code tagName} without the leading {@code #}, e.g. {@code "e"}, {@code "p"}, {@code "d"}. */
    public NostrFilter tag(String tagName, String... values) {
        tags.computeIfAbsent(tagName, k -> new ArrayList<>()).addAll(Arrays.asList(values));
        return this;
    }

    // --- accessors, for a relay's own server-side filter matching -----

    public List<String> getIds() { return Collections.unmodifiableList(ids); }
    public List<String> getAuthors() { return Collections.unmodifiableList(authors); }
    public List<Integer> getKinds() { return Collections.unmodifiableList(kinds); }
    /** Keyed by tag name without the leading {@code #}, e.g. {@code "e"}, {@code "p"}, {@code "d"}. */
    public Map<String, List<String>> getTags() { return Collections.unmodifiableMap(tags); }
    public Long getSince() { return since; }
    public Long getUntil() { return until; }
    public Integer getLimit() { return limit; }

    public static NostrFilter fromJson(JsonObject o) {
        NostrFilter f = new NostrFilter();
        if (o.has("ids")) for (JsonElement el : o.getAsJsonArray("ids")) f.ids.add(el.getAsString());
        if (o.has("authors")) for (JsonElement el : o.getAsJsonArray("authors")) f.authors.add(el.getAsString());
        if (o.has("kinds")) for (JsonElement el : o.getAsJsonArray("kinds")) f.kinds.add(el.getAsInt());
        if (o.has("since")) f.since = o.get("since").getAsLong();
        if (o.has("until")) f.until = o.get("until").getAsLong();
        if (o.has("limit")) f.limit = o.get("limit").getAsInt();
        for (String key : o.keySet()) {
            if (key.startsWith("#") && key.length() > 1) {
                List<String> values = new ArrayList<>();
                for (JsonElement el : o.getAsJsonArray(key)) values.add(el.getAsString());
                f.tags.put(key.substring(1), values);
            }
        }
        return f;
    }

    public JsonObject toJson() {
        JsonObject o = new JsonObject();
        if (!ids.isEmpty()) o.add("ids", strArray(ids));
        if (!authors.isEmpty()) o.add("authors", strArray(authors));
        if (!kinds.isEmpty()) {
            JsonArray a = new JsonArray();
            for (int k : kinds) a.add(k);
            o.add("kinds", a);
        }
        if (since != null) o.addProperty("since", since);
        if (until != null) o.addProperty("until", until);
        if (limit != null) o.addProperty("limit", limit);
        for (Map.Entry<String, List<String>> e : tags.entrySet()) {
            o.add("#" + e.getKey(), strArray(e.getValue()));
        }
        return o;
    }

    private static JsonArray strArray(List<String> v) {
        JsonArray a = new JsonArray();
        for (String s : v) a.add(s);
        return a;
    }
}