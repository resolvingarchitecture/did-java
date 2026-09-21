package ra.did.nostr.relay;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ra.common.Envelope;
import ra.common.route.Route;
import ra.common.service.BaseService;
import ra.did.nostr.NostrEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * The relay half of Remnant's Nostr surface as a plain {@link BaseService} -
 * the {@code NostrRelayAdapter} named in {@code 1m5-android/DESIGN.md}
 * §"Nostr Integration and Portable Identity", wired the same way
 * {@code bitcoin-client-java}'s {@code ra.btc.BitcoinService} is: a
 * standalone, bus-addressable component that {@code network.onemfive.core
 * .business.NostrService} (1m5-core-java) wraps thinly, exactly like
 * {@code network.onemfive.core.business.BitcoinService} wraps that one.
 *
 * <p>Deliberately generic (see {@link NostrRelayOps}): this service moves
 * already-signed events to and from a curated relay set and does not know
 * about kinds. Event construction and verification is
 * {@link NostrEvent}/{@link ra.did.nostr.NostrKeyRing}'s job, one layer down;
 * an inbound {@code PUBLISH} is re-verified here regardless (a caller cannot
 * make this service relay something that would not itself verify).
 */
public final class NostrRelayService extends BaseService implements NostrRelayOps {

    private static final Logger LOG = Logger.getLogger(NostrRelayService.class.getName());
    private static final Gson GSON = new Gson();
    private static final long DEFAULT_TIMEOUT_MS = 8_000;

    /** {@code 1m5.nostr.relays} - comma-separated relay URLs, overriding {@link NostrRelayPool#DEFAULT_RELAYS}. */
    public static final String PROP_RELAYS = "1m5.nostr.relays";
    /** How long {@link #start} waits for at least one relay to connect before returning. */
    public static final String PROP_CONNECT_TIMEOUT_MS = "1m5.nostr.connectTimeoutMs";

    private final Map<String, QueryCollector> activeQueries = new ConcurrentHashMap<>();
    private volatile NostrRelayPool pool;

    @Override
    public boolean start(Properties p) {
        if (!super.start(p)) return false;
        List<String> relays = relaysFrom(p);
        pool = new NostrRelayPool(relays, new NostrRelayListener() {
            @Override
            public void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {
                QueryCollector c = activeQueries.get(subscriptionId);
                if (c != null) c.events.add(event);
            }

            @Override
            public void onEose(String relayUrl, String subscriptionId) {
                QueryCollector c = activeQueries.get(subscriptionId);
                if (c != null) c.eose.countDown();
            }

            @Override
            public void onNotice(String relayUrl, String message) {
                LOG.info(relayUrl + " NOTICE: " + message);
            }

            @Override
            public void onDisconnected(String relayUrl, String reason) {
                LOG.info(relayUrl + " disconnected: " + reason);
            }
        });
        pool.connectAll();
        long connectTimeoutMs = longProp(p, PROP_CONNECT_TIMEOUT_MS, 5_000);
        long deadline = System.currentTimeMillis() + connectTimeoutMs;
        while (pool.connectedCount() == 0 && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        LOG.info("NostrRelayService started, connected to " + pool.connectedCount() + "/" + relays.size() + " relays");
        return true;
    }

    @Override
    public boolean shutdown() {
        if (pool != null) pool.close();
        return super.shutdown();
    }

    @Override
    public boolean gracefulShutdown() {
        return shutdown();
    }

    @Override
    public void handleDocument(Envelope envelope) {
        Route route = envelope.getRoute();
        String operation = route == null ? null : route.getOperation();
        if (operation == null) {
            envelope.addErrorMessage("missing operation");
            return;
        }
        switch (operation) {
            case OPERATION_PUBLISH: handlePublish(envelope); break;
            case OPERATION_QUERY: handleQuery(envelope); break;
            case OPERATION_STATUS: handleStatus(envelope); break;
            default: envelope.addErrorMessage("unknown operation: " + operation);
        }
    }

    private void handlePublish(Envelope envelope) {
        String json = stringHeaderOrNull(envelope, HEADER_EVENT_JSON);
        if (json == null) {
            envelope.addErrorMessage("missing " + HEADER_EVENT_JSON);
            return;
        }
        NostrEvent event;
        try {
            java.lang.reflect.Type mapType = new com.google.gson.reflect.TypeToken<java.util.Map<String, Object>>() {}.getType();
            java.util.Map<String, Object> map = GSON.fromJson(json, mapType);
            event = NostrEvent.fromMap(map);
        } catch (RuntimeException ex) {
            envelope.addErrorMessage("malformed event json: " + ex.getMessage());
            return;
        }
        NostrEvent.VerifyResult vr = event.verify();
        if (!vr.ok) {
            envelope.addErrorMessage("event does not verify (step " + vr.step + "): " + vr.reason);
            return;
        }
        long timeoutMs = longHeaderOr(envelope, HEADER_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
        List<PublishResult> results = pool.publish(event, timeoutMs);
        JsonArray arr = new JsonArray();
        for (PublishResult r : results) {
            JsonObject o = new JsonObject();
            o.addProperty("relay", r.relayUrl);
            o.addProperty("accepted", r.accepted);
            o.addProperty("message", r.message);
            arr.add(o);
        }
        envelope.setHeader(HEADER_RESULTS_JSON, GSON.toJson(arr));
    }

    private void handleQuery(Envelope envelope) {
        String filterJson = stringHeaderOrNull(envelope, HEADER_FILTER_JSON);
        if (filterJson == null) {
            envelope.addErrorMessage("missing " + HEADER_FILTER_JSON);
            return;
        }
        NostrFilter filter;
        try {
            filter = NostrFilter.fromJson(JsonParser.parseString(filterJson).getAsJsonObject());
        } catch (RuntimeException ex) {
            envelope.addErrorMessage("malformed filter json: " + ex.getMessage());
            return;
        }
        long timeoutMs = longHeaderOr(envelope, HEADER_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
        String subId = pool.newSubscriptionId("query");
        int expected = Math.max(1, pool.connectedCount());
        QueryCollector collector = new QueryCollector(expected);
        activeQueries.put(subId, collector);
        try {
            pool.subscribeAll(subId, filter);
            collector.eose.await(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } finally {
            pool.unsubscribeAll(subId);
            activeQueries.remove(subId);
        }
        JsonArray arr = new JsonArray();
        for (NostrEvent ev : collector.events) {
            arr.add(JsonParser.parseString(ev.toJson()));
        }
        envelope.setHeader(HEADER_EVENTS_JSON, GSON.toJson(arr));
    }

    private void handleStatus(Envelope envelope) {
        envelope.setHeader(HEADER_CONNECTED_RELAYS, String.valueOf(pool.connectedCount()));
        envelope.setHeader(HEADER_TOTAL_RELAYS, String.valueOf(pool.relayUrls().size()));
    }

    private static List<String> relaysFrom(Properties p) {
        String raw = p == null ? null : p.getProperty(PROP_RELAYS);
        if (raw == null || raw.trim().isEmpty()) return NostrRelayPool.DEFAULT_RELAYS;
        List<String> out = new ArrayList<>();
        for (String s : raw.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out.isEmpty() ? NostrRelayPool.DEFAULT_RELAYS : out;
    }

    private static long longProp(Properties p, String key, long def) {
        String v = p == null ? null : p.getProperty(key);
        if (v == null) return def;
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String stringHeaderOrNull(Envelope e, String name) {
        Object v = e.getHeader(name);
        return v == null ? null : String.valueOf(v);
    }

    private static long longHeaderOr(Envelope e, String name, long def) {
        String v = stringHeaderOrNull(e, name);
        if (v == null) return def;
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException ex) {
            return def;
        }
    }

    private static final class QueryCollector {
        final List<NostrEvent> events = new CopyOnWriteArrayList<>();
        final CountDownLatch eose;
        QueryCollector(int relayCount) { eose = new CountDownLatch(relayCount); }
    }
}