package ra.did.nostr.relay;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import ra.did.nostr.NostrEvent;

import java.lang.reflect.Type;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * One relay connection speaking the NIP-01 wire protocol
 * (REQ/EVENT/EOSE/OK/CLOSE/CLOSED/NOTICE) - the {@code NostrRelayAdapter} named
 * in {@code 1m5-android/DESIGN.md} §"Nostr Integration and Portable Identity".
 * One instance per relay URL; {@link NostrRelayPool} is the normal entry point
 * for talking to a curated relay set rather than one relay directly.
 *
 * <p>Every inbound event is run through {@link NostrEvent#verify()} before it
 * reaches the listener - "malformed events, relays, and identifiers must be
 * rejected before storage or display" (`1m5-android/DESIGN.md`
 * §"Nostr Integration", "Requirements").
 */
public final class NostrRelayClient {

    private static final Logger LOG = Logger.getLogger(NostrRelayClient.class.getName());
    private static final Gson GSON = new Gson();
    private static final Type STRING_OBJECT_MAP = new TypeToken<Map<String, Object>>() {}.getType();
    private static final NostrRelayListener NOOP_LISTENER = new NostrRelayListener() {};

    private static final ScheduledExecutorService TIMEOUTS = Executors.newSingleThreadScheduledExecutor(
            (ThreadFactory) r -> {
                Thread t = new Thread(r, "nostr-relay-timeout");
                t.setDaemon(true);
                return t;
            });

    private final String relayUrl;
    private final NostrRelayListener listener;
    private final WebSocketClient ws;
    private final Map<String, CompletableFuture<PublishResult>> pendingPublishes = new ConcurrentHashMap<>();

    public NostrRelayClient(String relayUrl, NostrRelayListener listener) {
        this.relayUrl = relayUrl;
        this.listener = listener == null ? NOOP_LISTENER : listener;
        this.ws = new WebSocketClient(URI.create(relayUrl)) {
            @Override
            public void onOpen(ServerHandshake handshake) {
                NostrRelayClient.this.listener.onConnected(relayUrl);
            }

            @Override
            public void onMessage(String message) {
                handleMessage(message);
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                failAllPending("connection closed: " + reason);
                NostrRelayClient.this.listener.onDisconnected(relayUrl, reason);
            }

            @Override
            public void onError(Exception ex) {
                LOG.log(Level.WARNING, relayUrl + ": websocket error", ex);
            }
        };
    }

    public String url() { return relayUrl; }

    public boolean isOpen() { return ws.isOpen(); }

    public void connect() { ws.connect(); }

    public boolean connectBlocking(long timeout, TimeUnit unit) throws InterruptedException {
        return ws.connectBlocking(timeout, unit);
    }

    public void close() {
        failAllPending("client closed");
        ws.close();
    }

    public void subscribe(String subscriptionId, NostrFilter... filters) {
        JsonArray envelope = new JsonArray();
        envelope.add("REQ");
        envelope.add(subscriptionId);
        for (NostrFilter f : filters) envelope.add(f.toJson());
        send(GSON.toJson(envelope));
    }

    public void unsubscribe(String subscriptionId) {
        JsonArray envelope = new JsonArray();
        envelope.add("CLOSE");
        envelope.add(subscriptionId);
        send(GSON.toJson(envelope));
    }

    /** Publishes an already-signed event; resolves on this relay's {@code OK}, or after {@code timeoutMs}. */
    public CompletableFuture<PublishResult> publish(NostrEvent event, long timeoutMs) {
        CompletableFuture<PublishResult> future = new CompletableFuture<>();
        pendingPublishes.put(event.getId(), future);
        try {
            send("[\"EVENT\"," + event.toJson() + "]");
        } catch (RuntimeException e) {
            pendingPublishes.remove(event.getId());
            future.complete(new PublishResult(relayUrl, false, "send failed: " + e.getMessage()));
            return future;
        }
        TIMEOUTS.schedule(
                () -> completePublish(event.getId(), new PublishResult(relayUrl, false, "timeout")),
                timeoutMs, TimeUnit.MILLISECONDS);
        return future;
    }

    private void send(String text) {
        if (!ws.isOpen()) throw new IllegalStateException(relayUrl + " is not connected");
        ws.send(text);
    }

    private void handleMessage(String message) {
        JsonArray envelope;
        try {
            envelope = JsonParser.parseString(message).getAsJsonArray();
        } catch (RuntimeException e) {
            LOG.warning(relayUrl + ": malformed relay message, ignored: " + e.getMessage());
            return;
        }
        if (envelope.isEmpty()) return;
        String type = envelope.get(0).getAsString();
        switch (type) {
            case "EVENT": handleEvent(envelope); break;
            case "EOSE": if (envelope.size() > 1) listener.onEose(relayUrl, envelope.get(1).getAsString()); break;
            case "OK": handleOk(envelope); break;
            case "CLOSED":
                if (envelope.size() > 1) {
                    listener.onClosed(relayUrl, envelope.get(1).getAsString(),
                            envelope.size() > 2 ? envelope.get(2).getAsString() : "");
                }
                break;
            case "NOTICE": if (envelope.size() > 1) listener.onNotice(relayUrl, envelope.get(1).getAsString()); break;
            default: LOG.fine(relayUrl + ": ignoring unknown relay message type " + type);
        }
    }

    private void handleEvent(JsonArray envelope) {
        if (envelope.size() < 3) return;
        String subId = envelope.get(1).getAsString();
        NostrEvent event = decodeEvent(envelope.get(2).getAsJsonObject());
        if (event == null) return;
        NostrEvent.VerifyResult vr = event.verify();
        if (!vr.ok) {
            LOG.warning(relayUrl + ": dropped event " + event.getId() + " failing verification step " + vr.step
                    + ": " + vr.reason);
            return;
        }
        listener.onEvent(relayUrl, subId, event);
    }

    private void handleOk(JsonArray envelope) {
        if (envelope.size() < 3) return;
        String eventId = envelope.get(1).getAsString();
        boolean accepted = envelope.get(2).getAsBoolean();
        String message = envelope.size() > 3 ? envelope.get(3).getAsString() : "";
        completePublish(eventId, new PublishResult(relayUrl, accepted, message));
    }

    private NostrEvent decodeEvent(JsonObject obj) {
        try {
            Map<String, Object> map = GSON.fromJson(obj, STRING_OBJECT_MAP);
            return NostrEvent.fromMap(map);
        } catch (RuntimeException e) {
            LOG.warning(relayUrl + ": malformed event, dropped: " + e.getMessage());
            return null;
        }
    }

    private void completePublish(String eventId, PublishResult result) {
        CompletableFuture<PublishResult> future = pendingPublishes.remove(eventId);
        if (future != null) future.complete(result);
    }

    private void failAllPending(String reason) {
        pendingPublishes.forEach((id, f) -> f.complete(new PublishResult(relayUrl, false, reason)));
        pendingPublishes.clear();
    }
}