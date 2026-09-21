package ra.did.nostr.relay;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * A minimal, in-process NIP-01 relay for tests - no network, no flakiness, and
 * full control over what the "relay" says back. Not a spec-complete relay: it
 * only speaks the subset {@link NostrRelayClient} exercises.
 */
final class FakeRelay extends WebSocketServer {

    /** {@code (eventJson) -> [accepted, message]}. Default: accept everything. */
    volatile Function<String, Object[]> onEvent = json -> new Object[] {true, ""};
    volatile boolean sendEose = true;
    /** Set false to receive EVENT frames but never reply with OK - exercises the client's publish timeout. */
    volatile boolean sendOk = true;
    final List<String> receivedRaw = new CopyOnWriteArrayList<>();
    private final CountDownLatch ready = new CountDownLatch(1);

    FakeRelay(int port) {
        super(new InetSocketAddress("127.0.0.1", port));
        setReuseAddr(true);
    }

    void awaitReady() throws InterruptedException {
        if (!ready.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("fake relay never started");
    }

    @Override
    public void onStart() { ready.countDown(); }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {}

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {}

    @Override
    public void onError(WebSocket conn, Exception ex) {}

    @Override
    public void onMessage(WebSocket conn, String message) {
        receivedRaw.add(message);
        JsonArray envelope = JsonParser.parseString(message).getAsJsonArray();
        String type = envelope.get(0).getAsString();
        if ("EVENT".equals(type)) {
            String eventJson = envelope.get(1).toString();
            String eventId = envelope.get(1).getAsJsonObject().get("id").getAsString();
            Object[] outcome = onEvent.apply(eventJson);
            if (sendOk) conn.send("[\"OK\",\"" + eventId + "\"," + outcome[0] + ",\"" + outcome[1] + "\"]");
        } else if ("REQ".equals(type)) {
            String subId = envelope.get(1).getAsString();
            if (sendEose) conn.send("[\"EOSE\",\"" + subId + "\"]");
        }
        // CLOSE: nothing to do for these tests.
    }

    /** Pushes a relay-authored EVENT frame to every connected client, as-is. */
    void pushEvent(String subscriptionId, String rawEventJson) {
        String frame = "[\"EVENT\",\"" + subscriptionId + "\"," + rawEventJson + "]";
        for (WebSocket c : new ArrayList<>(getConnections())) c.send(frame);
    }

    void pushNotice(String message) {
        for (WebSocket c : new ArrayList<>(getConnections())) c.send("[\"NOTICE\",\"" + message + "\"]");
    }

    void pushEoseFor(String subscriptionId) {
        for (WebSocket c : new ArrayList<>(getConnections())) c.send("[\"EOSE\",\"" + subscriptionId + "\"]");
    }
}