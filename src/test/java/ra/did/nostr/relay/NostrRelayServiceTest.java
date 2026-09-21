package ra.did.nostr.relay;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ra.common.Client;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.did.nostr.NostrEvent;
import ra.did.nostr.NostrIdentity;
import ra.did.nostr.NostrKeyRing;

import java.util.ArrayList;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end through {@link NostrRelayService#handleDocument}, against real
 * {@link FakeRelay} instances (in-process, no live network) rather than
 * mocking the pool - same reasoning {@code BitcoinServiceIntegrationTest}
 * gives for exercising bitcoinj's RegTest network instead of a mocked wallet.
 */
public class NostrRelayServiceTest {

    private FakeRelay relay;
    private NostrRelayService service;

    @BeforeEach
    public void start() throws InterruptedException {
        relay = new FakeRelay(18780);
        relay.start();
        relay.awaitReady();

        Properties p = new Properties();
        p.setProperty(NostrRelayService.PROP_RELAYS, "ws://127.0.0.1:18780");
        service = new NostrRelayService();
        service.setProducer(new NoOpProducer());
        assertTrue(service.start(p));
    }

    @AfterEach
    public void stop() {
        service.gracefulShutdown();
        try {
            relay.stop(1000);
        } catch (InterruptedException ignored) {
        }
    }

    private static NostrEvent signedNote(String content) {
        NostrKeyRing ring = new NostrKeyRing();
        assertTrue(ring.init(new Properties()));
        NostrIdentity id = ring.generateIdentity();
        NostrEvent ev = NostrEvent.unsigned(1, new ArrayList<>(), content, 1_700_000_000L);
        return ring.sign(ev, id);
    }

    @Test
    public void statusReportsTheConnectedRelay() {
        Envelope e = Envelope.documentFactory();
        e.addRoute(NostrRelayService.class.getName(), NostrRelayOps.OPERATION_STATUS);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        service.handleDocument(e);
        assertEquals("1", String.valueOf(e.getHeader(NostrRelayOps.HEADER_CONNECTED_RELAYS)));
        assertEquals("1", String.valueOf(e.getHeader(NostrRelayOps.HEADER_TOTAL_RELAYS)));
    }

    @Test
    public void publishRoundTripsAResultPerRelay() {
        NostrEvent event = signedNote("hello from the service layer");
        Envelope e = Envelope.documentFactory();
        e.addRoute(NostrRelayService.class.getName(), NostrRelayOps.OPERATION_PUBLISH);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        e.setHeader(NostrRelayOps.HEADER_EVENT_JSON, event.toJson());
        service.handleDocument(e);

        assertTrue(ra.common.Envelope.getErrorMessages(e).isEmpty(), () -> String.valueOf(ra.common.Envelope.getErrorMessages(e)));
        JsonArray results = JsonParser.parseString(String.valueOf(e.getHeader(NostrRelayOps.HEADER_RESULTS_JSON))).getAsJsonArray();
        assertEquals(1, results.size());
        assertTrue(results.get(0).getAsJsonObject().get("accepted").getAsBoolean());
    }

    @Test
    public void publishRejectsATamperedEventBeforeItReachesTheRelay() {
        NostrEvent event = signedNote("original");
        event.setContent("tampered after signing");
        Envelope e = Envelope.documentFactory();
        e.addRoute(NostrRelayService.class.getName(), NostrRelayOps.OPERATION_PUBLISH);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        e.setHeader(NostrRelayOps.HEADER_EVENT_JSON, event.toJson());
        service.handleDocument(e);

        assertFalse(ra.common.Envelope.getErrorMessages(e).isEmpty());
        assertTrue(relay.receivedRaw.isEmpty(), "a tampered event must never be sent to the relay");
    }

    @Test
    public void queryReturnsAPushedEventAfterEose() {
        NostrEvent pushed = signedNote("query me");
        Envelope e = Envelope.documentFactory();
        e.addRoute(NostrRelayService.class.getName(), NostrRelayOps.OPERATION_QUERY);
        e.setRoute(e.getDynamicRoutingSlip().nextRoute());
        e.setHeader(NostrRelayOps.HEADER_FILTER_JSON, new NostrFilter().kinds(1).toJson().toString());

        relay.sendEose = false; // hold EOSE so the pushed event is guaranteed to land first
        Thread pusher = new Thread(() -> {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ignored) {
            }
            // subscription id is server-assigned by the client; the fake relay doesn't need to know it
            // to push - it just echoes whatever subId the client used in its REQ.
            String subId = lastReqSubId();
            relay.pushEvent(subId, pushed.toJson());
            relay.sendEose = true;
            relay.pushEoseFor(subId);
        });
        pusher.start();

        service.handleDocument(e);

        JsonArray events = JsonParser.parseString(String.valueOf(e.getHeader(NostrRelayOps.HEADER_EVENTS_JSON))).getAsJsonArray();
        assertEquals(1, events.size());
        assertEquals(pushed.getId(), events.get(0).getAsJsonObject().get("id").getAsString());
    }

    private String lastReqSubId() {
        for (int i = relay.receivedRaw.size() - 1; i >= 0; i--) {
            JsonArray env = JsonParser.parseString(relay.receivedRaw.get(i)).getAsJsonArray();
            if ("REQ".equals(env.get(0).getAsString())) return env.get(1).getAsString();
        }
        throw new IllegalStateException("no REQ observed yet");
    }

    private static final class NoOpProducer implements MessageProducer {
        @Override public boolean send(Envelope envelope) { return true; }
        @Override public boolean send(Envelope envelope, Client client) { return true; }
        @Override public boolean deadLetter(Envelope envelope) { return true; }
    }
}