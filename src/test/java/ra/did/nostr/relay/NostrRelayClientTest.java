package ra.did.nostr.relay;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ra.did.nostr.NostrEvent;
import ra.did.nostr.NostrIdentity;
import ra.did.nostr.NostrKeyRing;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class NostrRelayClientTest {

    private static final int PORT = 18765;
    private FakeRelay relay;
    private NostrRelayClient client;

    @BeforeEach
    public void start() throws InterruptedException {
        relay = new FakeRelay(PORT);
        relay.start();
        relay.awaitReady();
    }

    @AfterEach
    public void stop() throws InterruptedException {
        if (client != null) client.close();
        relay.stop(1000);
    }

    private NostrRelayClient connect(NostrRelayListener listener) throws InterruptedException {
        client = new NostrRelayClient("ws://127.0.0.1:" + PORT, listener);
        assertTrue(client.connectBlocking(5, TimeUnit.SECONDS), "client should connect to the fake relay");
        return client;
    }

    private static NostrEvent signedNote(String content) {
        NostrKeyRing ring = new NostrKeyRing();
        assertTrue(ring.init(new Properties()));
        NostrIdentity id = ring.generateIdentity();
        NostrEvent ev = NostrEvent.unsigned(1, new ArrayList<>(), content, 1_700_000_000L);
        return ring.sign(ev, id);
    }

    @Test
    public void publishResolvesAcceptedOnOk() throws Exception {
        connect(new NostrRelayListener() {});
        CompletableFuture<PublishResult> future = client.publish(signedNote("hello relay"), 5000);
        PublishResult result = future.get(5, TimeUnit.SECONDS);
        assertTrue(result.accepted);
        assertEquals("ws://127.0.0.1:" + PORT, result.relayUrl);
    }

    @Test
    public void publishResolvesRejectedWhenRelaySaysNo() throws Exception {
        relay.onEvent = json -> new Object[] {false, "blocked: spam"};
        connect(new NostrRelayListener() {});
        PublishResult result = client.publish(signedNote("spam"), 5000).get(5, TimeUnit.SECONDS);
        assertFalse(result.accepted);
        assertEquals("blocked: spam", result.message);
    }

    @Test
    public void publishTimesOutWhenRelayNeverAnswers() throws Exception {
        relay.sendOk = false; // relay accepts the connection but never replies
        connect(new NostrRelayListener() {});
        PublishResult result = client.publish(signedNote("into the void"), 300).get(5, TimeUnit.SECONDS);
        assertFalse(result.accepted);
        assertEquals("timeout", result.message);
    }

    @Test
    public void subscribeFiresEoseImmediatelyFromFakeRelay() throws Exception {
        CountDownLatch eose = new CountDownLatch(1);
        List<String> eoseSubIds = new CopyOnWriteArrayList<>();
        connect(new NostrRelayListener() {
            @Override
            public void onEose(String relayUrl, String subscriptionId) {
                eoseSubIds.add(subscriptionId);
                eose.countDown();
            }
        });
        client.subscribe("sub-1", new NostrFilter().kinds(1).limit(10));
        assertTrue(eose.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("sub-1"), eoseSubIds);
    }

    @Test
    public void relayPushedEventThatVerifiesReachesTheListener() throws Exception {
        NostrEvent signed = signedNote("pushed from the relay");
        CountDownLatch got = new CountDownLatch(1);
        AtomicInteger count = new AtomicInteger();
        connect(new NostrRelayListener() {
            @Override
            public void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {
                assertEquals(signed.getId(), event.getId());
                count.incrementAndGet();
                got.countDown();
            }
        });
        client.subscribe("sub-2", new NostrFilter().kinds(1));
        relay.pushEvent("sub-2", signed.toJson());
        assertTrue(got.await(5, TimeUnit.SECONDS));
        assertEquals(1, count.get());
    }

    @Test
    public void relayPushedEventThatFailsVerificationIsDropped() throws Exception {
        NostrEvent signed = signedNote("tampered after signing");
        signed.setContent("this content was changed post-signature");
        CountDownLatch never = new CountDownLatch(1);
        connect(new NostrRelayListener() {
            @Override
            public void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {
                never.countDown();
            }
        });
        client.subscribe("sub-3", new NostrFilter().kinds(1));
        relay.pushEvent("sub-3", signed.toJson());
        assertFalse(never.await(500, TimeUnit.MILLISECONDS), "a tampered event must never reach the listener");
    }

    @Test
    public void noticeReachesTheListener() throws Exception {
        CountDownLatch got = new CountDownLatch(1);
        List<String> notices = new CopyOnWriteArrayList<>();
        connect(new NostrRelayListener() {
            @Override
            public void onNotice(String relayUrl, String message) {
                notices.add(message);
                got.countDown();
            }
        });
        relay.pushNotice("rate limited");
        assertTrue(got.await(5, TimeUnit.SECONDS));
        assertEquals(List.of("rate limited"), notices);
    }
}