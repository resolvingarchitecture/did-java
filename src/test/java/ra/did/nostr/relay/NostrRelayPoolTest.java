package ra.did.nostr.relay;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ra.did.nostr.NostrEvent;
import ra.did.nostr.NostrIdentity;
import ra.did.nostr.NostrKeyRing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class NostrRelayPoolTest {

    private FakeRelay relayA;
    private FakeRelay relayB;
    private NostrRelayPool pool;

    @BeforeEach
    public void start() throws InterruptedException {
        relayA = new FakeRelay(18771);
        relayB = new FakeRelay(18772);
        relayA.start();
        relayB.start();
        relayA.awaitReady();
        relayB.awaitReady();
    }

    @AfterEach
    public void stop() throws InterruptedException {
        if (pool != null) pool.close();
        relayA.stop(1000);
        relayB.stop(1000);
    }

    private static NostrEvent signedNote(String content) {
        NostrKeyRing ring = new NostrKeyRing();
        assertTrue(ring.init(new Properties()));
        NostrIdentity id = ring.generateIdentity();
        NostrEvent ev = NostrEvent.unsigned(1, new ArrayList<>(), content, 1_700_000_000L);
        return ring.sign(ev, id);
    }

    @Test
    public void publishFansOutAndReportsEachRelaySeparately() throws Exception {
        relayB.onEvent = json -> new Object[] {false, "policy: rejected"};
        pool = new NostrRelayPool(
                Arrays.asList("ws://127.0.0.1:18771", "ws://127.0.0.1:18772"), new NostrRelayListener() {});
        pool.connectAll();
        awaitConnected(pool, 2);

        List<PublishResult> results = pool.publish(signedNote("hello pool"), 5000);
        assertEquals(2, results.size());
        assertEquals(1, results.stream().filter(r -> r.accepted).count());
        assertEquals(1, results.stream().filter(r -> !r.accepted).count());
    }

    @Test
    public void duplicateEventFromTwoRelaysReachesListenerOnce() throws Exception {
        NostrEvent signed = signedNote("same event, two relays");
        AtomicInteger count = new AtomicInteger();
        List<String> sourceRelays = new CopyOnWriteArrayList<>();
        CountDownLatch first = new CountDownLatch(1);

        pool = new NostrRelayPool(
                Arrays.asList("ws://127.0.0.1:18771", "ws://127.0.0.1:18772"), new NostrRelayListener() {
                    @Override
                    public void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {
                        sourceRelays.add(relayUrl);
                        count.incrementAndGet();
                        first.countDown();
                    }
                });
        pool.connectAll();
        awaitConnected(pool, 2);

        String subId = pool.newSubscriptionId("feed");
        pool.subscribeAll(subId, new NostrFilter().kinds(1));
        relayA.pushEvent(subId, signed.toJson());
        assertTrue(first.await(5, TimeUnit.SECONDS));
        relayB.pushEvent(subId, signed.toJson());
        Thread.sleep(300); // give the (would-be) second delivery a chance to arrive

        assertEquals(1, count.get(), "the same event id from a second relay must be deduplicated");
        assertEquals(1, sourceRelays.size());
    }

    private static void awaitConnected(NostrRelayPool pool, int expected) throws InterruptedException {
        for (int i = 0; i < 50 && pool.connectedCount() < expected; i++) Thread.sleep(100);
        assertEquals(expected, pool.connectedCount());
    }
}