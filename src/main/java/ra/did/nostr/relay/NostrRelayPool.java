package ra.did.nostr.relay;

import ra.did.nostr.NostrEvent;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A small curated relay set managed as one logical connection - "direct
 * {@code wss} connections to a small curated relay set" per
 * {@code 1m5-android/DESIGN.md} §"Relay and Transport Policy". Events are
 * deduplicated by id across relays before reaching the shared
 * {@link NostrRelayListener}, and a publish fans out to every connected relay
 * and reports each one's result individually rather than collapsing to a
 * single pass/fail - "per-relay publish results must be surfaced to the user
 * and to diagnostics" (same section).
 */
public final class NostrRelayPool {

    /** The relay set {@code did/scripts/publish-drafts.cjs} already publishes to, plus 1M5's own node - always included, not just a fallback. */
    public static final List<String> DEFAULT_RELAYS = Collections.unmodifiableList(Arrays.asList(
            "wss://resolvingarchitecture.io/apps/nostr/node",
            "wss://relay.damus.io",
            "wss://nos.lol",
            "wss://relay.primal.net",
            "wss://nostr.mom",
            "wss://offchain.pub",
            "wss://relay.highlighter.com",
            "wss://purplerelay.com"
    ));

    private final Map<String, NostrRelayClient> clients = new LinkedHashMap<>();
    private final Set<String> seenEventIds = ConcurrentHashMap.newKeySet();
    private final AtomicLong subCounter = new AtomicLong();

    public NostrRelayPool(Collection<String> relayUrls, NostrRelayListener listener) {
        NostrRelayListener dedup = new DedupingListener(listener == null ? new NostrRelayListener() {} : listener);
        for (String url : relayUrls) {
            clients.put(url, new NostrRelayClient(url, dedup));
        }
    }

    public static NostrRelayPool withDefaultRelays(NostrRelayListener listener) {
        return new NostrRelayPool(DEFAULT_RELAYS, listener);
    }

    public void connectAll() {
        for (NostrRelayClient c : clients.values()) c.connect();
    }

    public void close() {
        for (NostrRelayClient c : clients.values()) c.close();
    }

    public List<String> relayUrls() { return new ArrayList<>(clients.keySet()); }

    public int connectedCount() {
        int n = 0;
        for (NostrRelayClient c : clients.values()) if (c.isOpen()) n++;
        return n;
    }

    /** A fresh subscription id, unique within this pool. */
    public String newSubscriptionId(String prefix) {
        return prefix + "-" + subCounter.incrementAndGet();
    }

    public void subscribeAll(String subscriptionId, NostrFilter... filters) {
        for (NostrRelayClient c : clients.values()) {
            if (c.isOpen()) c.subscribe(subscriptionId, filters);
        }
    }

    public void unsubscribeAll(String subscriptionId) {
        for (NostrRelayClient c : clients.values()) {
            if (c.isOpen()) c.unsubscribe(subscriptionId);
        }
    }

    /**
     * Publishes to every connected relay and waits (up to {@code timeoutMs} per
     * relay) for each OK/timeout. A relay that is not connected is reported as
     * a failed result rather than skipped silently - the caller (and, per the
     * design doc, the diagnostics surface) needs the full picture, and a
     * partial accept is a normal outcome here, not an exception.
     */
    public List<PublishResult> publish(NostrEvent event, long timeoutMs) {
        List<CompletableFuture<PublishResult>> futures = new ArrayList<>();
        List<PublishResult> results = new ArrayList<>();
        for (NostrRelayClient c : clients.values()) {
            if (c.isOpen()) {
                futures.add(c.publish(event, timeoutMs));
            } else {
                results.add(new PublishResult(c.url(), false, "not connected"));
            }
        }
        for (CompletableFuture<PublishResult> f : futures) {
            try {
                results.add(f.get(timeoutMs + 2000, TimeUnit.MILLISECONDS));
            } catch (Exception e) {
                results.add(new PublishResult("unknown", false, "publish future failed: " + e.getMessage()));
            }
        }
        return results;
    }

    private final class DedupingListener implements NostrRelayListener {
        private final NostrRelayListener delegate;

        DedupingListener(NostrRelayListener delegate) { this.delegate = delegate; }

        @Override
        public void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {
            if (seenEventIds.add(event.getId())) delegate.onEvent(relayUrl, subscriptionId, event);
        }

        @Override
        public void onEose(String relayUrl, String subscriptionId) { delegate.onEose(relayUrl, subscriptionId); }

        @Override
        public void onClosed(String relayUrl, String subscriptionId, String message) {
            delegate.onClosed(relayUrl, subscriptionId, message);
        }

        @Override
        public void onNotice(String relayUrl, String message) { delegate.onNotice(relayUrl, message); }

        @Override
        public void onConnected(String relayUrl) { delegate.onConnected(relayUrl); }

        @Override
        public void onDisconnected(String relayUrl, String reason) { delegate.onDisconnected(relayUrl, reason); }
    }
}