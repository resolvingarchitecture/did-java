package ra.did.nostr.relay;

import ra.did.nostr.NostrEvent;

/**
 * Relay wire callbacks. One instance is normally shared across every relay in a
 * {@link NostrRelayPool} - implementations that care which relay an event came
 * from use the {@code relayUrl} parameter, not separate listener instances.
 */
public interface NostrRelayListener {

    /** A verified event matching an active subscription. Already passed {@link NostrEvent#verify()}. */
    default void onEvent(String relayUrl, String subscriptionId, NostrEvent event) {}

    /** This relay has sent everything it currently has for a subscription (stored events; live ones keep streaming). */
    default void onEose(String relayUrl, String subscriptionId) {}

    /** The relay closed a subscription server-side (NIP-01 {@code CLOSED}). */
    default void onClosed(String relayUrl, String subscriptionId, String message) {}

    /** A relay-level {@code NOTICE}, human-readable only - never used for control flow. */
    default void onNotice(String relayUrl, String message) {}

    default void onConnected(String relayUrl) {}

    default void onDisconnected(String relayUrl, String reason) {}
}