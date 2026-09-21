package ra.did.nostr.relay;

/**
 * {@link ra.common.Envelope} operation/header names for {@link NostrRelayService}.
 * Deliberately generic (publish/query a signed event, not "post a note" /
 * "follow someone") - kind-specific event construction stays where it already
 * lives (plain {@link ra.did.nostr.NostrEvent#unsigned} for kinds 0/1/3,
 * {@link ra.did.nostr.NostrAttestations} for kind 30100,
 * {@link ra.did.nostr.NostrRotation} for kinds 30101-30103); this service only
 * moves already-signed events to and from the relay set.
 */
public interface NostrRelayOps {

    String OPERATION_PUBLISH = "PUBLISH";
    String OPERATION_QUERY = "QUERY";
    String OPERATION_STATUS = "STATUS";

    /** Request (PUBLISH): a signed event, compact JSON ({@link ra.did.nostr.NostrEvent#toJson()}). */
    String HEADER_EVENT_JSON = "nostr.eventJson";
    /** Response (PUBLISH): JSON array of {@code {"relay":..,"accepted":..,"message":..}}. */
    String HEADER_RESULTS_JSON = "nostr.resultsJson";
    /** Request (QUERY): a NIP-01 filter object, JSON ({@link NostrFilter#toJson()}). */
    String HEADER_FILTER_JSON = "nostr.filterJson";
    /** Request (PUBLISH, QUERY), optional: how long to wait, in milliseconds. */
    String HEADER_TIMEOUT_MS = "nostr.timeoutMs";
    /** Response (QUERY): JSON array of raw signed event objects, deduplicated across relays. */
    String HEADER_EVENTS_JSON = "nostr.eventsJson";
    /** Response (STATUS). */
    String HEADER_CONNECTED_RELAYS = "nostr.connectedRelays";
    String HEADER_TOTAL_RELAYS = "nostr.totalRelays";
}