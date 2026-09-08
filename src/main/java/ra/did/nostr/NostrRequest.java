package ra.did.nostr;

import ra.common.service.ServiceMessage;

/**
 * Base for the {@code ra.did.nostr} bus requests handled by
 * {@link ra.did.DIDService}. Carries only the shared {@code successful} flag; the
 * {@code ServiceMessage} base provides {@code statusCode} / {@code errorMessage}
 * / {@code exception}.
 *
 * <p>Secret key material set on a subclass is a plain field and is deliberately
 * <em>not</em> included in {@code toMap()} (§6.3) — these requests are in-process
 * carriers, not something to route across services.
 */
public abstract class NostrRequest extends ServiceMessage {

    public static final int SIGNER_REQUIRED = 1;
    public static final int SIGNER_NOT_FOUND = 2;
    public static final int SUBJECT_REQUIRED = 3;
    public static final int INVALID_INPUT = 4;

    public boolean successful = false;

    /** Set on the builder operations: the signed event, and its compact JSON. */
    public NostrEvent event;
    public String eventJson;

    /** Record a produced-and-signed event as the result. */
    public void setResultEvent(NostrEvent ev) {
        this.event = ev;
        this.eventJson = ev.toJson();
        this.successful = true;
    }
}
