package ra.did.nostr.relay;

/** One relay's answer to a published event: its {@code OK} frame, or a local timeout/skip. */
public final class PublishResult {

    public final String relayUrl;
    public final boolean accepted;
    public final String message;

    public PublishResult(String relayUrl, boolean accepted, String message) {
        this.relayUrl = relayUrl;
        this.accepted = accepted;
        this.message = message == null ? "" : message;
    }

    @Override
    public String toString() {
        return (accepted ? "OK  " : "FAIL") + " " + relayUrl + (message.isEmpty() ? "" : " (" + message + ")");
    }
}