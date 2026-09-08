package ra.did.nostr;

/**
 * {@code EXPORT_NSEC} — the {@code nsec1…} form of a held identity's secret.
 *
 * <p>This exposes the entire identity (§6.3): the caller MUST have obtained an
 * explicit, separately-confirmed user action first and set {@link #confirmed}.
 * The service refuses without it, logs the export, and does not include the
 * result in any {@code toMap()}.
 */
public class ExportNsecRequest extends NostrRequest {

    public static final int CONFIRMATION_REQUIRED = 20;

    /** x-only pubkey (hex or npub) of the identity to export. Must be one the service holds. */
    public String pubkey;
    /** Passphrase, if the identity is only persisted and not already in memory. Not serialised. */
    public String passphrase;
    /** MUST be set by the caller after an explicit user confirmation. */
    public boolean confirmed;

    // Response — not serialised.
    public String nsec;
}
