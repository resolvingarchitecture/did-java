package ra.did.nostr;

/**
 * {@code DELETE_NOSTR_IDENTITY} — remove a held/persisted identity: drop it from
 * memory and delete its encrypted file. Irreversible.
 */
public class DeleteNostrIdentityRequest extends NostrRequest {

    /** x-only pubkey (hex or npub) of the identity to remove. */
    public String pubkey;

    // Response
    public boolean removedFromMemory;
    public boolean deletedFromDisk;
}
