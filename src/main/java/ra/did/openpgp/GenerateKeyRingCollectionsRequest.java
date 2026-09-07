package ra.did.openpgp;

import ra.did.DIDRequest;

import ra.common.identity.DID;
import ra.common.identity.PublicKey;

import static ra.did.HashStrength.HASH_STRENGTH_64;

public class GenerateKeyRingCollectionsRequest extends DIDRequest {
    public static int REQUEST_REQUIRED = 1;
    public static int KEY_RING_USERNAME_REQUIRED = 2;
    public static int KEY_RING_PASSPHRASE_REQUIRED = 3;
    public static int KEY_RING_DID_TYPE_REQUIRED = 4;
    public static int KEY_RING_USERNAME_TAKEN = 5;
    public static int KEY_RING_LOCATION_INACCESSIBLE = 6;

    // Required
    public String location;
    // Required
    public String keyRingUsername;
    // Required
    public String keyRingPassphrase;
    // Required
    public DID.DIDType didType;

    public int hashStrength = HASH_STRENGTH_64; // default

    public boolean persist = true;

    // Response is publicKey associated with key ring username (default)
    public PublicKey identityPublicKey;
    public PublicKey encryptionPublicKey;

}
