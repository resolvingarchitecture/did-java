package ra.did.openpgp;

import ra.did.DIDRequest;

import ra.common.identity.DID;

import static ra.did.HashStrength.HASH_STRENGTH_64;

public class GenerateKeyRingRequest extends DIDRequest {

    public static int KEYRING_USERNAME_REQUIRED = 2;
    public static int KEYRING_PASSPHRASE_REQUIRED = 3;
    public static int KEYRING_DID_TYPE_REQURIED = 4;
    public static int ALIAS_REQUIRED = 5;
    public static int ALIAS_PASSPHRASE_REQUIRED = 6;
    public static int KEYRING_LOCATION_REQUIRED = 7;
    public static int KEYRING_LOCATION_INACCESSIBLE = 8;

    public String location;
    public String keyRingUsername;
    public String keyRingPassphrase;
    public DID.DIDType type;
    public String alias;
    public String aliasPassphrase;
    public int hashStrength = HASH_STRENGTH_64;
}
