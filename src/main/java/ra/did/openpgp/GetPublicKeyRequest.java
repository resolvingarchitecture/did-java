package ra.did.openpgp;

import ra.did.DIDRequest;

import org.bouncycastle.openpgp.PGPPublicKey;

public class GetPublicKeyRequest extends DIDRequest {

    public static int ALIAS_OR_FINGERPRINT_REQUIRED = 2;
    public static int LOCATION_OR_USERNAME_REQUIRED = 3;

    public boolean master = true;
    // Alias used to retrieve master public key
    public String alias;
    // Fingerprint used to retrieve sub public key
    public byte[] fingerprint;
    // The key-ring collection to read from
    public String location;
    public String keyRingUsername;
    // Response
    public PGPPublicKey publicKey;
}
