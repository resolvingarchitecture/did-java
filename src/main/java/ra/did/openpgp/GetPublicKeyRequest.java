package ra.did.openpgp;

import ra.did.DIDRequest;

import org.bouncycastle.openpgp.PGPPublicKey;

public class GetPublicKeyRequest extends DIDRequest {

    public static int ALIAS_OR_FINGERPRINT_REQUIRED = 2;

    public boolean master = true;
    // Alias used to retrieve master public key
    public String alias;
    // Fingerprint used to retrieve sub public key
    public byte[] fingerprint;
    // Response
    PGPPublicKey publicKey;
}
