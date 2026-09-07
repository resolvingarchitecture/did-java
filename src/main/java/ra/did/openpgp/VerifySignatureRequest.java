package ra.did.openpgp;

import ra.did.DIDRequest;

import ra.common.identity.DID;

public class VerifySignatureRequest extends DIDRequest {

    public static int LOCATION_REQUIRED = 2;
    public static int LOCATION_INACCESSIBLE = 3;

    // Request
    public String location;
    public String keyRingUsername;
    public String keyRingPassphrase;
    public String alias;
    public DID.DIDType type;
    public byte[] contentSigned;
    public byte[] signature;
    public byte[] fingerprint;
    // Response
    public boolean verified = false;
}
