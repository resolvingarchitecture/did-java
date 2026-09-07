package ra.did;

import ra.common.service.ServiceMessage;

public abstract class DIDRequest extends ServiceMessage {

    public static int KEY_RING_IMPLEMENTATION_UNKNOWN = 1;

    // Default key-ring implementation. A string (not OpenPGPKeyRing.class) so the
    // base request package does not depend on ra.did.openpgp.
    public String keyRingImplementation = "ra.did.openpgp.OpenPGPKeyRing";

    public Boolean successful = false;
}
