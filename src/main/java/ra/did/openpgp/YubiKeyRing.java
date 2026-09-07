package ra.did.openpgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.usb4java.*;

import java.io.IOException;
import java.util.Properties;
import java.util.logging.Logger;

public class YubiKeyRing implements KeyRing {

    private static final Logger LOG = Logger.getLogger(YubiKeyRing.class.getName());

    /** The vendor ID of the Yubikey. */
    private static final short VENDOR_ID = 0x1050;
    /** The product ID of the Yubikey. */
    //private static final short PRODUCT_ID = 0x0114;
    //private static final short PRODUCT_ID2 = 0x0111;
    private static final short[] PRODUCT_ID_NEO = {0x0111, 0x0114};

    private boolean initialized = false;

    @Override
    public boolean init(Properties properties) {
        // Initialize the libusb context
        int result = LibUsb.init(null);
        if (result != LibUsb.SUCCESS){
            LOG.warning("Unable to initialize libusb. Error code: "+result);
            return initialized;
        }

        // Search for the missile launcher USB device and stop when not found
        Device device = findYubikey(PRODUCT_ID_NEO);
        if (device == null){
            LOG.info("Yubikey not found.");
            return initialized;
        }

        // Open the device
        DeviceHandle handle = new DeviceHandle();
        result = LibUsb.open(device, handle);
        if (result != LibUsb.SUCCESS) {
            LOG.warning("Unable to initialize libusb. Error code: "+result);
            return initialized;
        }

        // TODO: Continue initialization

        return initialized;
    }

    @Override
    public void generateKeyRingCollections(GenerateKeyRingCollectionsRequest r) throws IOException, PGPException {

    }

    @Override
    public PGPPublicKeyRingCollection getPublicKeyRingCollection(String location, String username) throws IOException, PGPException {
        return null;
    }

    @Override
    public PGPPublicKey getPublicKey(PGPPublicKeyRingCollection c, String keyAlias, boolean master) throws PGPException {
        return null;
    }

    @Override
    public void createKeyRings(String location, String keyRingUsername, String keyRingPassphrase, String alias, String aliasPassphrase, int hashStrength, String keyRingImplementation) throws IOException, PGPException {

    }

    @Override
    public void encrypt(EncryptRequest r) throws IOException, PGPException {

    }

    @Override
    public void decrypt(DecryptRequest r) throws IOException, PGPException {

    }

    @Override
    public void sign(SignRequest r) throws IOException, PGPException {

    }

    @Override
    public void verifySignature(VerifySignatureRequest r) throws IOException, PGPException {

    }

    /**
     * Searches for the yubikey device and returns it. If there are
     * multiple yubikeys attached then this simple demo only returns
     * the first one.
     *
     * @return The yubikey USB device or null if not found.
     */
    Device findYubikey(short[] pids){
        // Read the USB device list
        DeviceList list = new DeviceList();
        int result = LibUsb.getDeviceList(null, list);
        if (result < 0){
            throw new RuntimeException("Unable to get device list. Result=" + result);
        }

        try{
            // Iterate over all devices and scan for the missile launcher
            for (Device device: list){
                DeviceDescriptor descriptor = new DeviceDescriptor();
                result = LibUsb.getDeviceDescriptor(device, descriptor);
                LOG.info(descriptor.dump());

                if (result < 0){
                    throw new RuntimeException("Unable to read device descriptor. Result=" + result);
                }
                if (descriptor.idVendor() == VENDOR_ID && contains(pids, descriptor.idProduct())) {
                    LOG.info("Found device:"+device.toString());
                    return device;
                }
            }
        }
        finally{
            // Ensure the allocated device list is freed
            //LibUsb.freeDeviceList(list, true);
            LibUsb.freeDeviceList(list, false);
        }

        // No yubikey found
        return null;
    }

    private boolean contains(short[] pids, short pid){
        for (int i=0; i<pids.length; i++){
            if (pids[i]==pid)
                return true;
        }
        return false;
    }
}
