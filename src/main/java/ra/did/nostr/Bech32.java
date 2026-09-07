package ra.did.nostr;

import java.util.Locale;

/**
 * Bech32 (BIP-173) encoding, as used by NIP-19 for {@code npub} / {@code nsec}.
 *
 * NIP-19 uses Bech32, not Bech32m, and lifts the 90-character length limit, so
 * this implementation applies the original constant ({@code 1}) and does not cap
 * length.
 *
 * Port of Pieter Wuille's BIP-173 reference implementation.
 */
final class Bech32 {

    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int[] GENERATOR = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};

    private Bech32() {}

    static String encode(String hrp, byte[] data) {
        byte[] values = convertBits(data, 8, 5, true);
        byte[] checksum = createChecksum(hrp, values);
        byte[] combined = new byte[values.length + checksum.length];
        System.arraycopy(values, 0, combined, 0, values.length);
        System.arraycopy(checksum, 0, combined, values.length, checksum.length);
        StringBuilder sb = new StringBuilder(hrp.length() + 1 + combined.length);
        sb.append(hrp).append('1');
        for (byte b : combined) sb.append(CHARSET.charAt(b));
        return sb.toString();
    }

    /** @return {hrp, decoded-8-bit-bytes} */
    static Object[] decode(String bech) {
        if (!bech.equals(bech.toLowerCase(Locale.ROOT)) && !bech.equals(bech.toUpperCase(Locale.ROOT))) {
            throw new IllegalArgumentException("bech32: mixed case");
        }
        bech = bech.toLowerCase(Locale.ROOT);
        int pos = bech.lastIndexOf('1');
        if (pos < 1 || pos + 7 > bech.length()) {
            throw new IllegalArgumentException("bech32: invalid separator position");
        }
        String hrp = bech.substring(0, pos);
        byte[] values = new byte[bech.length() - 1 - pos];
        for (int i = 0; i < values.length; i++) {
            int d = CHARSET.indexOf(bech.charAt(pos + 1 + i));
            if (d == -1) throw new IllegalArgumentException("bech32: invalid data character");
            values[i] = (byte) d;
        }
        if (!verifyChecksum(hrp, values)) {
            throw new IllegalArgumentException("bech32: bad checksum");
        }
        byte[] payload = new byte[values.length - 6];
        System.arraycopy(values, 0, payload, 0, payload.length);
        return new Object[]{hrp, convertBits(payload, 5, 8, false)};
    }

    private static int polymod(byte[] values) {
        int chk = 1;
        for (byte value : values) {
            int top = chk >>> 25;
            chk = (chk & 0x1ffffff) << 5 ^ (value & 0xff);
            for (int i = 0; i < 5; i++) {
                chk ^= ((top >>> i) & 1) != 0 ? GENERATOR[i] : 0;
            }
        }
        return chk;
    }

    private static byte[] hrpExpand(String hrp) {
        byte[] out = new byte[hrp.length() * 2 + 1];
        for (int i = 0; i < hrp.length(); i++) {
            out[i] = (byte) (hrp.charAt(i) >>> 5);
            out[i + hrp.length() + 1] = (byte) (hrp.charAt(i) & 0x1f);
        }
        out[hrp.length()] = 0;
        return out;
    }

    private static boolean verifyChecksum(String hrp, byte[] values) {
        byte[] exp = hrpExpand(hrp);
        byte[] combined = new byte[exp.length + values.length];
        System.arraycopy(exp, 0, combined, 0, exp.length);
        System.arraycopy(values, 0, combined, exp.length, values.length);
        return polymod(combined) == 1;
    }

    private static byte[] createChecksum(String hrp, byte[] values) {
        byte[] exp = hrpExpand(hrp);
        byte[] enc = new byte[exp.length + values.length + 6];
        System.arraycopy(exp, 0, enc, 0, exp.length);
        System.arraycopy(values, 0, enc, exp.length, values.length);
        int mod = polymod(enc) ^ 1;
        byte[] checksum = new byte[6];
        for (int i = 0; i < 6; i++) {
            checksum[i] = (byte) ((mod >>> (5 * (5 - i))) & 31);
        }
        return checksum;
    }

    private static byte[] convertBits(byte[] data, int fromBits, int toBits, boolean pad) {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (byte b : data) {
            int value = b & 0xff;
            if ((value >>> fromBits) != 0) {
                throw new IllegalArgumentException("bech32: input value out of range");
            }
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) out.write((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new IllegalArgumentException("bech32: invalid padding");
        }
        return out.toByteArray();
    }
}
