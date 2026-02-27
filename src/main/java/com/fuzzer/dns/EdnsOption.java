package com.fuzzer.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * EDNS0 OPT Record (RFC 6891)
 *
 * EDNS extends DNS with larger UDP payloads and option fields.
 * This is a historically rich area for vulnerabilities — the option
 * parsing code in many DNS servers is complex and under-tested.
 *
 * Wire format of OPT record:
 *   NAME    = 0x00 (root)
 *   TYPE    = 41 (OPT)
 *   CLASS   = UDP payload size
 *   TTL     = extended RCODE + flags
 *   RDLENGTH = length of option data
 *   RDATA   = {option-code, option-length, option-data} ...
 */
public class EdnsOption {

    public static final int TYPE_OPT = 41;

    // Common EDNS option codes
    public static final int OPT_LLQ        = 1;    // Long-Lived Queries
    public static final int OPT_NSID       = 3;    // Name Server Identifier
    public static final int OPT_DAU        = 5;    // DNSSEC Algorithm Understood
    public static final int OPT_DHU        = 6;    // DS Hash Understood
    public static final int OPT_N3U        = 7;    // NSEC3 Hash Understood
    public static final int OPT_ECS        = 8;    // EDNS Client Subnet
    public static final int OPT_EXPIRE     = 9;    // EDNS EXPIRE
    public static final int OPT_COOKIE     = 10;   // DNS Cookies (RFC 7873)
    public static final int OPT_TCP_KA     = 11;   // TCP Keepalive
    public static final int OPT_PADDING    = 12;   // Padding
    public static final int OPT_CHAIN      = 13;   // CHAIN Query
    public static final int OPT_KEY_TAG    = 14;   // EDNS Key Tag

    private int udpPayloadSize = 4096;
    private int extRcode = 0;
    private int version = 0;
    private boolean dnssecOk = false;

    private List<int[]> optionCodes = new ArrayList<>();
    private List<byte[]> optionData  = new ArrayList<>();

    public EdnsOption() {}

    public EdnsOption setUdpPayloadSize(int size) {
        this.udpPayloadSize = size;
        return this;
    }

    public EdnsOption setDnssecOk(boolean ok) {
        this.dnssecOk = ok;
        return this;
    }

    public EdnsOption addOption(int code, byte[] data) {
        optionCodes.add(new int[]{code});
        optionData.add(data);
        return this;
    }

    /**
     * Serialize to OPT RR wire format bytes.
     */
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // NAME = root (0x00)
        out.write(0x00);

        // TYPE = OPT (41)
        ByteBuffer tmp = ByteBuffer.allocate(2);
        tmp.putShort((short) TYPE_OPT);
        out.write(tmp.array());

        // CLASS = UDP payload size
        tmp = ByteBuffer.allocate(2);
        tmp.putShort((short) udpPayloadSize);
        out.write(tmp.array());

        // TTL = extended RCODE (1 byte) + VERSION (1 byte) + flags (2 bytes)
        int ttl = (extRcode << 24) | (version << 16);
        if (dnssecOk) ttl |= 0x8000;
        tmp = ByteBuffer.allocate(4);
        tmp.putInt(ttl);
        out.write(tmp.array());

        // Build RDATA (options)
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        for (int i = 0; i < optionCodes.size(); i++) {
            int code = optionCodes.get(i)[0];
            byte[] data = optionData.get(i);
            ByteBuffer opt = ByteBuffer.allocate(4 + data.length);
            opt.putShort((short) code);
            opt.putShort((short) data.length);
            opt.put(data);
            rdata.write(opt.array());
        }
        byte[] rdataBytes = rdata.toByteArray();

        // RDLENGTH
        tmp = ByteBuffer.allocate(2);
        tmp.putShort((short) rdataBytes.length);
        out.write(tmp.array());

        // RDATA
        out.write(rdataBytes);

        return out.toByteArray();
    }

    /**
     * Build a standard EDNS0 OPT record with 4096 byte payload.
     */
    public static byte[] standard() throws IOException {
        return new EdnsOption().setUdpPayloadSize(4096).toBytes();
    }

    /**
     * Build an EDNS0 OPT with a cookie option (8 bytes client cookie).
     */
    public static byte[] withCookie(byte[] clientCookie) throws IOException {
        return new EdnsOption()
                .setUdpPayloadSize(4096)
                .addOption(OPT_COOKIE, clientCookie)
                .toBytes();
    }
}
