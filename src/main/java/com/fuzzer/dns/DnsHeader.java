package com.fuzzer.dns;

import java.nio.ByteBuffer;

/**
 * DNS Message Header (RFC 1035 Section 4.1.1)
 * Fixed 12-byte structure at the start of every DNS message.
 */
public class DnsHeader {

    public int id;          // 16-bit message ID
    public boolean qr;      // 0 = query, 1 = response
    public int opcode;      // 4-bit opcode (0=QUERY, 1=IQUERY, 2=STATUS)
    public boolean aa;      // Authoritative Answer
    public boolean tc;      // TrunCation
    public boolean rd;      // Recursion Desired
    public boolean ra;      // Recursion Available
    public int rcode;       // 4-bit response code
    public int qdCount;     // Question count
    public int anCount;     // Answer count
    public int nsCount;     // Authority count
    public int arCount;     // Additional count

    public DnsHeader() {}

    public DnsHeader(int id, boolean recursionDesired) {
        this.id = id;
        this.qr = false;
        this.opcode = 0;
        this.aa = false;
        this.tc = false;
        this.rd = recursionDesired;
        this.ra = false;
        this.rcode = 0;
        this.qdCount = 1;
        this.anCount = 0;
        this.nsCount = 0;
        this.arCount = 0;
    }

    /**
     * Serialize header to 12 bytes.
     */
    public byte[] toBytes() {
        ByteBuffer buf = ByteBuffer.allocate(12);
        buf.putShort((short) id);

        int flags = 0;
        if (qr)  flags |= 0x8000;
        flags |= (opcode & 0x0F) << 11;
        if (aa)  flags |= 0x0400;
        if (tc)  flags |= 0x0200;
        if (rd)  flags |= 0x0100;
        if (ra)  flags |= 0x0080;
        flags |= (rcode & 0x0F);

        buf.putShort((short) flags);
        buf.putShort((short) qdCount);
        buf.putShort((short) anCount);
        buf.putShort((short) nsCount);
        buf.putShort((short) arCount);
        return buf.array();
    }

    /**
     * Deserialize header from byte array.
     */
    public static DnsHeader fromBytes(byte[] data) {
        if (data.length < 12) throw new IllegalArgumentException("Header too short");
        ByteBuffer buf = ByteBuffer.wrap(data);
        DnsHeader h = new DnsHeader();
        h.id = buf.getShort() & 0xFFFF;
        int flags = buf.getShort() & 0xFFFF;
        h.qr      = (flags & 0x8000) != 0;
        h.opcode  = (flags >> 11) & 0x0F;
        h.aa      = (flags & 0x0400) != 0;
        h.tc      = (flags & 0x0200) != 0;
        h.rd      = (flags & 0x0100) != 0;
        h.ra      = (flags & 0x0080) != 0;
        h.rcode   = flags & 0x0F;
        h.qdCount = buf.getShort() & 0xFFFF;
        h.anCount = buf.getShort() & 0xFFFF;
        h.nsCount = buf.getShort() & 0xFFFF;
        h.arCount = buf.getShort() & 0xFFFF;
        return h;
    }

    @Override
    public String toString() {
        return String.format("DnsHeader[id=%d qr=%b opcode=%d rd=%b rcode=%d qdCount=%d]",
                id, qr, opcode, rd, rcode, qdCount);
    }
}
