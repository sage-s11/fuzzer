package com.fuzzer.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * DNS Question Section (RFC 1035 Section 4.1.2)
 */
public class DnsQuestion {

    public String qname;   // Domain name e.g. "example.com"
    public int qtype;      // Record type: 1=A, 2=NS, 5=CNAME, 15=MX, 255=ANY
    public int qclass;     // Class: 1=IN (Internet)

    public static final int TYPE_A    = 1;
    public static final int TYPE_NS   = 2;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_MX   = 15;
    public static final int TYPE_AAAA = 28;
    public static final int TYPE_ANY  = 255;
    public static final int CLASS_IN  = 1;

    public DnsQuestion(String qname, int qtype, int qclass) {
        this.qname  = qname;
        this.qtype  = qtype;
        this.qclass = qclass;
    }

    /**
     * Encode domain name to DNS label format.
     * "example.com" → [7]example[3]com[0]
     */
    public static byte[] encodeName(String name) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (name == null || name.isEmpty() || name.equals(".")) {
            out.write(0);
            return out.toByteArray();
        }
        String[] labels = name.split("\\.");
        for (String label : labels) {
            byte[] b = label.getBytes();
            out.write(b.length);
            out.write(b);
        }
        out.write(0); // root label
        return out.toByteArray();
    }

    /**
     * Decode DNS label format back to string.
     */
    public static String decodeName(ByteBuffer buf) {
        StringBuilder sb = new StringBuilder();
        int len;
        while ((len = buf.get() & 0xFF) != 0) {
            if ((len & 0xC0) == 0xC0) {
                // Pointer compression
                int offset = ((len & 0x3F) << 8) | (buf.get() & 0xFF);
                int savedPos = buf.position();
                buf.position(offset);
                String remainder = decodeName(buf);
                buf.position(savedPos);
                if (sb.length() > 0) sb.append('.');
                sb.append(remainder);
                return sb.toString();
            }
            if (sb.length() > 0) sb.append('.');
            byte[] label = new byte[len];
            buf.get(label);
            sb.append(new String(label));
        }
        return sb.toString();
    }

    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(encodeName(qname));
        ByteBuffer suffix = ByteBuffer.allocate(4);
        suffix.putShort((short) qtype);
        suffix.putShort((short) qclass);
        out.write(suffix.array());
        return out.toByteArray();
    }

    @Override
    public String toString() {
        return String.format("DnsQuestion[%s type=%d class=%d]", qname, qtype, qclass);
    }
}
