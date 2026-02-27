package com.fuzzer.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Full DNS Message container.
 * Composes header + questions into wire format and parses responses.
 */
public class DnsMessage {

    public DnsHeader header;
    public List<DnsQuestion> questions = new ArrayList<>();

    // Raw response bytes for analysis (answers not fully decoded in v1)
    public byte[] rawResponse;

    public DnsMessage() {
        this.header = new DnsHeader();
    }

    public DnsMessage(DnsHeader header) {
        this.header = header;
    }

    public void addQuestion(DnsQuestion q) {
        questions.add(q);
        header.qdCount = questions.size();
    }

    /**
     * Serialize entire message to wire format bytes.
     */
    public byte[] toBytes() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(header.toBytes());
        for (DnsQuestion q : questions) {
            out.write(q.toBytes());
        }
        return out.toByteArray();
    }

    /**
     * Build a standard A-record query for the given domain.
     */
    public static DnsMessage standardQuery(int id, String domain) {
        DnsHeader hdr = new DnsHeader(id, true);
        DnsMessage msg = new DnsMessage(hdr);
        msg.addQuestion(new DnsQuestion(domain, DnsQuestion.TYPE_A, DnsQuestion.CLASS_IN));
        return msg;
    }

    /**
     * Parse response header from raw bytes (minimal — just extracts rcode and counts).
     */
    public static DnsHeader parseResponseHeader(byte[] data) {
        return DnsHeader.fromBytes(data);
    }

    /**
     * Check if a response indicates server error (SERVFAIL, FORMERR, etc.)
     */
    public static boolean isErrorResponse(byte[] data) {
        if (data == null || data.length < 12) return false;
        DnsHeader h = DnsHeader.fromBytes(data);
        return h.rcode != 0;
    }

    @Override
    public String toString() {
        return String.format("DnsMessage[%s questions=%s]", header, questions);
    }
}
