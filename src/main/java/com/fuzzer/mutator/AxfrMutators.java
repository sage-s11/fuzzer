package com.fuzzer.mutator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * AxfrMutators — Mutators targeting DNS over TCP and AXFR zone transfers.
 *
 * These mutators attack attack surfaces that are ONLY accessible over TCP:
 *
 * ─────────────────────────────────────────────────────────────────
 * ATTACK SURFACE 1: TCP length field (RFC 1035 §4.2.2)
 *
 *   Every DNS message on TCP is prefixed with a 2-byte big-endian length.
 *   The server reads this length, then reads exactly that many bytes.
 *
 *   If the length field is wrong, the server either:
 *     - Tries to read too many bytes (blocks waiting for data that never arrives)
 *     - Reads too few bytes (next message starts mid-previous-message)
 *     - Gets confused about message boundaries entirely
 *
 *   This is a fundamentally different attack surface from UDP where
 *   each datagram is self-delimiting.
 *
 * ─────────────────────────────────────────────────────────────────
 * ATTACK SURFACE 2: AXFR protocol sequence (RFC 5936)
 *
 *   AXFR is a zone transfer — the server sends all records in a zone.
 *   The protocol sequence is:
 *     Client → [AXFR query]
 *     Server → [Message 1: SOA record]
 *     Server → [Messages 2..N: all zone records]
 *     Server → [Message N+1: SOA record again — terminator]
 *
 *   Attack surfaces:
 *     - What if the client sends a second AXFR before the first completes?
 *     - What if the AXFR query has a malformed zone name?
 *     - What if the query claims QTYPE=AXFR but with wrong QCLASS?
 *     - What if the client sends an IXFR (incremental) with a future serial?
 *     - What if TSIG authentication is present but malformed?
 *
 * ─────────────────────────────────────────────────────────────────
 * ATTACK SURFACE 3: Large message sizes
 *
 *   TCP allows messages up to 65535 bytes (2^16 - 1, the max the 2-byte
 *   length field can represent). UDP is limited to ~512 bytes by default
 *   or 4096 with EDNS. The TCP large-message parsing path is separate
 *   and typically less hardened.
 *
 * ─────────────────────────────────────────────────────────────────
 * ATTACK SURFACE 4: Connection state manipulation
 *
 *   TCP is stateful. Some attacks work by abusing connection state:
 *     - Send a valid AXFR request then abruptly close the connection mid-response
 *     - Send multiple pipelined queries without waiting for responses
 *     - Send a query, then a second query before reading the response
 */
public class AxfrMutators {

    private static final Random RNG = new Random();

    // =========================================================================
    // Helper: build a standard AXFR request
    // =========================================================================

    /**
     * Build a well-formed AXFR query for the given zone.
     *
     * Wire format:
     *   [DNS header: QR=0, OPCODE=0, QDCOUNT=1]
     *   [QNAME: encoded zone name]
     *   [QTYPE=252 (AXFR)]
     *   [QCLASS=1 (IN)]
     *
     * AXFR QTYPE = 252 (0x00FC)
     */
    public static byte[] buildAxfrQuery(int txId, String zone) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header: ID + flags(QR=0,RD=0) + QDCOUNT=1 + AN/NS/AR=0
        ByteBuffer hdr = ByteBuffer.allocate(12);
        hdr.putShort((short) txId);   // ID
        hdr.putShort((short) 0x0000); // flags: standard query
        hdr.putShort((short) 1);      // QDCOUNT=1
        hdr.putShort((short) 0);      // ANCOUNT=0
        hdr.putShort((short) 0);      // NSCOUNT=0
        hdr.putShort((short) 0);      // ARCOUNT=0
        out.write(hdr.array());

        // QNAME: encode zone as DNS labels
        out.write(encodeName(zone));

        // QTYPE=AXFR (252), QCLASS=IN (1)
        out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});

        return out.toByteArray();
    }

    /**
     * Build an IXFR (incremental zone transfer) query.
     * IXFR includes a SOA record in the authority section specifying
     * the client's current serial number.
     *
     * IXFR QTYPE = 251 (0x00FB)
     */
    public static byte[] buildIxfrQuery(int txId, String zone, long serial) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Header: QDCOUNT=1, NSCOUNT=1 (SOA in authority)
        ByteBuffer hdr = ByteBuffer.allocate(12);
        hdr.putShort((short) txId);
        hdr.putShort((short) 0x0000);
        hdr.putShort((short) 1);  // QDCOUNT
        hdr.putShort((short) 0);  // ANCOUNT
        hdr.putShort((short) 1);  // NSCOUNT (SOA goes here)
        hdr.putShort((short) 0);  // ARCOUNT
        out.write(hdr.array());

        // Question: QTYPE=IXFR (251)
        out.write(encodeName(zone));
        out.write(new byte[]{0x00, (byte)0xFB, 0x00, 0x01});

        // Authority: SOA record with client's current serial
        out.write(buildSoaRecord(zone, serial));

        return out.toByteArray();
    }

    /**
     * Encode a domain name to DNS label wire format.
     * "fuzz.local" → [4]fuzz[5]local[0]
     */
    public static byte[] encodeName(String name) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (name == null || name.isEmpty() || name.equals(".")) {
            out.write(0);
            return out.toByteArray();
        }
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes();
            out.write(b.length);
            out.write(b);
        }
        out.write(0);
        return out.toByteArray();
    }

    /**
     * Build a minimal SOA record for use in IXFR authority section.
     */
    private static byte[] buildSoaRecord(String zone, long serial) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // NAME (compressed pointer to question, offset 12) = 0xC00C
        out.write(new byte[]{(byte)0xC0, 0x0C});
        // TYPE=SOA (6), CLASS=IN (1)
        out.write(new byte[]{0x00, 0x06, 0x00, 0x01});
        // TTL=300
        out.write(new byte[]{0x00, 0x00, 0x01, 0x2C});

        // RDATA: mname + rname + serial + refresh + retry + expire + minimum
        ByteArrayOutputStream rdata = new ByteArrayOutputStream();
        rdata.write(encodeName("ns1." + zone));         // MNAME
        rdata.write(encodeName("hostmaster." + zone));  // RNAME
        ByteBuffer nums = ByteBuffer.allocate(20);
        nums.putInt((int)(serial & 0xFFFFFFFFL)); // serial
        nums.putInt(3600);   // refresh
        nums.putInt(900);    // retry
        nums.putInt(604800); // expire
        nums.putInt(300);    // minimum
        rdata.write(nums.array());
        byte[] rdataBytes = rdata.toByteArray();

        // RDLENGTH
        out.write((rdataBytes.length >> 8) & 0xFF);
        out.write(rdataBytes.length & 0xFF);
        out.write(rdataBytes);

        return out.toByteArray();
    }

    // =========================================================================
    // MUTATOR 1: TcpLengthMutator
    //
    // Attacks the 2-byte TCP length prefix (RFC 1035 §4.2.2).
    // The DNS message body is kept valid — only the length field is wrong.
    // This reaches the TCP framing parser specifically.
    // =========================================================================

    public static class TcpLengthMutator implements Mutator {

        public enum Variant {
            OVERCLAIM,      // claim more bytes than message contains → server blocks
            UNDERCLAIM,     // claim fewer bytes → server reads mid-message as next message start
            ZERO_LENGTH,    // claim 0 bytes → server reads 0 bytes and waits for next length
            MAX_LENGTH,     // claim 65535 → server tries to read 65535 bytes (OOM pressure)
            ONE_BYTE,       // claim 1 byte for a 27-byte message → 26 bytes become "next message"
        }

        private final Variant variant;

        public TcpLengthMutator(Variant variant) { this.variant = variant; }
        public TcpLengthMutator() { this.variant = null; }

        /**
         * Returns the message bytes AND the claimed length as a pair.
         * The TcpHarness.sendWithLength() method uses both.
         *
         * Since mutate(byte[]) can only return bytes, we encode the claimed
         * length as the first 2 bytes of the returned array, followed by the
         * actual message. The AxfrFuzzer unwraps this.
         *
         * Format: [claimed_len_hi][claimed_len_lo][actual_message_bytes...]
         */
        @Override
        public byte[] mutate(byte[] input) {
            Variant v = (variant != null) ? variant
                    : Variant.values()[RNG.nextInt(Variant.values().length)];

            int claimedLen = switch (v) {
                case OVERCLAIM  -> input.length + 200 + RNG.nextInt(1000);
                case UNDERCLAIM -> Math.max(1, input.length / 2);
                case ZERO_LENGTH -> 0;
                case MAX_LENGTH  -> 65535;
                case ONE_BYTE    -> 1;
            };
            claimedLen = Math.min(65535, Math.max(0, claimedLen));

            // Encode: [claimed_hi][claimed_lo][actual message]
            byte[] out = new byte[2 + input.length];
            out[0] = (byte)((claimedLen >> 8) & 0xFF);
            out[1] = (byte)(claimedLen & 0xFF);
            System.arraycopy(input, 0, out, 2, input.length);
            return out;
        }

        @Override
        public String name() {
            return "TcpLength(" + (variant != null ? variant : "RANDOM") + ")";
        }
    }

    // =========================================================================
    // MUTATOR 2: AxfrRequestMutator
    //
    // Builds specifically malformed AXFR/IXFR request messages.
    // The TCP framing is kept valid — only the AXFR protocol content is wrong.
    // This reaches the AXFR request parser specifically.
    // =========================================================================

    public static class AxfrRequestMutator implements Mutator {

        public enum Variant {
            WRONG_QCLASS,       // QTYPE=AXFR but QCLASS != IN (e.g., CHAOS=3)
            WRONG_QTYPE_NEAR,   // QTYPE=253 (MAILB, near AXFR=252)
            QTYPE_IXFR,         // IXFR with future serial (server has older zone)
            QTYPE_IXFR_ZERO_SERIAL, // IXFR with serial=0
            MULTI_QUESTION,     // QDCOUNT=2 with two AXFR questions for same zone
            AXFR_WITH_EDNS,     // AXFR query with EDNS OPT record (unusual combination)
            AXFR_WITH_TSIG,     // AXFR with malformed TSIG additional record
            EMPTY_ZONE_NAME,    // AXFR for root zone "."
            LONG_ZONE_NAME,     // AXFR for a very long zone name (near 255 bytes)
        }

        private final Variant variant;
        private final String zone;

        public AxfrRequestMutator(Variant variant, String zone) {
            this.variant = variant;
            this.zone    = zone;
        }

        public AxfrRequestMutator(String zone) {
            this.variant = null;
            this.zone    = zone;
        }

        @Override
        public byte[] mutate(byte[] input) {
            Variant v = (variant != null) ? variant
                    : Variant.values()[RNG.nextInt(Variant.values().length)];
            try {
                return buildVariant(v);
            } catch (Exception e) {
                return Arrays.copyOf(input, input.length);
            }
        }

        private byte[] buildVariant(Variant v) throws IOException {
            int txId = 0x1000 + RNG.nextInt(0xEFFF);
            switch (v) {

                case WRONG_QCLASS -> {
                    // AXFR query with QCLASS=3 (CHAOS) instead of IN (1)
                    // Some servers check QCLASS early and reject, others reach
                    // the AXFR handler before checking class
                    byte[] q = buildAxfrQuery(txId, zone);
                    // QCLASS is the last 2 bytes — overwrite with CHAOS=3
                    q[q.length - 2] = 0x00;
                    q[q.length - 1] = 0x03;
                    return q;
                }

                case WRONG_QTYPE_NEAR -> {
                    // QTYPE=253 (MAILB — reserved/obsolete, adjacent to AXFR=252)
                    // Tests whether the AXFR handler has an off-by-one in type matching
                    byte[] q = buildAxfrQuery(txId, zone);
                    q[q.length - 4] = 0x00;
                    q[q.length - 3] = (byte)0xFD; // 253
                    return q;
                }

                case QTYPE_IXFR -> {
                    // IXFR with a serial far in the future — server's zone has a lower serial
                    // The server should respond with a full AXFR (if delta too large)
                    // or an error. Tests the serial comparison logic.
                    long futureSerial = 999_999_999L;
                    return buildIxfrQuery(txId, zone, futureSerial);
                }

                case QTYPE_IXFR_ZERO_SERIAL -> {
                    // IXFR with serial=0 — every zone has serial > 0 by convention
                    // Edge case in the serial comparison: (server_serial - 0) = server_serial
                    return buildIxfrQuery(txId, zone, 0);
                }

                case MULTI_QUESTION -> {
                    // QDCOUNT=2, two AXFR questions for the same zone
                    // RFC 1035 §4.1.2: QDCOUNT should be 1 for AXFR
                    // Tests whether the server loops over questions or processes only the first
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) txId);
                    hdr.putShort((short) 0x0000);
                    hdr.putShort((short) 2);  // QDCOUNT=2
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    out.write(hdr.array());
                    // Two identical AXFR questions
                    out.write(encodeName(zone));
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});
                    out.write(encodeName(zone));
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});
                    return out.toByteArray();
                }

                case AXFR_WITH_EDNS -> {
                    // AXFR query with EDNS0 OPT record in additional section
                    // EDNS + AXFR is unusual — most AXFR implementations don't expect it
                    // Tests interactions between EDNS and AXFR code paths
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) txId);
                    hdr.putShort((short) 0x0000);
                    hdr.putShort((short) 1);  // QDCOUNT=1
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 1);  // ARCOUNT=1 (OPT record)
                    out.write(hdr.array());
                    out.write(encodeName(zone));
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01}); // AXFR IN
                    // OPT record: NAME=root, TYPE=41, CLASS=4096, TTL=0, RDLENGTH=0
                    out.write(new byte[]{
                        0x00,               // NAME = root
                        0x00, 0x29,         // TYPE = OPT (41)
                        0x10, 0x00,         // CLASS = 4096 (UDP payload)
                        0x00, 0x00, 0x00, 0x00, // TTL = 0
                        0x00, 0x00          // RDLENGTH = 0
                    });
                    return out.toByteArray();
                }

                case AXFR_WITH_TSIG -> {
                    // AXFR with a malformed TSIG record (QTYPE=250) in additional section
                    // TSIG is used to authenticate zone transfers — malformed TSIG
                    // reaches the TSIG validation code with garbage input
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) txId);
                    hdr.putShort((short) 0x0000);
                    hdr.putShort((short) 1);  // QDCOUNT=1
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 1);  // ARCOUNT=1 (TSIG)
                    out.write(hdr.array());
                    out.write(encodeName(zone));
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});
                    // TSIG record: NAME=key, TYPE=250, CLASS=ANY, TTL=0, RDATA=garbage
                    out.write(encodeName("fuzz-key"));
                    out.write(new byte[]{
                        0x00, (byte)0xFA, // TYPE=TSIG (250)
                        0x00, (byte)0xFF, // CLASS=ANY (255)
                        0x00, 0x00, 0x00, 0x00, // TTL=0
                        0x00, 0x10,       // RDLENGTH=16
                        // RDATA: algorithm name + garbage time/fudge/mac
                        0x05, 'h','m','a','c',
                        0x03, 'm','d','5',
                        0x00,             // root (algorithm name end)
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // time + fudge (garbage)
                    });
                    return out.toByteArray();
                }

                case EMPTY_ZONE_NAME -> {
                    // AXFR for root zone "." — a single 0x00 as QNAME
                    // Tests whether the AXFR code correctly handles the root zone
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) txId);
                    hdr.putShort((short) 0x0000);
                    hdr.putShort((short) 1);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    out.write(hdr.array());
                    out.write(new byte[]{0x00}); // root zone QNAME
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});
                    return out.toByteArray();
                }

                case LONG_ZONE_NAME -> {
                    // AXFR for a zone with a very long name (near 255-byte limit)
                    // Tests label length validation in the AXFR path
                    StringBuilder longName = new StringBuilder();
                    for (int i = 0; i < 8; i++) {
                        longName.append("a".repeat(30)).append(".");
                    }
                    longName.append("local");
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) txId);
                    hdr.putShort((short) 0x0000);
                    hdr.putShort((short) 1);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    out.write(hdr.array());
                    out.write(encodeName(longName.toString()));
                    out.write(new byte[]{0x00, (byte)0xFC, 0x00, 0x01});
                    return out.toByteArray();
                }

                default -> { return buildAxfrQuery(txId, zone); }
            }
        }

        @Override
        public String name() {
            return "AxfrRequest(" + (variant != null ? variant : "RANDOM") + ")";
        }
    }

    // =========================================================================
    // MUTATOR 3: TcpFramingMutator
    //
    // Attacks TCP message boundary handling — sends multiple messages
    // in a single TCP write, or splits a message across multiple writes.
    // Tests whether the server correctly re-assembles messages from the
    // TCP stream regardless of how they arrive.
    //
    // This is NOT about DNS content — it's about whether the TCP framing
    // layer correctly handles stream fragmentation, a common source of
    // bugs in protocols that run over TCP.
    // =========================================================================

    public static class TcpFramingMutator implements Mutator {

        public enum Variant {
            PIPELINED_TWO,      // send two valid queries back-to-back without waiting
            PIPELINED_FLOOD,    // send 10 queries pipelined
            SPLIT_HEADER,       // send length prefix, wait, then send message
            CONCAT_MESSAGES,    // two messages concatenated with no gap
            AXFR_THEN_QUERY,    // send AXFR, then immediately send a normal query
        }

        private final Variant variant;
        private final String zone;

        public TcpFramingMutator(Variant variant, String zone) {
            this.variant = variant;
            this.zone    = zone;
        }

        public TcpFramingMutator(String zone) {
            this.variant = null;
            this.zone    = zone;
        }

        /**
         * Returns the raw multi-message byte stream.
         * The AxfrFuzzer sends this via TcpHarness.sendRaw().
         */
        @Override
        public byte[] mutate(byte[] input) {
            Variant v = (variant != null) ? variant
                    : Variant.values()[RNG.nextInt(Variant.values().length)];
            try {
                return buildVariant(v, input);
            } catch (Exception e) {
                return Arrays.copyOf(input, input.length);
            }
        }

        private byte[] buildVariant(Variant v, byte[] seed) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            switch (v) {

                case PIPELINED_TWO -> {
                    // Two standard queries back-to-back, both length-prefixed
                    // Server should process each independently
                    appendLengthPrefixed(out, seed);
                    byte[] q2 = buildAxfrQuery(0x2000, zone);
                    appendLengthPrefixed(out, q2);
                }

                case PIPELINED_FLOOD -> {
                    // 10 pipelined queries — tests pipelining buffer limits
                    for (int i = 0; i < 10; i++) {
                        byte[] q = buildAxfrQuery(0x3000 + i, zone);
                        appendLengthPrefixed(out, q);
                    }
                }

                case SPLIT_HEADER -> {
                    // Only the length prefix — no message body follows.
                    // Server blocks waiting for the promised bytes.
                    // AxfrFuzzer sends this then waits for timeout.
                    int len = seed.length;
                    out.write((len >> 8) & 0xFF);
                    out.write(len & 0xFF);
                    // No body — deliberately incomplete
                }

                case CONCAT_MESSAGES -> {
                    // Two messages concatenated — the second message's bytes
                    // immediately follow the first with no padding
                    appendLengthPrefixed(out, seed);
                    byte[] q2 = buildAxfrQuery(0x4000 + RNG.nextInt(0x1000), zone);
                    appendLengthPrefixed(out, q2);
                }

                case AXFR_THEN_QUERY -> {
                    // AXFR request followed immediately by a standard A query
                    // Before the server has finished processing the AXFR,
                    // it receives a new query. Tests interleaving behavior.
                    byte[] axfr = buildAxfrQuery(0x5000, zone);
                    appendLengthPrefixed(out, axfr);
                    // A query for the same domain
                    ByteArrayOutputStream aQuery = new ByteArrayOutputStream();
                    ByteBuffer hdr = ByteBuffer.allocate(12);
                    hdr.putShort((short) 0x5001);
                    hdr.putShort((short) 0x0100);
                    hdr.putShort((short) 1);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    hdr.putShort((short) 0);
                    aQuery.write(hdr.array());
                    aQuery.write(encodeName(zone));
                    aQuery.write(new byte[]{0x00, 0x01, 0x00, 0x01}); // A IN
                    appendLengthPrefixed(out, aQuery.toByteArray());
                }
            }
            return out.toByteArray();
        }

        private void appendLengthPrefixed(ByteArrayOutputStream out, byte[] msg)
                throws IOException {
            int len = msg.length;
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
            out.write(msg);
        }

        @Override
        public String name() {
            return "TcpFraming(" + (variant != null ? variant : "RANDOM") + ")";
        }
    }
}
