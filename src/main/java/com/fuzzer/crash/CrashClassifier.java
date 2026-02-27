package com.fuzzer.crash;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * CrashClassifier
 *
 * Triage engine that analyzes crash trigger payloads and assigns a
 * structured verdict explaining WHY the crash happened.
 *
 * Problem it solves:
 *   Raw crash detection can't distinguish between:
 *     (a) Server dropped a packet correctly per RFC  → EXPECTED_DROP
 *     (b) Server is actually broken                  → TRUE_POSITIVE
 *     (c) Server is rate-limiting us                 → RATE_LIMITED
 *     (d) Input was so malformed the OS dropped it   → PREFILTERED
 *
 *   Without triage, everything looks like a bug. With triage,
 *   only real anomalies surface and get escalated.
 *
 * Classification hierarchy (checked in order, first match wins):
 *
 *   EXPECTED_DROP     — QR=1 on incoming packet (response bit set on query).
 *                       RFC 1035 §4.1.1: servers MUST ignore such packets.
 *                       Not a bug. This is correct BIND9 behavior.
 *
 *   EXPECTED_DROP     — Reserved/undefined opcode with QR=0.
 *                       RFC 1035 §4.1.1: unknown opcodes → NOTIMP (rcode=4).
 *                       If we got a timeout here instead of NOTIMP, flag it.
 *                       If we got NOTIMP, it's expected.
 *
 *   EXPECTED_DROP     — Zero-length payload or payload under minimum DNS size.
 *                       Most stacks drop sub-12-byte DNS packets at the OS level.
 *
 *   MALFORMED_TRUNC   — TC bit set (truncation) on a UDP query. Unusual but
 *                       servers should still respond. Timeout here is suspicious.
 *
 *   QDCOUNT_MISMATCH  — QDCOUNT claims N questions but payload can't contain them.
 *                       Servers should respond FORMERR (rcode=1). Timeout is anomalous.
 *
 *   LABEL_OVERFLOW    — Domain name encoding exceeds 255-byte max label chain.
 *                       Should produce FORMERR. Hard crash here is serious.
 *
 *   RESERVED_BITS     — Z bit (bit 6 of flags) is set. RFC says MUST be zero.
 *                       Servers should ignore it. Crash on this is suspicious.
 *
 *   UNKNOWN_QTYPE     — QTYPE in reserved range (0x0000, 0x8000+).
 *                       Should produce NOTIMP or NOERROR with no answers.
 *                       Crash here is worth investigating.
 *
 *   OPCODE_UNDEFINED  — Opcode > 5 (all currently defined opcodes are 0-5).
 *                       Should produce NOTIMP. Timeout is expected.
 *
 *   SUSPICIOUS        — Timeout with no explainable RFC reason. Needs manual review.
 *
 *   TRUE_POSITIVE     — Hard crash (port unreachable) with non-trivially malformed input.
 *                       Highest priority. Server process likely terminated.
 */
public class CrashClassifier {

    public enum Verdict {
        TRUE_POSITIVE,          // Hard crash, server likely died — highest priority
        SUSPICIOUS,             // Soft crash with no RFC-based explanation — review manually
        PTR_LOOP_TIMEOUT,       // Compression pointer loop caused timeout — investigate depth limit
        EDNS_PARSE_ANOMALY,     // EDNS option overflow caused unexpected behavior — investigate
        MALFORMED_TRUNC,        // TC bit on UDP query caused timeout — investigate
        QDCOUNT_MISMATCH,       // Count/payload mismatch caused timeout — investigate
        LABEL_OVERFLOW,         // Oversize label caused timeout — investigate
        RESERVED_BITS,          // Z-bit set caused timeout — investigate
        UNKNOWN_QTYPE,          // Reserved QTYPE caused timeout — investigate
        OPCODE_UNDEFINED,       // Undefined opcode caused timeout — expected
        EXPECTED_DROP,          // QR=1 or other RFC-mandated drop — not a bug
        PREFILTERED,            // Payload too short to be valid DNS — OS likely dropped it
        UNCLASSIFIED            // Couldn't determine cause
    }

    public enum Priority {
        CRITICAL,   // TRUE_POSITIVE — file a bug immediately
        HIGH,       // SUSPICIOUS, PTR_LOOP_TIMEOUT, EDNS_PARSE_ANOMALY, MALFORMED_TRUNC,
                    // QDCOUNT_MISMATCH, LABEL_OVERFLOW, RESERVED_BITS
        MEDIUM,     // UNKNOWN_QTYPE
        LOW,        // OPCODE_UNDEFINED, EXPECTED_DROP
        INFO        // PREFILTERED, UNCLASSIFIED
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Classify a crash record. Attaches verdict and reasoning to the record.
     */
    public ClassificationResult classify(CrashDetector.CrashRecord crash) {
        byte[] payload = crash.triggerBytes;

        // --- Trivial rejections ---
        if (payload == null || payload.length < 12) {
            return result(Verdict.PREFILTERED, Priority.INFO,
                    "Payload under 12 bytes — below minimum DNS message size. " +
                    "Likely dropped by OS or network stack before reaching BIND9.");
        }

        ByteBuffer buf = ByteBuffer.wrap(payload);
        int id    = buf.getShort() & 0xFFFF;
        int flags = buf.getShort() & 0xFFFF;

        // Parse flags
        boolean qr      = (flags & 0x8000) != 0;
        int     opcode  = (flags >> 11) & 0x0F;
        boolean aa      = (flags & 0x0400) != 0;
        boolean tc      = (flags & 0x0200) != 0;
        boolean rd      = (flags & 0x0100) != 0;
        boolean ra      = (flags & 0x0080) != 0;
        boolean zBit    = (flags & 0x0040) != 0;  // reserved, must be zero
        boolean adBit   = (flags & 0x0020) != 0;
        boolean cdBit   = (flags & 0x0010) != 0;
        int     rcode   = flags & 0x0F;

        int qdCount = buf.getShort() & 0xFFFF;
        int anCount = buf.getShort() & 0xFFFF;
        int nsCount = buf.getShort() & 0xFFFF;
        int arCount = buf.getShort() & 0xFFFF;

        int remainingBytes = payload.length - 12;

        // Build flag description for reports
        String flagDesc = describeFlagWord(flags, qr, opcode, tc, rd, ra, zBit, rcode);

        // --- Hard crash — highest priority regardless of cause ---
        if (crash.type == CrashDetector.CrashRecord.CrashType.HARD_CRASH) {
            // Even if QR=1, a hard crash on it is still worth noting
            if (qr) {
                return result(Verdict.TRUE_POSITIVE, Priority.CRITICAL,
                        "HARD CRASH (port unreachable) triggered by packet with QR=1. " +
                        "Server process likely terminated. QR=1 should be silently dropped per RFC 1035 — " +
                        "a crash on it is unexpected and serious. Flags: " + flagDesc);
            }
            return result(Verdict.TRUE_POSITIVE, Priority.CRITICAL,
                    "HARD CRASH (port unreachable). Server process likely terminated. " +
                    "Payload: " + payload.length + " bytes. Flags: " + flagDesc +
                    ". Opcode: " + opcode + ". QDCOUNT: " + qdCount);
        }

        // --- From here all are soft crashes (TIMEOUT) ---

        // 1. QR=1 — server received what looks like a response, not a query.
        //    RFC 1035 §4.1.1: QR bit distinguishes queries (0) from responses (1).
        //    A server MUST NOT respond to packets with QR=1.
        //    This is the primary cause of all the HeaderFlags soft crashes we observed.
        if (qr) {
            return result(Verdict.EXPECTED_DROP, Priority.LOW,
                    "QR bit (0x8000) is SET — packet appears to be a DNS response, not a query. " +
                    "RFC 1035 §4.1.1 requires servers to ignore such packets. " +
                    "BIND9 silent drop is CORRECT behavior. Not a vulnerability. " +
                    "Flags: " + flagDesc);
        }

        // 2. Undefined opcode — values 3,4,6-15 are not assigned.
        //    RFC 1035: servers SHOULD return NOTIMP (rcode=4) for unknown opcodes.
        //    A timeout instead of NOTIMP is mildly suspicious but common in strict implementations.
        if (opcode > 5) {
            return result(Verdict.OPCODE_UNDEFINED, Priority.LOW,
                    "Opcode " + opcode + " is undefined (valid range: 0=QUERY, 1=IQUERY, " +
                    "2=STATUS, 4=NOTIFY, 5=UPDATE). RFC 1035 expects NOTIMP response. " +
                    "Timeout instead of NOTIMP is common but worth noting. Flags: " + flagDesc);
        }

        // 3. TC bit on a UDP query
        //    TC (TrunCation) is normally set by a *server* to indicate response was truncated.
        //    Receiving TC=1 on a query is unusual. Servers should handle it gracefully.
        if (tc && !qr) {
            return result(Verdict.MALFORMED_TRUNC, Priority.HIGH,
                    "TC (TrunCation) bit set on an incoming UDP query. " +
                    "This bit is normally set by servers on truncated responses, not on queries. " +
                    "Server should respond normally — timeout here is suspicious. " +
                    "Flags: " + flagDesc);
        }

        // 4. Z-bit (reserved bit 6) set
        //    RFC 1035 §4.1.1: Z bits MUST be zero in all queries and responses.
        //    Most implementations ignore it, but some strict parsers may reject it.
        if (zBit) {
            return result(Verdict.RESERVED_BITS, Priority.HIGH,
                    "Reserved Z-bit (bit 6, 0x0040) is SET. RFC 1035 §4.1.1 states Z bits " +
                    "MUST be zero. Well-behaved servers should ignore this and process normally. " +
                    "Timeout here suggests BIND9 may be dropping on Z-bit, which is overly strict. " +
                    "Flags: " + flagDesc);
        }

        // 5. QDCOUNT mismatch — claimed questions don't fit in remaining payload
        //    Each question is minimum ~5 bytes (1-byte root label + 4 bytes type/class).
        //    If QDCOUNT * 5 > remainingBytes, the message is structurally impossible.
        if (qdCount > 0 && (qdCount * 5) > remainingBytes) {
            return result(Verdict.QDCOUNT_MISMATCH, Priority.HIGH,
                    "QDCOUNT=" + qdCount + " claims " + qdCount + " questions but payload " +
                    "only has " + remainingBytes + " bytes after header (" +
                    (qdCount * 5) + " bytes minimum needed). " +
                    "Server should return FORMERR (rcode=1). Timeout instead of FORMERR is anomalous. " +
                    "Flags: " + flagDesc);
        }

        // 6. Zero QDCOUNT with QUERY opcode
        //    A standard query with 0 questions is technically malformed.
        //    Server should return FORMERR. Timeout is suspicious.
        if (qdCount == 0 && opcode == 0) {
            return result(Verdict.QDCOUNT_MISMATCH, Priority.MEDIUM,
                    "QDCOUNT=0 on a QUERY opcode (0) message. A query with no questions " +
                    "is malformed per RFC 1035. Server should return FORMERR. " +
                    "Timeout here is mildly suspicious. Flags: " + flagDesc);
        }

        // 7. Label overflow — check if QNAME section appears to exceed 255-byte limit
        //    We scan for the root label terminator. If we hit end of buffer without one,
        //    the label chain is missing its terminator.
        if (remainingBytes > 4) {
            LabelScanResult scan = scanLabels(payload, 12);
            if (scan.overflow) {
                return result(Verdict.LABEL_OVERFLOW, Priority.HIGH,
                        "Domain name label chain appears to exceed 255-byte maximum " +
                        "(RFC 1035 §3.1) or is missing root label terminator. " +
                        "Bytes scanned: " + scan.bytesScanned + ". " +
                        "Server should return FORMERR. Timeout here is anomalous. " +
                        "Flags: " + flagDesc);
            }
            if (scan.missingTerminator) {
                return result(Verdict.LABEL_OVERFLOW, Priority.MEDIUM,
                        "Domain name label chain has no root label terminator (0x00). " +
                        "Structurally incomplete QNAME. Server should return FORMERR. " +
                        "Flags: " + flagDesc);
            }
        }

        // 8. Reserved QTYPE — check if QTYPE is in reserved range
        //    After scanning labels we can check the QTYPE bytes
        if (remainingBytes >= 4) {
            int qtypeOffset = findQTypeOffset(payload, 12);
            if (qtypeOffset > 0 && qtypeOffset + 1 < payload.length) {
                int qtype = ((payload[qtypeOffset] & 0xFF) << 8) | (payload[qtypeOffset + 1] & 0xFF);
                if (qtype == 0x0000 || qtype >= 0x8000) {
                    return result(Verdict.UNKNOWN_QTYPE, Priority.MEDIUM,
                            "QTYPE=0x" + String.format("%04X", qtype) + " is in reserved range. " +
                            "QTYPE=0 is undefined. QTYPE >= 0x8000 is private use / unassigned. " +
                            "Server should return NOTIMP or NOERROR with empty answer section. " +
                            "Timeout here is worth investigating. Flags: " + flagDesc);
                }
            }
        }

        // 9. Semantic mutator detection — classify by mutator name patterns
        //    These mutators construct specific structural traps. A timeout from
        //    them is more meaningful than a random-byte timeout.
        String mutatorName = (crash.mutatorName != null) ? crash.mutatorName.toLowerCase() : "";

        if (mutatorName.contains("compressionptr") || mutatorName.contains("ptrloop")) {
            return result(Verdict.PTR_LOOP_TIMEOUT, Priority.HIGH,
                    "Compression pointer loop mutator triggered a timeout. " +
                    "Server may be following a pointer cycle without a depth limit. " +
                    "RFC 1035 §4.1.4: implementations must detect pointer loops. " +
                    "A timeout here suggests the parser is spinning — investigate loop detection logic. " +
                    "Mutator: " + crash.mutatorName);
        }

        if (mutatorName.contains("ednsopt") || mutatorName.contains("ednsoption")) {
            return result(Verdict.EDNS_PARSE_ANOMALY, Priority.HIGH,
                    "EDNS option overflow mutator triggered a timeout. " +
                    "Server may be mis-parsing RDLENGTH or option-length fields in OPT record. " +
                    "RFC 6891 §6.1.2: RDLENGTH and option lengths must be bounds-checked. " +
                    "This is a historically significant bug class — see CVE-2016-2776. " +
                    "Mutator: " + crash.mutatorName);
        }

        if (mutatorName.contains("zerolength") || mutatorName.contains("zerolabel")) {
            return result(Verdict.LABEL_OVERFLOW, Priority.HIGH,
                    "Zero-length label mutator triggered a timeout. " +
                    "Server may be misinterpreting a zero-length label mid-name or " +
                    "failing to handle structural ambiguity in QNAME parsing. " +
                    "RFC 1035 §3.1: a zero-length label is the root terminator — " +
                    "injecting it mid-name creates parsing ambiguity. " +
                    "Mutator: " + crash.mutatorName);
        }

        // 10. Soft crash with no classifiable RFC reason — genuine suspicious behavior
        if (crash.type == CrashDetector.CrashRecord.CrashType.SOFT_CRASH_TIMEOUT) {
            return result(Verdict.SUSPICIOUS, Priority.HIGH,
                    "Consecutive timeouts with no obvious RFC-mandated drop reason detected. " +
                    "Payload is structurally plausible but server stopped responding. " +
                    "This warrants manual inspection. Flags: " + flagDesc +
                    ". QDCOUNT: " + qdCount + ". Remaining bytes: " + remainingBytes);
        }

        return result(Verdict.UNCLASSIFIED, Priority.INFO,
                "Could not determine crash cause. Manual review required. Flags: " + flagDesc);
    }

    /**
     * Classify a list of crash records and return a triage report.
     */
    public TriageReport triageAll(List<CrashDetector.CrashRecord> crashes) {
        TriageReport report = new TriageReport();
        for (CrashDetector.CrashRecord crash : crashes) {
            ClassificationResult result = classify(crash);
            result.crash = crash;
            report.add(result);
        }
        return report;
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private ClassificationResult result(Verdict verdict, Priority priority, String reasoning) {
        return new ClassificationResult(verdict, priority, reasoning);
    }

    private String describeFlagWord(int flags, boolean qr, int opcode, boolean tc,
                                     boolean rd, boolean ra, boolean zBit, int rcode) {
        return String.format("0x%04X [QR=%d OPCODE=%d TC=%d RD=%d RA=%d Z=%d RCODE=%d]",
                flags, qr ? 1 : 0, opcode, tc ? 1 : 0, rd ? 1 : 0,
                ra ? 1 : 0, zBit ? 1 : 0, rcode);
    }

    /**
     * Walk the label chain starting at offset.
     * Returns whether an overflow or missing terminator was detected.
     */
    private LabelScanResult scanLabels(byte[] data, int offset) {
        LabelScanResult result = new LabelScanResult();
        int pos = offset;
        int totalNameBytes = 0;
        int maxIterations = 128; // prevent infinite loop on circular pointers

        while (pos < data.length && maxIterations-- > 0) {
            int b = data[pos] & 0xFF;

            // Pointer compression
            if ((b & 0xC0) == 0xC0) {
                pos += 2;
                result.bytesScanned = pos - offset;
                return result; // pointer — name ends here, structure ok
            }

            // Root label — end of name
            if (b == 0) {
                result.bytesScanned = pos - offset + 1;
                return result; // clean termination
            }

            // Label length
            if (b > 63) {
                result.overflow = true; // label > 63 bytes — RFC violation
                result.bytesScanned = pos - offset;
                return result;
            }

            totalNameBytes += b + 1;
            pos += b + 1;

            if (totalNameBytes > 255) {
                result.overflow = true;
                result.bytesScanned = pos - offset;
                return result;
            }
        }

        // Reached end of buffer without root label
        result.missingTerminator = true;
        result.bytesScanned = pos - offset;
        return result;
    }

    /**
     * Find the offset of QTYPE in the payload by walking the QNAME.
     * Returns -1 if not found.
     */
    private int findQTypeOffset(byte[] data, int offset) {
        int pos = offset;
        int guard = 0;
        while (pos < data.length && guard++ < 128) {
            int b = data[pos] & 0xFF;
            if ((b & 0xC0) == 0xC0) { pos += 2; return pos; }
            if (b == 0) return pos + 1; // QTYPE starts right after root label
            pos += b + 1;
        }
        return -1;
    }

    // -------------------------------------------------------------------------
    // Result containers
    // -------------------------------------------------------------------------

    private static class LabelScanResult {
        boolean overflow = false;
        boolean missingTerminator = false;
        int bytesScanned = 0;
    }

    public static class ClassificationResult {
        public final Verdict verdict;
        public final Priority priority;
        public final String reasoning;
        public CrashDetector.CrashRecord crash; // attached after triage

        public ClassificationResult(Verdict verdict, Priority priority, String reasoning) {
            this.verdict   = verdict;
            this.priority  = priority;
            this.reasoning = reasoning;
        }

        public boolean isActionable() {
            return priority == Priority.CRITICAL || priority == Priority.HIGH;
        }

        public boolean isExpected() {
            return verdict == Verdict.EXPECTED_DROP || verdict == Verdict.PREFILTERED;
        }

        @Override
        public String toString() {
            return String.format("[%s/%s] %s", priority, verdict, reasoning);
        }
    }

    // -------------------------------------------------------------------------
    // Triage Report
    // -------------------------------------------------------------------------

    public static class TriageReport {
        private final List<ClassificationResult> results = new ArrayList<>();

        public void add(ClassificationResult r) { results.add(r); }

        public List<ClassificationResult> getAll()         { return results; }
        public int total()                                  { return results.size(); }

        public List<ClassificationResult> getByPriority(Priority p) {
            return results.stream().filter(r -> r.priority == p).toList();
        }

        public List<ClassificationResult> getByVerdict(Verdict v) {
            return results.stream().filter(r -> r.verdict == v).toList();
        }

        public List<ClassificationResult> getActionable() {
            return results.stream().filter(ClassificationResult::isActionable).toList();
        }

        public List<ClassificationResult> getExpected() {
            return results.stream().filter(ClassificationResult::isExpected).toList();
        }

        public String toReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("╔══════════════════════════════════════════════════════════╗\n");
            sb.append("║              CRASH TRIAGE REPORT                        ║\n");
            sb.append("╚══════════════════════════════════════════════════════════╝\n\n");

            // Summary counts by verdict
            sb.append("SUMMARY\n");
            sb.append("─".repeat(60)).append("\n");
            for (Verdict v : Verdict.values()) {
                long count = results.stream().filter(r -> r.verdict == v).count();
                if (count > 0) {
                    Priority p = results.stream().filter(r -> r.verdict == v)
                            .findFirst().map(r -> r.priority).orElse(Priority.INFO);
                    sb.append(String.format("  %-22s %-10s %d finding(s)%n",
                            v, "[" + p + "]", count));
                }
            }
            sb.append("\n");

            // Actionable findings first
            List<ClassificationResult> actionable = getActionable();
            if (!actionable.isEmpty()) {
                sb.append("ACTIONABLE FINDINGS (").append(actionable.size()).append(")\n");
                sb.append("─".repeat(60)).append("\n");
                for (ClassificationResult r : actionable) {
                    appendFinding(sb, r);
                }
            }

            // Expected drops — summarized, not detailed
            List<ClassificationResult> expected = getExpected();
            if (!expected.isEmpty()) {
                sb.append("EXPECTED DROPS (").append(expected.size())
                        .append(") — RFC-compliant behavior, not bugs\n");
                sb.append("─".repeat(60)).append("\n");
                for (ClassificationResult r : expected) {
                    if (r.crash != null) {
                        sb.append(String.format("  iter=%-6d  mutator=%-30s  %s%n",
                                r.crash.iteration, r.crash.mutatorName, r.verdict));
                    }
                }
                sb.append("\n");
            }

            return sb.toString();
        }

        private void appendFinding(StringBuilder sb, ClassificationResult r) {
            if (r.crash == null) return;
            sb.append(String.format("\n  [%s] iter=%d  mutator=%s%n",
                    r.verdict, r.crash.iteration, r.crash.mutatorName));
            sb.append(String.format("  Timestamp : %s%n", r.crash.timestamp));
            sb.append(String.format("  Payload   : %d bytes%n", r.crash.triggerBytes.length));
            sb.append(String.format("  Reasoning : %s%n", r.reasoning));
            sb.append("\n");
        }
    }
}
