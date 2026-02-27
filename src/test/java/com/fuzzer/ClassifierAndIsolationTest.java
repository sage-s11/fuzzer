package com.fuzzer;

import com.fuzzer.crash.CrashClassifier;
import com.fuzzer.crash.CrashClassifier.*;
import com.fuzzer.crash.CrashDetector;
import com.fuzzer.crash.CrashDetector.CrashRecord;
import com.fuzzer.dns.DnsHeader;
import com.fuzzer.dns.DnsMessage;
import com.fuzzer.mutator.MutationEngine;
import com.fuzzer.mutator.Mutators;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Tests for CrashClassifier and Isolated Mutator Mode.
 */
public class ClassifierAndIsolationTest {

    private CrashClassifier classifier;

    @BeforeEach
    void setup() {
        classifier = new CrashClassifier();
    }

    // =========================================================================
    // Helper: build a raw DNS payload with specific flags
    // =========================================================================

    private byte[] buildPayload(int flags, String domain, int qtype) throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(512);
        buf.putShort((short) 0x1234);     // ID
        buf.putShort((short) flags);       // FLAGS
        buf.putShort((short) 1);           // QDCOUNT
        buf.putShort((short) 0);           // ANCOUNT
        buf.putShort((short) 0);           // NSCOUNT
        buf.putShort((short) 0);           // ARCOUNT
        for (String label : domain.split("\\.")) {
            buf.put((byte) label.length());
            buf.put(label.getBytes());
        }
        buf.put((byte) 0);                 // root label
        buf.putShort((short) qtype);       // QTYPE
        buf.putShort((short) 1);           // QCLASS IN
        return Arrays.copyOf(buf.array(), buf.position());
    }

    private CrashRecord makeSoftCrash(byte[] payload, String mutator) {
        return new CrashRecord(
                CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, payload, mutator, 42L);
    }

    private CrashRecord makeHardCrash(byte[] payload, String mutator) {
        return new CrashRecord(
                CrashRecord.CrashType.HARD_CRASH, payload, mutator, 99L);
    }

    // =========================================================================
    // CrashClassifier — EXPECTED_DROP cases
    // =========================================================================

    @Test
    @DisplayName("QR=1 on soft crash → EXPECTED_DROP")
    void qrBitSetSoftCrashIsExpectedDrop() throws IOException {
        byte[] payload = buildPayload(0x8000, "fuzz.local", 1); // QR=1, opcode=0
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.EXPECTED_DROP, result.verdict);
        assertEquals(Priority.LOW, result.priority);
        assertFalse(result.isActionable());
        assertTrue(result.isExpected());
    }

    @Test
    @DisplayName("QR=1 flags 0xAAAA → EXPECTED_DROP")
    void alternatingFlagsWithQrIsExpectedDrop() throws IOException {
        byte[] payload = buildPayload(0xAAAA, "fuzz.local", 1);
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.EXPECTED_DROP, result.verdict);
    }

    @Test
    @DisplayName("QR=1 flags 0xFFFF → EXPECTED_DROP")
    void allFlagsSetIsExpectedDrop() throws IOException {
        byte[] payload = buildPayload(0xFFFF, "fuzz.local", 1);
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.EXPECTED_DROP, result.verdict);
    }

    @Test
    @DisplayName("QR=1 hard crash → TRUE_POSITIVE (server should not crash on this)")
    void qrBitHardCrashIsTruePositive() throws IOException {
        byte[] payload = buildPayload(0x8000, "fuzz.local", 1);
        ClassificationResult result = classifier.classify(makeHardCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.TRUE_POSITIVE, result.verdict);
        assertEquals(Priority.CRITICAL, result.priority);
        assertTrue(result.isActionable());
    }

    // =========================================================================
    // CrashClassifier — TRUE_POSITIVE cases
    // =========================================================================

    @Test
    @DisplayName("Hard crash with normal flags → TRUE_POSITIVE CRITICAL")
    void hardCrashNormalFlagsIsCritical() throws IOException {
        byte[] payload = buildPayload(0x0100, "fuzz.local", 1); // standard RD query
        ClassificationResult result = classifier.classify(makeHardCrash(payload, "OversizeLabel"));
        assertEquals(Verdict.TRUE_POSITIVE, result.verdict);
        assertEquals(Priority.CRITICAL, result.priority);
    }

    // =========================================================================
    // CrashClassifier — MALFORMED_TRUNC
    // =========================================================================

    @Test
    @DisplayName("TC=1 on UDP query soft crash → MALFORMED_TRUNC HIGH")
    void tcBitOnQueryIsMalformedTrunc() throws IOException {
        // QR=0, TC=1, opcode=0, rd=1
        byte[] payload = buildPayload(0x0300, "fuzz.local", 1); // 0x0300 = TC+RD
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.MALFORMED_TRUNC, result.verdict);
        assertEquals(Priority.HIGH, result.priority);
    }

    // =========================================================================
    // CrashClassifier — OPCODE_UNDEFINED
    // =========================================================================

    @Test
    @DisplayName("Undefined opcode (>5) soft crash → OPCODE_UNDEFINED LOW")
    void undefinedOpcodeSoftCrash() throws IOException {
        // QR=0, opcode=7 (undefined) = flags 0x3800
        byte[] payload = buildPayload(0x3800, "fuzz.local", 1);
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.OPCODE_UNDEFINED, result.verdict);
        assertEquals(Priority.LOW, result.priority);
    }

    // =========================================================================
    // CrashClassifier — QDCOUNT_MISMATCH
    // =========================================================================

    @Test
    @DisplayName("QDCOUNT=255 with tiny payload → QDCOUNT_MISMATCH HIGH")
    void qdcountMismatchIsHigh() {
        // Craft a payload where header claims 255 questions but body has none
        byte[] payload = new byte[14];
        payload[0] = 0x12; payload[1] = 0x34;    // ID
        payload[2] = 0x01; payload[3] = 0x00;    // flags: RD=1
        payload[4] = 0x00; payload[5] = (byte)255; // QDCOUNT=255
        // rest zeros
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "QdCountMismatch"));
        assertEquals(Verdict.QDCOUNT_MISMATCH, result.verdict);
        assertEquals(Priority.HIGH, result.priority);
    }

    // =========================================================================
    // CrashClassifier — PREFILTERED
    // =========================================================================

    @Test
    @DisplayName("Payload under 12 bytes → PREFILTERED INFO")
    void shortPayloadIsPrefiltered() {
        byte[] payload = new byte[6]; // too short to be DNS
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "BitFlip"));
        assertEquals(Verdict.PREFILTERED, result.verdict);
        assertEquals(Priority.INFO, result.priority);
        assertFalse(result.isActionable());
    }

    @Test
    @DisplayName("Null payload → PREFILTERED INFO")
    void nullPayloadIsPrefiltered() {
        CrashRecord record = new CrashRecord(
                CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, null, "BitFlip", 1L);
        ClassificationResult result = classifier.classify(record);
        assertEquals(Verdict.PREFILTERED, result.verdict);
    }

    // =========================================================================
    // CrashClassifier — UNKNOWN_QTYPE
    // =========================================================================

    @Test
    @DisplayName("QTYPE=0x0000 (reserved) soft crash → UNKNOWN_QTYPE MEDIUM")
    void reservedQtypeZeroIsMedium() throws IOException {
        byte[] payload = buildPayload(0x0100, "fuzz.local", 0x0000);
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "RandomType"));
        assertEquals(Verdict.UNKNOWN_QTYPE, result.verdict);
        assertEquals(Priority.MEDIUM, result.priority);
    }

    @Test
    @DisplayName("QTYPE=0x8000 (private use range) → UNKNOWN_QTYPE MEDIUM")
    void privateQtypeIsMedium() throws IOException {
        byte[] payload = buildPayload(0x0100, "fuzz.local", 0x8000);
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "RandomType"));
        assertEquals(Verdict.UNKNOWN_QTYPE, result.verdict);
    }

    // =========================================================================
    // CrashClassifier — RESERVED_BITS (Z-bit)
    // =========================================================================

    @Test
    @DisplayName("Z-bit set (0x0040), QR=0 → RESERVED_BITS HIGH")
    void zBitSetIsReservedBitsHigh() throws IOException {
        // QR=0, opcode=0, Z-bit=1 (bit 6 = 0x0040)
        byte[] payload = buildPayload(0x0140, "fuzz.local", 1); // RD=1 + Z=1
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        assertEquals(Verdict.RESERVED_BITS, result.verdict);
        assertEquals(Priority.HIGH, result.priority);
    }

    // =========================================================================
    // TriageReport
    // =========================================================================

    @Test
    @DisplayName("Triage report groups by verdict correctly")
    void triageReportGroupsByVerdict() throws IOException {
        byte[] expectedDrop = buildPayload(0x8000, "fuzz.local", 1);
        byte[] truePos      = buildPayload(0x0100, "fuzz.local", 1);

        CrashClassifier.TriageReport report = new CrashClassifier.TriageReport();
        report.add(classifier.classify(makeSoftCrash(expectedDrop, "HeaderFlags")));
        report.add(classifier.classify(makeHardCrash(truePos, "OversizeLabel")));

        assertEquals(1, report.getByVerdict(Verdict.EXPECTED_DROP).size());
        assertEquals(1, report.getByVerdict(Verdict.TRUE_POSITIVE).size());
        assertEquals(1, report.getActionable().size());
        assertEquals(1, report.getExpected().size());
    }

    @Test
    @DisplayName("Triage report renders without exceptions")
    void triageReportRendersCleanly() throws IOException {
        byte[] payload = buildPayload(0x8000, "fuzz.local", 1);
        CrashClassifier.TriageReport report = new CrashClassifier.TriageReport();
        ClassificationResult r = classifier.classify(makeSoftCrash(payload, "HeaderFlags"));
        r.crash = makeSoftCrash(payload, "HeaderFlags");
        report.add(r);
        String rendered = report.toReport();
        assertNotNull(rendered);
        assertTrue(rendered.contains("TRIAGE REPORT"));
        assertTrue(rendered.contains("EXPECTED_DROP"));
    }

    // =========================================================================
    // MutationEngine — isolate()
    // =========================================================================

    @Test
    @DisplayName("isolate() with exact name restricts to one mutator")
    void isolateExactNameRestrictsToOne() {
        MutationEngine engine = new MutationEngine();
        assertTrue(engine.getMutatorCount() >= 26, "v1+v2 pool must be >= 26");
        engine.isolate("HeaderFlags");
        assertEquals(1, engine.getMutatorCount());
        assertEquals("HeaderFlags", engine.getMutators().get(0).name());
    }

    @Test
    @DisplayName("isolate() with substring matches multiple mutators")
    void isolateSubstringMatchesMultiple() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("bitflip"); // should match BitFlip(1) and BitFlip(4)
        assertEquals(2, engine.getMutatorCount());
    }

    @Test
    @DisplayName("isolate() 'label' matches both label mutators")
    void isolateLabelMatchesBoth() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("label"); // LabelLength, OversizeLabel, ZeroLengthLabel x6
        assertEquals(8, engine.getMutatorCount());
    }

    @Test
    @DisplayName("isolate() with unknown name leaves pool unchanged and warns")
    void isolateUnknownNameLeavesPoolUnchanged() {
        MutationEngine engine = new MutationEngine();
        int before = engine.getMutatorCount();
        engine.isolate("doesnotexist_xyz");
        assertEquals(before, engine.getMutatorCount());
    }

    @Test
    @DisplayName("isolate() is case-insensitive")
    void isolateCaseInsensitive() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("HEADERFLAGS");
        assertEquals(1, engine.getMutatorCount());
    }

    @Test
    @DisplayName("After isolate(), round-robin only cycles isolated mutator")
    void afterIsolateRoundRobinOnlyCyclesIsolated() throws IOException {
        MutationEngine engine = new MutationEngine();
        engine.isolate("HeaderFlags");
        byte[] seed = DnsMessage.standardQuery(0x1234, "fuzz.local").toBytes();

        for (int i = 0; i < 20; i++) {
            MutationEngine.MutationResult result = engine.mutateRoundRobin(seed);
            assertEquals("HeaderFlags", result.mutatorName);
        }
    }

    @Test
    @DisplayName("getMutatorNames() returns comma-separated names after isolate")
    void getMutatorNamesAfterIsolate() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("bitflip");
        String names = engine.getMutatorNames();
        assertTrue(names.contains("BitFlip"));
    }

    // =========================================================================
    // Integration: classifier correctly handles our actual observed crashes
    // =========================================================================

    @Test
    @DisplayName("Reproducer hex payload 0xAAAA flags classifies as EXPECTED_DROP")
    void reproducerPayloadFromActualRun() {
        // Exact bytes from iter=594 crash report:
        // 13 38 AA AA 00 01 00 00 00 00 00 00 04 66 75 7A 7A 05 6C 6F 63 61 6C 00 00 00 00 01
        byte[] payload = new byte[]{
            0x13, 0x38,                               // ID
            (byte)0xAA, (byte)0xAA,                  // FLAGS = 0xAAAA (QR=1)
            0x00, 0x01,                               // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,      // AN/NS/AR counts
            0x04, 0x66, 0x75, 0x7A, 0x7A,            // [4]fuzz
            0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C,      // [5]local
            0x00,                                      // root
            0x00, 0x00,                               // QTYPE=0 (RandomType mutator)
            0x00, 0x01                                // QCLASS=IN
        };
        ClassificationResult result = classifier.classify(makeSoftCrash(payload, "BoundaryValue+HeaderFlags+RandomType"));
        assertEquals(Verdict.EXPECTED_DROP, result.verdict);
        assertTrue(result.reasoning.contains("QR bit"));
        assertFalse(result.isActionable());
    }
}
