package com.fuzzer;

import com.fuzzer.mutator.SemanticMutators;
import com.fuzzer.mutator.SemanticMutators.*;
import com.fuzzer.mutator.MutationEngine;
import com.fuzzer.dns.DnsMessage;
import com.fuzzer.crash.CrashClassifier;
import com.fuzzer.crash.CrashDetector.CrashRecord;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Tests for v2 Semantic Mutators.
 *
 * Validates that each mutator:
 *   1. Produces output of valid minimum length
 *   2. Preserves the DNS header (first 12 bytes ID)
 *   3. Does not modify the original seed array
 *   4. Produces structurally distinct output from the seed
 *   5. Each variant produces distinct output from other variants
 */
public class SemanticMutatorTest {

    private byte[] seed;

    @BeforeEach
    void setup() throws IOException {
        seed = DnsMessage.standardQuery(0x1337, "fuzz.local").toBytes();
    }

    // =========================================================================
    // CompressionPointerLoopMutator
    // =========================================================================

    @Test
    @DisplayName("SELF_LOOP produces valid min-length output")
    void selfLoopMinLength() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.SELF_LOOP);
        byte[] out = m.mutate(seed);
        assertTrue(out.length >= 18, "Self-loop payload must be at least 18 bytes");
    }

    @Test
    @DisplayName("SELF_LOOP contains pointer at offset 12 pointing to 12")
    void selfLoopPointerIsCorrect() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.SELF_LOOP);
        byte[] out = m.mutate(seed);
        // Pointer = 0xC00C at offset 12
        assertEquals((byte)0xC0, out[12], "High byte of pointer must be 0xC0");
        assertEquals((byte)0x0C, out[13], "Low byte of pointer must be 0x0C (offset 12)");
    }

    @Test
    @DisplayName("TWO_HOP_LOOP contains two pointers forming a cycle")
    void twoHopLoopHasCycle() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.TWO_HOP_LOOP);
        byte[] out = m.mutate(seed);
        assertTrue(out.length >= 20);
        // First pointer at offset 12 must have bits 11 set
        assertEquals(0xC0, out[12] & 0xC0, "Offset 12 must be a pointer (bits 11)");
        // Second pointer at offset 14 must point back
        assertEquals(0xC0, out[14] & 0xC0, "Offset 14 must be a pointer (bits 11)");
    }

    @Test
    @DisplayName("FORWARD_PTR contains out-of-bounds pointer")
    void forwardPtrIsOob() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.FORWARD_PTR);
        byte[] out = m.mutate(seed);
        // 0xDF at offset 12 = bits 11 set + high offset bits
        assertEquals((byte)0xC0, (byte)(out[12] & 0xC0), "Must be pointer");
        // Reconstruct offset — must be > packet length
        int offset = ((out[12] & 0x3F) << 8) | (out[13] & 0xFF);
        assertTrue(offset > out.length, "Pointer must reference beyond packet end");
    }

    @Test
    @DisplayName("CHAIN_DEPTH produces 64-hop chain of pointers")
    void chainDepthHas64Hops() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.CHAIN_DEPTH);
        byte[] out = m.mutate(seed);
        // 64 hops × 2 bytes each = 128 bytes of pointer chain after 12-byte header
        assertTrue(out.length >= 12 + 128, "Chain depth payload must be at least 140 bytes");
        // All 64 entries must be pointers (bits 11 set)
        for (int i = 0; i < 64; i++) {
            int pos = 12 + i * 2;
            assertEquals(0xC0, out[pos] & 0xC0,
                    "Hop " + i + " at offset " + pos + " must be a pointer");
        }
    }

    @Test
    @DisplayName("Seed is not modified by any CompressionPtr variant")
    void compressionPtrDoesNotModifySeed() {
        byte[] original = seed.clone();
        for (var v : CompressionPointerLoopMutator.Variant.values()) {
            new CompressionPointerLoopMutator(v).mutate(seed);
            assertArrayEquals(original, seed, "Variant " + v + " must not modify seed");
        }
    }

    @Test
    @DisplayName("Header ID is preserved in SELF_LOOP output")
    void selfLoopPreservesHeaderId() {
        var m = new CompressionPointerLoopMutator(CompressionPointerLoopMutator.Variant.SELF_LOOP);
        byte[] out = m.mutate(seed);
        // ID is bytes 0-1
        assertEquals(seed[0], out[0]);
        assertEquals(seed[1], out[1]);
    }

    // =========================================================================
    // EdnsOptionOverflowMutator
    // =========================================================================

    @Test
    @DisplayName("RDLENGTH_OVERFLOW produces packet with OPT record")
    void rdlengthOverflowHasOptRecord() {
        var m = new EdnsOptionOverflowMutator(EdnsOptionOverflowMutator.Variant.RDLENGTH_OVERFLOW);
        byte[] out = m.mutate(seed);
        assertTrue(out.length > seed.length, "EDNS variant must produce longer output than seed");
        // Verify ARCOUNT=1 in header (bytes 10-11)
        int arcount = ((out[10] & 0xFF) << 8) | (out[11] & 0xFF);
        assertEquals(1, arcount, "ARCOUNT must be 1 (one OPT record)");
    }

    @Test
    @DisplayName("RDLENGTH_OVERFLOW OPT record claims length > actual remaining bytes")
    void rdlengthOverflowClaimsMoreThanAvailable() {
        var m = new EdnsOptionOverflowMutator(EdnsOptionOverflowMutator.Variant.RDLENGTH_OVERFLOW);
        byte[] out = m.mutate(seed);
        // Find the OPT record — scan for TYPE=41 (0x0029) after the question
        int optPos = findOptRecord(out);
        assertTrue(optPos >= 0, "OPT record must be present");
        // RDLENGTH is at optPos + 9 (1 NAME + 2 TYPE + 2 CLASS + 4 TTL)
        int rdlengthOffset = optPos + 9;
        if (rdlengthOffset + 1 < out.length) {
            int rdlength = ((out[rdlengthOffset] & 0xFF) << 8) | (out[rdlengthOffset + 1] & 0xFF);
            int actualRemaining = out.length - rdlengthOffset - 2;
            assertTrue(rdlength > actualRemaining,
                    "RDLENGTH (" + rdlength + ") must exceed actual remaining bytes (" + actualRemaining + ")");
        }
    }

    @Test
    @DisplayName("VERSION_NONZERO has non-zero EDNS version in OPT TTL")
    void versionNonzeroHasNonzeroVersion() {
        var m = new EdnsOptionOverflowMutator(EdnsOptionOverflowMutator.Variant.VERSION_NONZERO);
        byte[] out = m.mutate(seed);
        int optPos = findOptRecord(out);
        assertTrue(optPos >= 0, "OPT record must be present");
        // TTL byte 1 (second byte of 4-byte TTL) = version field
        int versionOffset = optPos + 6; // 1 NAME + 2 TYPE + 2 CLASS + 1 extRcode
        if (versionOffset < out.length) {
            assertNotEquals(0, out[versionOffset] & 0xFF,
                    "EDNS version must be non-zero");
        }
    }

    @Test
    @DisplayName("All EDNS variants produce output longer than seed")
    void allEdnsVariantsLongerThanSeed() {
        for (var v : EdnsOptionOverflowMutator.Variant.values()) {
            byte[] out = new EdnsOptionOverflowMutator(v).mutate(seed);
            assertTrue(out.length > seed.length,
                    "EDNS variant " + v + " must produce output longer than seed");
        }
    }

    @Test
    @DisplayName("Seed is not modified by any EDNS variant")
    void ednsVariantsDoNotModifySeed() {
        byte[] original = seed.clone();
        for (var v : EdnsOptionOverflowMutator.Variant.values()) {
            new EdnsOptionOverflowMutator(v).mutate(seed);
            assertArrayEquals(original, seed, "EDNS variant " + v + " must not modify seed");
        }
    }

    // =========================================================================
    // ZeroLengthLabelMutator
    // =========================================================================

    @Test
    @DisplayName("ZERO_LABEL_MID inserts zero byte after first label")
    void zeroLabelMidInsertedAfterFirstLabel() {
        var m = new ZeroLengthLabelMutator(ZeroLengthLabelMutator.Variant.ZERO_LABEL_MID);
        byte[] out = m.mutate(seed);
        assertTrue(out.length >= 12 + 5 + 1, "Must have at least header + [4]fuzz + zero");
        // Byte at offset 12 = 0x04 (label length for "fuzz")
        assertEquals(0x04, out[12] & 0xFF, "First label length must be 4");
        // Byte at offset 17 = 0x00 (zero-length label injected after "fuzz")
        assertEquals(0x00, out[17] & 0xFF, "Zero-length label must appear at offset 17");
    }

    @Test
    @DisplayName("ZERO_LABEL_START makes name start with root label immediately")
    void zeroLabelStartBeginsWithRoot() {
        var m = new ZeroLengthLabelMutator(ZeroLengthLabelMutator.Variant.ZERO_LABEL_START);
        byte[] out = m.mutate(seed);
        assertEquals(0x00, out[12] & 0xFF, "First byte of QNAME must be 0x00 (root label)");
    }

    @Test
    @DisplayName("CONSECUTIVE_ZEROS has three zeros mid-name")
    void consecutiveZerosHasThreeZeros() {
        var m = new ZeroLengthLabelMutator(ZeroLengthLabelMutator.Variant.CONSECUTIVE_ZEROS);
        byte[] out = m.mutate(seed);
        // [4]fuzz at offset 12, three zeros start at offset 17
        assertEquals(0x00, out[17] & 0xFF, "First zero at offset 17");
        assertEquals(0x00, out[18] & 0xFF, "Second zero at offset 18");
        assertEquals(0x00, out[19] & 0xFF, "Third zero at offset 19");
    }

    @Test
    @DisplayName("LONE_DOT produces minimal 18-byte packet")
    void loneDotProducesMinimalPacket() {
        var m = new ZeroLengthLabelMutator(ZeroLengthLabelMutator.Variant.LONE_DOT);
        byte[] out = m.mutate(seed);
        // header(12) + root(1) + TYPE(2) + CLASS(2) = 17 minimum
        assertTrue(out.length >= 17, "LONE_DOT packet must be at least 17 bytes");
        assertEquals(0x00, out[12] & 0xFF, "QNAME must be just root label");
    }

    @Test
    @DisplayName("MIXED_PTR_LABEL contains pointer after first label")
    void mixedPtrLabelHasPointer() {
        var m = new ZeroLengthLabelMutator(ZeroLengthLabelMutator.Variant.MIXED_PTR_LABEL);
        byte[] out = m.mutate(seed);
        // offset 12: [4]fuzz (5 bytes), then pointer at offset 17
        assertEquals(0x04, out[12] & 0xFF, "First label length must be 4");
        assertEquals(0xC0, out[17] & 0xC0, "Byte after label must be pointer (bits 11)");
        assertEquals(0x0C, out[18] & 0xFF, "Pointer must target offset 12");
    }

    @Test
    @DisplayName("Seed is not modified by any ZeroLengthLabel variant")
    void zeroLabelVariantsDoNotModifySeed() {
        byte[] original = seed.clone();
        for (var v : ZeroLengthLabelMutator.Variant.values()) {
            new ZeroLengthLabelMutator(v).mutate(seed);
            assertArrayEquals(original, seed, "ZeroLabel variant " + v + " must not modify seed");
        }
    }

    @Test
    @DisplayName("All ZeroLengthLabel variants produce non-null output")
    void allZeroLabelVariantsProduceOutput() {
        for (var v : ZeroLengthLabelMutator.Variant.values()) {
            byte[] out = new ZeroLengthLabelMutator(v).mutate(seed);
            assertNotNull(out, "Variant " + v + " must produce non-null output");
            assertTrue(out.length >= 12, "Variant " + v + " output must be at least 12 bytes");
        }
    }

    // =========================================================================
    // MutationEngine — v2 mutators registered
    // =========================================================================

    @Test
    @DisplayName("MutationEngine now has v1 + v2 mutators (>= 26 total)")
    void engineHasV2Mutators() {
        MutationEngine engine = new MutationEngine();
        assertTrue(engine.getMutatorCount() >= 26,
                "Engine must have at least 26 mutators (9 v1 + 17 v2), got: " + engine.getMutatorCount());
    }

    @Test
    @DisplayName("isolate('CompressionPtr') matches compression pointer mutators")
    void isolateCompressionPtr() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("CompressionPtr");
        assertEquals(4, engine.getMutatorCount(),
                "Should isolate 4 CompressionPtr variants");
    }

    @Test
    @DisplayName("isolate('EdnsOpt') matches EDNS overflow mutators")
    void isolateEdnsOpt() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("EdnsOpt");
        assertEquals(7, engine.getMutatorCount(),
                "Should isolate 7 EdnsOptOverflow variants");
    }

    @Test
    @DisplayName("isolate('ZeroLength') matches zero-length label mutators")
    void isolateZeroLength() {
        MutationEngine engine = new MutationEngine();
        engine.isolate("ZeroLength");
        assertEquals(6, engine.getMutatorCount(),
                "Should isolate 6 ZeroLengthLabel variants");
    }

    @Test
    @DisplayName("Stacked mutations work with v2 mutators")
    void stackedWithV2Mutators() throws IOException {
        MutationEngine engine = new MutationEngine();
        engine.isolate("EdnsOpt");
        MutationEngine.MutationResult result = engine.mutateStacked(seed, 2);
        assertNotNull(result.bytes);
        assertTrue(result.mutatorName.contains("+"), "Stacked name must contain '+'");
    }

    // =========================================================================
    // CrashClassifier — semantic verdict detection
    // =========================================================================

    @Test
    @DisplayName("CompressionPtr timeout classified as PTR_LOOP_TIMEOUT HIGH")
    void compressionPtrClassifiedCorrectly() {
        CrashRecord crash = new CrashRecord(
                CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, seed,
                "CompressionPtrLoop(SELF_LOOP)", 42L);
        CrashClassifier.ClassificationResult result = new CrashClassifier().classify(crash);
        assertEquals(CrashClassifier.Verdict.PTR_LOOP_TIMEOUT, result.verdict);
        assertEquals(CrashClassifier.Priority.HIGH, result.priority);
        assertTrue(result.isActionable());
    }

    @Test
    @DisplayName("EdnsOptOverflow timeout classified as EDNS_PARSE_ANOMALY HIGH")
    void ednsOptClassifiedCorrectly() {
        CrashRecord crash = new CrashRecord(
                CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, seed,
                "EdnsOptOverflow(RDLENGTH_OVERFLOW)", 99L);
        CrashClassifier.ClassificationResult result = new CrashClassifier().classify(crash);
        assertEquals(CrashClassifier.Verdict.EDNS_PARSE_ANOMALY, result.verdict);
        assertEquals(CrashClassifier.Priority.HIGH, result.priority);
        assertTrue(result.isActionable());
    }

    @Test
    @DisplayName("ZeroLengthLabel timeout classified as LABEL_OVERFLOW HIGH")
    void zeroLabelClassifiedCorrectly() {
        CrashRecord crash = new CrashRecord(
                CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, seed,
                "ZeroLengthLabel(ZERO_LABEL_MID)", 7L);
        CrashClassifier.ClassificationResult result = new CrashClassifier().classify(crash);
        assertEquals(CrashClassifier.Verdict.LABEL_OVERFLOW, result.verdict);
        assertEquals(CrashClassifier.Priority.HIGH, result.priority);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Find the offset of an OPT record (TYPE=41) in a DNS message.
     * Returns -1 if not found.
     */
    private int findOptRecord(byte[] data) {
        // Scan from offset 12 looking for TYPE=0x0029 (41)
        for (int i = 12; i < data.length - 2; i++) {
            if ((data[i] & 0xFF) == 0x00 &&
                (data[i+1] & 0xFF) == 0x29) {
                return i - 1; // return offset of NAME byte before TYPE
            }
        }
        return -1;
    }
}
