package com.fuzzer;

import com.fuzzer.mutator.AxfrMutators;
import com.fuzzer.mutator.AxfrMutators.*;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Tests for TCP/AXFR components.
 *
 * Validates:
 *   1. AXFR query wire format (valid baseline)
 *   2. IXFR query wire format
 *   3. All TcpLengthMutator variants produce correct encoding
 *   4. All AxfrRequestMutator variants produce parseable output
 *   5. All TcpFramingMutator variants produce non-empty output
 *   6. Seed immutability contract
 */
public class AxfrFuzzerTest {

    // =========================================================================
    // AxfrMutators.buildAxfrQuery
    // =========================================================================

    @Test
    @DisplayName("AXFR query has correct minimum length")
    void axfrQueryMinLength() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        // 12 (header) + 12 (fuzz.local encoded) + 4 (QTYPE+QCLASS) = 28 minimum
        assertTrue(q.length >= 28, "AXFR query must be at least 28 bytes, got " + q.length);
    }

    @Test
    @DisplayName("AXFR query has correct header ID")
    void axfrQueryHeaderId() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        int id = ((q[0] & 0xFF) << 8) | (q[1] & 0xFF);
        assertEquals(0x1337, id, "Header ID must be 0x1337");
    }

    @Test
    @DisplayName("AXFR query has QR=0 (query, not response)")
    void axfrQueryIsQuery() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        assertEquals(0, (q[2] >> 7) & 1, "QR bit must be 0 (query)");
    }

    @Test
    @DisplayName("AXFR query has QDCOUNT=1")
    void axfrQueryQdcount() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        int qdcount = ((q[4] & 0xFF) << 8) | (q[5] & 0xFF);
        assertEquals(1, qdcount, "QDCOUNT must be 1");
    }

    @Test
    @DisplayName("AXFR query QTYPE=252 (0x00FC)")
    void axfrQueryQtype() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        // QTYPE is the 2 bytes before QCLASS at end of question
        int qtype = ((q[q.length - 4] & 0xFF) << 8) | (q[q.length - 3] & 0xFF);
        assertEquals(252, qtype, "AXFR QTYPE must be 252");
    }

    @Test
    @DisplayName("AXFR query QCLASS=1 (IN)")
    void axfrQueryQclass() throws IOException {
        byte[] q = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        int qclass = ((q[q.length - 2] & 0xFF) << 8) | (q[q.length - 1] & 0xFF);
        assertEquals(1, qclass, "AXFR QCLASS must be 1 (IN)");
    }

    // =========================================================================
    // AxfrMutators.buildIxfrQuery
    // =========================================================================

    @Test
    @DisplayName("IXFR query QTYPE=251 (0x00FB)")
    void ixfrQueryQtype() throws IOException {
        byte[] q = AxfrMutators.buildIxfrQuery(0x2000, "fuzz.local", 12345L);
        // QTYPE in question section — find it by scanning for 0x00 0xFB
        boolean found = false;
        for (int i = 12; i < q.length - 1; i++) {
            if ((q[i] & 0xFF) == 0x00 && (q[i+1] & 0xFF) == 0xFB) {
                found = true;
                break;
            }
        }
        assertTrue(found, "IXFR query must contain QTYPE=251 (0x00FB)");
    }

    @Test
    @DisplayName("IXFR query has NSCOUNT=1 (SOA in authority)")
    void ixfrQueryNscount() throws IOException {
        byte[] q = AxfrMutators.buildIxfrQuery(0x2000, "fuzz.local", 12345L);
        int nscount = ((q[8] & 0xFF) << 8) | (q[9] & 0xFF);
        assertEquals(1, nscount, "IXFR NSCOUNT must be 1 (one SOA in authority)");
    }

    // =========================================================================
    // TcpLengthMutator
    // =========================================================================

    @Test
    @DisplayName("TcpLength encoding: first 2 bytes are claimed length, rest is message")
    void tcpLengthEncoding() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        var m = new TcpLengthMutator(TcpLengthMutator.Variant.OVERCLAIM);
        byte[] out = m.mutate(seed);

        // First 2 bytes = claimed length
        int claimed = ((out[0] & 0xFF) << 8) | (out[1] & 0xFF);
        // Bytes 2+ = actual message
        int actualLen = out.length - 2;
        assertTrue(claimed > actualLen,
                "OVERCLAIM: claimed length (" + claimed + ") must exceed actual (" + actualLen + ")");
    }

    @Test
    @DisplayName("ZERO_LENGTH variant claims 0 bytes")
    void tcpLengthZero() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        var m = new TcpLengthMutator(TcpLengthMutator.Variant.ZERO_LENGTH);
        byte[] out = m.mutate(seed);
        int claimed = ((out[0] & 0xFF) << 8) | (out[1] & 0xFF);
        assertEquals(0, claimed, "ZERO_LENGTH must claim 0 bytes");
    }

    @Test
    @DisplayName("MAX_LENGTH variant claims 65535 bytes")
    void tcpLengthMax() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        var m = new TcpLengthMutator(TcpLengthMutator.Variant.MAX_LENGTH);
        byte[] out = m.mutate(seed);
        int claimed = ((out[0] & 0xFF) << 8) | (out[1] & 0xFF);
        assertEquals(65535, claimed, "MAX_LENGTH must claim 65535");
    }

    @Test
    @DisplayName("UNDERCLAIM variant claims fewer bytes than actual message")
    void tcpLengthUnderclaim() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        var m = new TcpLengthMutator(TcpLengthMutator.Variant.UNDERCLAIM);
        byte[] out = m.mutate(seed);
        int claimed = ((out[0] & 0xFF) << 8) | (out[1] & 0xFF);
        int actual = out.length - 2;
        assertTrue(claimed < actual,
                "UNDERCLAIM: claimed (" + claimed + ") must be less than actual (" + actual + ")");
    }

    @Test
    @DisplayName("Seed not modified by any TcpLength variant")
    void tcpLengthSeedImmutability() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] original = seed.clone();
        for (var v : TcpLengthMutator.Variant.values()) {
            new TcpLengthMutator(v).mutate(seed);
            assertArrayEquals(original, seed, "Variant " + v + " must not modify seed");
        }
    }

    // =========================================================================
    // AxfrRequestMutator
    // =========================================================================

    @Test
    @DisplayName("All AxfrRequest variants produce non-null non-empty output")
    void axfrRequestAllVariantsNonNull() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        for (var v : AxfrRequestMutator.Variant.values()) {
            byte[] out = new AxfrRequestMutator(v, "fuzz.local").mutate(seed);
            assertNotNull(out, "Variant " + v + " must not return null");
            assertTrue(out.length >= 12, "Variant " + v + " must be at least 12 bytes");
        }
    }

    @Test
    @DisplayName("WRONG_QCLASS variant has QCLASS != 1")
    void axfrRequestWrongQclass() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new AxfrRequestMutator(
                AxfrRequestMutator.Variant.WRONG_QCLASS, "fuzz.local").mutate(seed);
        int qclass = ((out[out.length - 2] & 0xFF) << 8) | (out[out.length - 1] & 0xFF);
        assertNotEquals(1, qclass, "WRONG_QCLASS must not have QCLASS=1 (IN)");
    }

    @Test
    @DisplayName("MULTI_QUESTION variant has QDCOUNT=2")
    void axfrRequestMultiQuestion() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new AxfrRequestMutator(
                AxfrRequestMutator.Variant.MULTI_QUESTION, "fuzz.local").mutate(seed);
        int qdcount = ((out[4] & 0xFF) << 8) | (out[5] & 0xFF);
        assertEquals(2, qdcount, "MULTI_QUESTION must have QDCOUNT=2");
    }

    @Test
    @DisplayName("AXFR_WITH_EDNS variant has ARCOUNT=1")
    void axfrRequestEdns() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new AxfrRequestMutator(
                AxfrRequestMutator.Variant.AXFR_WITH_EDNS, "fuzz.local").mutate(seed);
        int arcount = ((out[10] & 0xFF) << 8) | (out[11] & 0xFF);
        assertEquals(1, arcount, "AXFR_WITH_EDNS must have ARCOUNT=1 (OPT record)");
    }

    @Test
    @DisplayName("Seed not modified by any AxfrRequest variant")
    void axfrRequestSeedImmutability() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] original = seed.clone();
        for (var v : AxfrRequestMutator.Variant.values()) {
            new AxfrRequestMutator(v, "fuzz.local").mutate(seed);
            assertArrayEquals(original, seed, "Variant " + v + " must not modify seed");
        }
    }

    // =========================================================================
    // TcpFramingMutator
    // =========================================================================

    @Test
    @DisplayName("All TcpFraming variants produce non-empty output")
    void tcpFramingAllVariantsNonEmpty() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        for (var v : TcpFramingMutator.Variant.values()) {
            byte[] out = new TcpFramingMutator(v, "fuzz.local").mutate(seed);
            assertNotNull(out, "Variant " + v + " must not return null");
            assertTrue(out.length >= 2, "Variant " + v + " must be at least 2 bytes");
        }
    }

    @Test
    @DisplayName("PIPELINED_TWO produces output longer than single message")
    void tcpFramingPipelinedTwo() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new TcpFramingMutator(
                TcpFramingMutator.Variant.PIPELINED_TWO, "fuzz.local").mutate(seed);
        // Should be at least 2x the single message size (two length-prefixed messages)
        assertTrue(out.length > seed.length + 2,
                "PIPELINED_TWO must be longer than single message");
    }

    @Test
    @DisplayName("PIPELINED_FLOOD produces output for 10 messages")
    void tcpFramingFlood() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new TcpFramingMutator(
                TcpFramingMutator.Variant.PIPELINED_FLOOD, "fuzz.local").mutate(seed);
        // 10 messages × (2 byte prefix + message length)
        assertTrue(out.length > seed.length * 5,
                "PIPELINED_FLOOD must contain multiple messages");
    }

    @Test
    @DisplayName("SPLIT_HEADER produces only 2 bytes (length prefix, no body)")
    void tcpFramingSplitHeader() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] out = new TcpFramingMutator(
                TcpFramingMutator.Variant.SPLIT_HEADER, "fuzz.local").mutate(seed);
        assertEquals(2, out.length,
                "SPLIT_HEADER must produce exactly 2 bytes (length prefix only)");
        // The claimed length should match the seed length
        int claimed = ((out[0] & 0xFF) << 8) | (out[1] & 0xFF);
        assertEquals(seed.length, claimed,
                "SPLIT_HEADER length prefix must match seed length");
    }

    @Test
    @DisplayName("Seed not modified by any TcpFraming variant")
    void tcpFramingSeedImmutability() throws IOException {
        byte[] seed = AxfrMutators.buildAxfrQuery(0x1337, "fuzz.local");
        byte[] original = seed.clone();
        for (var v : TcpFramingMutator.Variant.values()) {
            new TcpFramingMutator(v, "fuzz.local").mutate(seed);
            assertArrayEquals(original, seed, "Variant " + v + " must not modify seed");
        }
    }

    // =========================================================================
    // encodeName utility
    // =========================================================================

    @Test
    @DisplayName("encodeName produces correct label format for fuzz.local")
    void encodeNameFuzzLocal() throws IOException {
        byte[] encoded = AxfrMutators.encodeName("fuzz.local");
        // Expected: [4]fuzz[5]local[0] = 12 bytes
        assertEquals(12, encoded.length);
        assertEquals(4, encoded[0]);  // length of "fuzz"
        assertEquals('f', (char)encoded[1]);
        assertEquals(5, encoded[5]);  // length of "local"
        assertEquals(0, encoded[11]); // root label
    }

    @Test
    @DisplayName("encodeName handles root zone")
    void encodeNameRoot() throws IOException {
        byte[] encoded = AxfrMutators.encodeName(".");
        assertEquals(1, encoded.length);
        assertEquals(0, encoded[0]);
    }

    @Test
    @DisplayName("encodeName handles single label")
    void encodeNameSingleLabel() throws IOException {
        byte[] encoded = AxfrMutators.encodeName("local");
        // [5]local[0] = 7 bytes
        assertEquals(7, encoded.length);
        assertEquals(5, encoded[0]);
        assertEquals(0, encoded[6]);
    }
}
