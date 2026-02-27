package com.fuzzer;

import com.fuzzer.dns.*;
import com.fuzzer.fsm.*;
import com.fuzzer.mutator.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Unit tests for DNS Fuzzer v1
 *
 * Tests cover:
 *   - DNS header serialization/deserialization roundtrip
 *   - DNS question encoding
 *   - FSM state transitions
 *   - Mutator output validity
 *   - Mutation engine cycling
 */
public class FuzzerTest {

    // -------------------------------------------------------------------------
    // DNS Header Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Header serializes to exactly 12 bytes")
    void headerSerializesTo12Bytes() {
        DnsHeader h = new DnsHeader(0x1234, true);
        assertEquals(12, h.toBytes().length);
    }

    @Test
    @DisplayName("Header roundtrip preserves all fields")
    void headerRoundtrip() {
        DnsHeader original = new DnsHeader(0xABCD, true);
        original.rd = true;
        original.qdCount = 1;

        byte[] bytes = original.toBytes();
        DnsHeader parsed = DnsHeader.fromBytes(bytes);

        assertEquals(original.id,      parsed.id);
        assertEquals(original.qr,      parsed.qr);
        assertEquals(original.rd,      parsed.rd);
        assertEquals(original.qdCount, parsed.qdCount);
        assertEquals(original.rcode,   parsed.rcode);
    }

    @Test
    @DisplayName("Header with all flags set roundtrips")
    void headerAllFlagsRoundtrip() {
        DnsHeader h = new DnsHeader(0xFFFF, false);
        h.qr = true;
        h.aa = true;
        h.tc = true;
        h.rd = true;
        h.opcode = 0xF;

        byte[] bytes = h.toBytes();
        DnsHeader parsed = DnsHeader.fromBytes(bytes);

        assertEquals(h.id, parsed.id);
        assertTrue(parsed.qr);
        assertTrue(parsed.aa);
        assertTrue(parsed.tc);
        assertTrue(parsed.rd);
    }

    // -------------------------------------------------------------------------
    // DNS Question Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Label encoding produces correct wire format")
    void labelEncodingIsCorrect() throws IOException {
        byte[] encoded = DnsQuestion.encodeName("example.com");
        // [7]example[3]com[0]
        assertEquals(7, encoded[0]);
        assertEquals('e', encoded[1]);
        assertEquals(3,   encoded[8]);
        assertEquals('c', encoded[9]);
        assertEquals(0,   encoded[12]); // root label
    }

    @Test
    @DisplayName("Empty domain encodes to single zero byte")
    void emptyDomainEncoding() throws IOException {
        byte[] encoded = DnsQuestion.encodeName("");
        assertEquals(1, encoded.length);
        assertEquals(0, encoded[0]);
    }

    @Test
    @DisplayName("Question serializes with correct QTYPE and QCLASS")
    void questionSerializesTypeAndClass() throws IOException {
        DnsQuestion q = new DnsQuestion("test.local", DnsQuestion.TYPE_A, DnsQuestion.CLASS_IN);
        byte[] bytes = q.toBytes();
        // Last 4 bytes are QTYPE (2) + QCLASS (2)
        ByteBuffer buf = ByteBuffer.wrap(bytes, bytes.length - 4, 4);
        short qtype  = buf.getShort();
        short qclass = buf.getShort();
        assertEquals(1, qtype);  // TYPE_A
        assertEquals(1, qclass); // CLASS_IN
    }

    // -------------------------------------------------------------------------
    // DNS Message Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("Standard query builds non-empty bytes")
    void standardQueryBuilds() throws IOException {
        DnsMessage msg = DnsMessage.standardQuery(0x0001, "example.com");
        byte[] bytes = msg.toBytes();
        assertTrue(bytes.length > 12); // More than just a header
    }

    @Test
    @DisplayName("Standard query has correct question count in header")
    void standardQueryQuestionCount() throws IOException {
        DnsMessage msg = DnsMessage.standardQuery(0x0001, "example.com");
        byte[] bytes = msg.toBytes();
        DnsHeader h = DnsHeader.fromBytes(bytes);
        assertEquals(1, h.qdCount);
    }

    @Test
    @DisplayName("Response with rcode=0 is not flagged as error")
    void rcode0NotError() {
        DnsHeader h = new DnsHeader(0x0001, true);
        h.qr = true;
        h.rcode = 0;
        assertFalse(DnsMessage.isErrorResponse(h.toBytes()));
    }

    @Test
    @DisplayName("Response with rcode=2 (SERVFAIL) is flagged as error")
    void rcode2IsError() {
        DnsHeader h = new DnsHeader(0x0001, true);
        h.qr = true;
        h.rcode = 2;
        // Need full 12-byte header
        assertTrue(DnsMessage.isErrorResponse(h.toBytes()));
    }

    // -------------------------------------------------------------------------
    // FSM Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("DNS FSM initializes in INITIAL state")
    void fsmInitializesCorrectly() {
        StateMachine fsm = DnsStateMachine.build();
        assertEquals(DnsStateMachine.S_INITIAL, fsm.getCurrentState().getName());
    }

    @Test
    @DisplayName("DNS FSM has fuzzable states")
    void fsmHasFuzzableStates() {
        StateMachine fsm = DnsStateMachine.build();
        assertFalse(fsm.getFuzzableStates().isEmpty());
    }

    @Test
    @DisplayName("FSM transitions from INITIAL on ALWAYS trigger")
    void fsmTransitionsFromInitial() {
        StateMachine fsm = DnsStateMachine.build();
        ProtocolState next = fsm.transition(StateTransition.Trigger.ALWAYS);
        assertNotNull(next);
        assertEquals(DnsStateMachine.S_SEND_STANDARD, next.getName());
    }

    @Test
    @DisplayName("FSM resets to initial state")
    void fsmResets() {
        StateMachine fsm = DnsStateMachine.build();
        fsm.transition(StateTransition.Trigger.ALWAYS);
        assertNotEquals(DnsStateMachine.S_INITIAL, fsm.getCurrentState().getName());
        fsm.reset();
        assertEquals(DnsStateMachine.S_INITIAL, fsm.getCurrentState().getName());
    }

    // -------------------------------------------------------------------------
    // Mutator Tests
    // -------------------------------------------------------------------------

    @Test
    @DisplayName("BitFlipMutator produces output same length as input")
    void bitFlipPreservesLength() throws IOException {
        byte[] input = DnsMessage.standardQuery(0x0001, "example.com").toBytes();
        Mutator m = new Mutators.BitFlipMutator(1);
        byte[] output = m.mutate(input);
        assertEquals(input.length, output.length);
    }

    @Test
    @DisplayName("BitFlipMutator does not modify original array")
    void bitFlipDoesNotModifyOriginal() throws IOException {
        byte[] input = DnsMessage.standardQuery(0x0001, "example.com").toBytes();
        byte[] copy  = input.clone();
        Mutator m = new Mutators.BitFlipMutator(4);
        m.mutate(input);
        assertArrayEquals(copy, input); // original unchanged
    }

    @Test
    @DisplayName("HeaderFlagsMutator produces 12+ byte output")
    void headerFlagsMutatorOutput() throws IOException {
        byte[] input = DnsMessage.standardQuery(0x0001, "example.com").toBytes();
        Mutator m = new Mutators.HeaderFlagsMutator();
        byte[] output = m.mutate(input);
        assertTrue(output.length >= 12);
    }

    @Test
    @DisplayName("OversizeLabelMutator produces output longer than input")
    void oversizeLabelMutatorProducesLargerOutput() throws IOException {
        byte[] input = DnsMessage.standardQuery(0x0001, "a.com").toBytes();
        Mutator m = new Mutators.OversizeLabelMutator();
        byte[] output = m.mutate(input);
        assertTrue(output.length > input.length);
    }

    @Test
    @DisplayName("MutationEngine round-robin cycles through all mutators")
    void mutationEngineRoundRobin() throws IOException {
        MutationEngine engine = new MutationEngine();
        byte[] seed = DnsMessage.standardQuery(0x0001, "example.com").toBytes();
        int count = engine.getMutatorCount();

        // Cycle through all + some
        for (int i = 0; i < count * 2; i++) {
            MutationEngine.MutationResult result = engine.mutateRoundRobin(seed);
            assertNotNull(result.bytes);
            assertNotNull(result.mutatorName);
        }
    }

    @Test
    @DisplayName("Stacked mutator produces output")
    void stackedMutatorProducesOutput() throws IOException {
        MutationEngine engine = new MutationEngine();
        byte[] seed = DnsMessage.standardQuery(0x0001, "example.com").toBytes();
        MutationEngine.MutationResult result = engine.mutateStacked(seed, 3);
        assertNotNull(result.bytes);
        assertTrue(result.mutatorName.contains("+"), "Stacked name should contain '+'");
    }
}
