package com.fuzzer.mutator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * SemanticMutators — v2 mutation classes.
 *
 * The key difference from v1:
 *   v1 mutators corrupt bytes without understanding structure.
 *   v2 mutators CONSTRUCT specifically shaped payloads that are
 *   valid enough to pass initial checks but contain logical traps
 *   deep in the parsing path.
 *
 * These reach code that v1 never touches because the message needs
 * to be structurally coherent up to the vulnerable field.
 *
 * ─────────────────────────────────────────────────────────────────
 * MUTATOR 1: CompressionPointerLoop
 *
 *   DNS name compression (RFC 1035 §4.1.4) uses 2-byte pointers
 *   (high bits 11xxxxxx xxxxxxxx) to reference earlier offsets.
 *   Parsers must follow the pointer to reconstruct the name.
 *
 *   Attack surface: pointer that creates a cycle.
 *   The parser follows A→B→A forever, or A→A immediately.
 *
 *   Variants:
 *     SELF_LOOP     — pointer at offset X points back to offset X
 *     TWO_HOP_LOOP  — pointer at X points to Y, pointer at Y points to X
 *     FORWARD_PTR   — pointer past end of packet (out-of-bounds read)
 *     CHAIN_DEPTH   — 128 chained pointers before loop (tests depth limit)
 *
 *   CVE history: CVE-2000-0333 (multiple DNS implementations),
 *                CVE-2017-14491 (dnsmasq — 8 byte overflow in DNS name processing)
 *
 * ─────────────────────────────────────────────────────────────────
 * MUTATOR 2: EdnsOptionOverflow
 *
 *   EDNS0 OPT record (RFC 6891) contains options as:
 *     [2-byte code][2-byte length][N-byte data]
 *
 *   Attack surface: option-length field claims more bytes than
 *   the OPT record's RDLENGTH allows. The option parser reads
 *   `length` bytes starting at `data` — if it doesn't bounds-check
 *   against RDLENGTH, it reads past the end of the record.
 *
 *   Also attacks: negative/zero option lengths, option code in
 *   reserved range, RDLENGTH larger than UDP payload, stacked
 *   options where combined length overflows.
 *
 *   Variants:
 *     RDLENGTH_OVERFLOW    — RDLENGTH claims more bytes than packet contains
 *     OPTION_LEN_OVERFLOW  — single option-length > RDLENGTH
 *     ZERO_RDLENGTH        — RDLENGTH=0 but options present in packet
 *     NEGATIVE_OPTION_LEN  — option-length = 0xFFFF
 *     STACKED_OVERFLOW     — many options whose lengths sum past RDLENGTH
 *     RESERVED_OPTION_CODE — option code 0x0000 or 0xFFFF
 *     VERSION_NONZERO      — EDNS version field != 0 (should return BADVERS)
 *
 *   CVE history: CVE-2016-2776 (BIND 9 — assertion failure in buffer handling)
 *
 * ─────────────────────────────────────────────────────────────────
 * MUTATOR 3: ZeroLengthLabel
 *
 *   A DNS name label with length=0 IS the root label terminator.
 *   Injecting a zero-length label mid-name creates ambiguity:
 *     fuzz.local   → [4]fuzz[5]local[0]        (valid)
 *     fuzz..local  → [4]fuzz[0][5]local[0]     (zero-length label mid-name)
 *
 *   Parsers see the [0] and think the name is done. The [5]local[0]
 *   that follows is then parsed as the QTYPE/QCLASS — completely
 *   wrong bytes in a wrong context. Some parsers crash, some
 *   return garbage, some silently accept it.
 *
 *   Also attacks: labels that are valid but in wrong positions,
 *   names that are syntactically valid but semantically impossible,
 *   and names with mixed pointer/label encodings.
 *
 *   Variants:
 *     ZERO_LABEL_MID       — zero-length label inserted after first label
 *     ZERO_LABEL_START     — name starts with zero-length label (empty root)
 *     CONSECUTIVE_ZEROS    — multiple consecutive zero-length labels
 *     LABEL_AFTER_ROOT     — data bytes after the root label before QTYPE
 *     MIXED_PTR_LABEL      — valid label followed immediately by pointer
 *     LONE_DOT             — single dot (".") as entire domain name
 */
public class SemanticMutators {

    private static final Random RNG = new Random();

    // =========================================================================
    // MUTATOR 1: Compression Pointer Loop
    // =========================================================================

    public static class CompressionPointerLoopMutator implements Mutator {

        public enum Variant {
            SELF_LOOP,      // pointer points to itself
            TWO_HOP_LOOP,   // A→B→A cycle
            FORWARD_PTR,    // pointer past end of packet (OOB read)
            CHAIN_DEPTH     // deep chain before loop
        }

        private final Variant variant;

        public CompressionPointerLoopMutator(Variant variant) {
            this.variant = variant;
        }

        /** Random variant constructor — picks a variant each call */
        public CompressionPointerLoopMutator() {
            this.variant = null; // null = random each invocation
        }

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 12) return Arrays.copyOf(input, input.length);
            Variant v = (variant != null) ? variant : Variant.values()[RNG.nextInt(Variant.values().length)];
            try {
                return switch (v) {
                    case SELF_LOOP    -> buildSelfLoop(input);
                    case TWO_HOP_LOOP -> buildTwoHopLoop(input);
                    case FORWARD_PTR  -> buildForwardPointer(input);
                    case CHAIN_DEPTH  -> buildChainDepth(input);
                };
            } catch (Exception e) {
                return Arrays.copyOf(input, input.length);
            }
        }

        /**
         * SELF_LOOP: Replace the QNAME with a single pointer that points to itself.
         *
         * Wire layout:
         *   [header 12 bytes]
         *   [0xC0][0x0C]   ← pointer at offset 12, pointing to offset 12 (itself)
         *   [0x00][0x01]   ← QTYPE=A
         *   [0x00][0x01]   ← QCLASS=IN
         *
         * A parser following this pointer enters an infinite loop:
         *   offset 12 → read 0xC00C → go to offset 12 → read 0xC00C → ...
         */
        private byte[] buildSelfLoop(byte[] input) {
            byte[] header = Arrays.copyOf(input, 12);
            // pointer 0xC00C = bits 11 + offset 12 (0x0C)
            byte[] name   = {(byte)0xC0, 0x0C};
            byte[] suffix = {0x00, 0x01, 0x00, 0x01}; // A IN
            return concat(header, name, suffix);
        }

        /**
         * TWO_HOP_LOOP: Two pointers that point at each other.
         *
         * Wire layout:
         *   [header 12 bytes]
         *   [0xC0][0x10]   ← at offset 12: pointer to offset 16
         *   [0x00][0x01]   ← QTYPE placeholder at offset 14
         *   [0x00][0x01]   ← QCLASS placeholder at offset 16
         *   Wait — we need the second pointer at 16:
         *
         * Actual layout:
         *   offset 12: [0xC0][0x0E]  ← pointer to offset 14
         *   offset 14: [0xC0][0x0C]  ← pointer back to offset 12
         *   offset 16: [0x00][0x01][0x00][0x01]  ← QTYPE/QCLASS (never reached)
         */
        private byte[] buildTwoHopLoop(byte[] input) {
            byte[] header = Arrays.copyOf(input, 12);
            byte[] body = {
                (byte)0xC0, 0x0E,  // offset 12: → offset 14
                (byte)0xC0, 0x0C,  // offset 14: → offset 12 (loop)
                0x00, 0x01,        // QTYPE=A  (unreachable)
                0x00, 0x01         // QCLASS=IN (unreachable)
            };
            return concat(header, body);
        }

        /**
         * FORWARD_PTR: Pointer that references an offset beyond the packet end.
         *
         * The parser tries to jump to offset 0x1FFF (8191) in a packet
         * that's only ~20 bytes. This is an out-of-bounds read — the
         * parser reads whatever is in memory at that offset.
         *
         * offset 12: [0xDF][0xFF] = pointer to offset 0x1FFF
         */
        private byte[] buildForwardPointer(byte[] input) {
            byte[] header = Arrays.copyOf(input, 12);
            // 0xDF = 1101 1111 → bits 11 set (pointer), offset high = 0x1F
            // 0xFF = offset low = 0xFF → total offset = 0x1FFF = 8191
            byte[] body = {
                (byte)0xDF, (byte)0xFF,  // pointer to way-out-of-bounds offset
                0x00, 0x01,              // QTYPE=A
                0x00, 0x01               // QCLASS=IN
            };
            return concat(header, body);
        }

        /**
         * CHAIN_DEPTH: 64 pointer hops before hitting a self-loop.
         *
         * Tests whether the parser has a depth limit on pointer following.
         * RFC 1035 doesn't specify a limit. Some parsers limit to 128 hops,
         * some to 10, some have none (crash risk).
         *
         * Each hop is 2 bytes. 64 hops = 128 bytes of pointer chain.
         * The last pointer loops back to the first.
         *
         * Layout:
         *   offset 12:  [0xC0][0x0E] → offset 14
         *   offset 14:  [0xC0][0x10] → offset 16
         *   ...
         *   offset 12+126: [0xC0][0x0C] → back to offset 12 (loop)
         */
        private byte[] buildChainDepth(byte[] input) throws IOException {
            byte[] header = Arrays.copyOf(input, 12);
            int depth = 64;
            ByteArrayOutputStream body = new ByteArrayOutputStream();

            // Each pointer at position (12 + i*2) points to (12 + (i+1)*2)
            for (int i = 0; i < depth - 1; i++) {
                int nextOffset = 12 + (i + 1) * 2;
                body.write(0xC0 | ((nextOffset >> 8) & 0x3F));
                body.write(nextOffset & 0xFF);
            }
            // Last pointer loops back to offset 12
            body.write(0xC0);
            body.write(0x0C);

            // QTYPE + QCLASS (unreachable but structurally present)
            body.write(new byte[]{0x00, 0x01, 0x00, 0x01});

            return concat(header, body.toByteArray());
        }

        @Override
        public String name() {
            return "CompressionPtrLoop(" + (variant != null ? variant : "RANDOM") + ")";
        }

        private byte[] concat(byte[]... parts) {
            int total = Arrays.stream(parts).mapToInt(p -> p.length).sum();
            byte[] out = new byte[total];
            int pos = 0;
            for (byte[] p : parts) {
                System.arraycopy(p, 0, out, pos, p.length);
                pos += p.length;
            }
            return out;
        }
    }

    // =========================================================================
    // MUTATOR 2: EDNS Option Overflow
    // =========================================================================

    public static class EdnsOptionOverflowMutator implements Mutator {

        public enum Variant {
            RDLENGTH_OVERFLOW,    // RDLENGTH > actual remaining bytes in packet
            OPTION_LEN_OVERFLOW,  // single option-length > RDLENGTH
            ZERO_RDLENGTH,        // RDLENGTH=0 but option bytes follow in packet
            NEGATIVE_OPTION_LEN,  // option-length = 0xFFFF
            STACKED_OVERFLOW,     // many options summing past RDLENGTH
            RESERVED_OPTION_CODE, // option code 0x0000 or 0xFFFF
            VERSION_NONZERO       // EDNS version != 0 (should trigger BADVERS)
        }

        private final Variant variant;

        public EdnsOptionOverflowMutator(Variant variant) {
            this.variant = variant;
        }

        public EdnsOptionOverflowMutator() {
            this.variant = null;
        }

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 12) return Arrays.copyOf(input, input.length);
            Variant v = (variant != null) ? variant : Variant.values()[RNG.nextInt(Variant.values().length)];
            try {
                return buildWithEdns(input, v);
            } catch (Exception e) {
                return Arrays.copyOf(input, input.length);
            }
        }

        /**
         * Build a DNS query with a valid question section followed by
         * a malformed EDNS0 OPT record in the additional section.
         *
         * The question section is kept valid so BIND9 parses past it
         * and reaches the OPT record parser — which is where the trap is.
         */
        private byte[] buildWithEdns(byte[] input, Variant v) throws IOException {
            // Extract valid question from input (bytes 12 onward)
            // or build a minimal one if input is too short
            byte[] question = extractOrBuildQuestion(input);

            // Build malformed OPT record
            byte[] opt = buildOpt(v);

            // Build header with ARCOUNT=1 (one additional record = our OPT)
            byte[] header = buildHeader(input, 1);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(header);
            out.write(question);
            out.write(opt);
            return out.toByteArray();
        }

        /**
         * Build a 12-byte DNS header.
         * Preserves ID from input, sets standard query flags, QDCOUNT=1, ARCOUNT=arCount.
         */
        private byte[] buildHeader(byte[] input, int arCount) {
            ByteBuffer buf = ByteBuffer.allocate(12);
            int id = (input.length >= 2)
                    ? ((input[0] & 0xFF) << 8) | (input[1] & 0xFF)
                    : 0x1337;
            buf.putShort((short) id);
            buf.putShort((short) 0x0100);  // QR=0 RD=1
            buf.putShort((short) 1);       // QDCOUNT=1
            buf.putShort((short) 0);       // ANCOUNT=0
            buf.putShort((short) 0);       // NSCOUNT=0
            buf.putShort((short) arCount); // ARCOUNT
            return buf.array();
        }

        /**
         * Extract question bytes from input, or build a minimal valid question.
         */
        private byte[] extractOrBuildQuestion(byte[] input) throws IOException {
            if (input.length > 12) {
                // Find end of question section in input
                int pos = 12;
                while (pos < input.length) {
                    int b = input[pos] & 0xFF;
                    if (b == 0) { pos += 5; break; }          // root label + QTYPE + QCLASS
                    if ((b & 0xC0) == 0xC0) { pos += 6; break; } // pointer + QTYPE + QCLASS
                    pos += b + 1;
                }
                if (pos <= input.length) {
                    return Arrays.copyOfRange(input, 12, pos);
                }
            }
            // Fallback: minimal valid question for "fuzz.local" TYPE=A CLASS=IN
            return new byte[]{
                0x04, 0x66, 0x75, 0x7A, 0x7A,  // [4]fuzz
                0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, // [5]local
                0x00,                                 // root
                0x00, 0x01,                           // TYPE=A
                0x00, 0x01                            // CLASS=IN
            };
        }

        /**
         * Build a malformed OPT record per the selected variant.
         *
         * OPT record wire format:
         *   0x00         NAME = root
         *   0x00 0x29    TYPE = 41 (OPT)
         *   0x10 0x00    CLASS = UDP payload size (4096)
         *   0x00 0x00 0x00 0x00  TTL = ext-rcode(0) + version(0) + flags(0)
         *   [2 bytes]    RDLENGTH
         *   [N bytes]    RDATA = options
         */
        private byte[] buildOpt(Variant v) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(0x00);               // NAME = root
            out.write(new byte[]{0x00, 0x29}); // TYPE = OPT (41)

            switch (v) {

                case RDLENGTH_OVERFLOW -> {
                    // CLASS=4096, TTL=0, RDLENGTH=512 but NO rdata bytes follow
                    // Parser tries to read 512 bytes that aren't there
                    out.write(new byte[]{0x10, 0x00}); // CLASS=4096
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00}); // TTL=0
                    out.write(new byte[]{0x02, 0x00}); // RDLENGTH=512 (0x0200)
                    // No RDATA — parser reads past end of packet
                }

                case OPTION_LEN_OVERFLOW -> {
                    // Valid RDLENGTH=8, but option inside claims length=0x7FFF
                    // Option: [code=8 (ECS)][length=0x7FFF][2 bytes data]
                    // Parser reads option-length=32767 into a 2-byte actual data region
                    byte[] option = {
                        0x00, 0x08,        // option code = ECS (8)
                        0x7F, (byte)0xFF,  // option-length = 32767 (way more than available)
                        0x00, 0x00         // 2 bytes of actual data
                    };
                    out.write(new byte[]{0x10, 0x00}); // CLASS=4096
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00}); // TTL=0
                    writeShort(out, option.length);    // RDLENGTH = actual option bytes
                    out.write(option);
                }

                case ZERO_RDLENGTH -> {
                    // RDLENGTH=0 but we append option bytes AFTER the OPT record
                    // Some parsers read RDLENGTH to know how far to advance, then
                    // stop. Others read the next bytes as QTYPE/QCLASS of a phantom
                    // question. Tests what happens when RDLENGTH disagrees with content.
                    byte[] trailingOption = {
                        0x00, 0x03,  // option code = NSID
                        0x00, 0x04,  // option-length = 4
                        0x41, 0x41, 0x41, 0x41 // "AAAA"
                    };
                    out.write(new byte[]{0x10, 0x00});
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00});
                    out.write(new byte[]{0x00, 0x00}); // RDLENGTH = 0
                    out.write(trailingOption);          // bytes after OPT — parser confusion
                }

                case NEGATIVE_OPTION_LEN -> {
                    // option-length = 0xFFFF (65535 as unsigned, or -1 as signed)
                    // If parser interprets as signed and checks > 0, it passes.
                    // Then tries to read 65535 bytes → massive OOB read.
                    byte[] option = {
                        0x00, 0x0A,        // option code = COOKIE (10)
                        (byte)0xFF, (byte)0xFF, // option-length = 0xFFFF
                        0x01, 0x02, 0x03, 0x04  // 4 bytes of actual data
                    };
                    out.write(new byte[]{0x10, 0x00});
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00});
                    writeShort(out, option.length);
                    out.write(option);
                }

                case STACKED_OVERFLOW -> {
                    // 10 options each claiming length=100, but RDLENGTH only covers 10*8=80 bytes
                    // Combined claimed length = 1000 bytes vs actual 80 bytes
                    // Tests whether the parser validates cumulative option length
                    ByteArrayOutputStream opts = new ByteArrayOutputStream();
                    for (int i = 0; i < 10; i++) {
                        opts.write(new byte[]{0x00, (byte)(i + 1)}); // code=1..10
                        opts.write(new byte[]{0x00, 0x64});           // length=100 (claimed)
                        opts.write(new byte[]{0x41, 0x41, 0x41, 0x41}); // 4 bytes actual data
                    }
                    byte[] allOpts = opts.toByteArray();
                    out.write(new byte[]{0x10, 0x00});
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00});
                    writeShort(out, allOpts.length); // RDLENGTH = actual bytes (not claimed)
                    out.write(allOpts);
                }

                case RESERVED_OPTION_CODE -> {
                    // Option codes 0x0000 and 0xFFFF are reserved (RFC 6891)
                    // Servers should ignore unknown options, but reserved codes
                    // may have special handling that's under-tested
                    int code = (RNG.nextBoolean()) ? 0x0000 : 0xFFFF;
                    byte[] option = {
                        (byte)((code >> 8) & 0xFF), (byte)(code & 0xFF), // reserved code
                        0x00, 0x08,  // length=8
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  // 8 bytes data
                    };
                    out.write(new byte[]{0x10, 0x00});
                    out.write(new byte[]{0x00, 0x00, 0x00, 0x00});
                    writeShort(out, option.length);
                    out.write(option);
                }

                case VERSION_NONZERO -> {
                    // EDNS version field (byte 2 of TTL) != 0
                    // RFC 6891 §6.1.3: server MUST respond with BADVERS (rcode=16)
                    // Tests whether the BADVERS path has any bugs
                    int[] versions = {1, 2, 127, 255};
                    int ver = versions[RNG.nextInt(versions.length)];
                    out.write(new byte[]{0x10, 0x00}); // CLASS=4096
                    // TTL: extRcode=0, version=ver, flags=0
                    out.write(new byte[]{0x00, (byte)ver, 0x00, 0x00});
                    out.write(new byte[]{0x00, 0x00}); // RDLENGTH=0
                }
            }

            return out.toByteArray();
        }

        private void writeShort(ByteArrayOutputStream out, int value) {
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
        }

        @Override
        public String name() {
            return "EdnsOptOverflow(" + (variant != null ? variant : "RANDOM") + ")";
        }
    }

    // =========================================================================
    // MUTATOR 3: Zero-Length Label
    // =========================================================================

    public static class ZeroLengthLabelMutator implements Mutator {

        public enum Variant {
            ZERO_LABEL_MID,       // zero-length label after first label
            ZERO_LABEL_START,     // name starts with zero-length label
            CONSECUTIVE_ZEROS,    // multiple consecutive zero-length labels
            LABEL_AFTER_ROOT,     // extra bytes after root label before QTYPE
            MIXED_PTR_LABEL,      // valid label followed immediately by pointer
            LONE_DOT              // single dot (root zone) as entire QNAME
        }

        private final Variant variant;

        public ZeroLengthLabelMutator(Variant variant) {
            this.variant = variant;
        }

        public ZeroLengthLabelMutator() {
            this.variant = null;
        }

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 12) return Arrays.copyOf(input, input.length);
            Variant v = (variant != null) ? variant : Variant.values()[RNG.nextInt(Variant.values().length)];
            try {
                return buildWithVariant(input, v);
            } catch (Exception e) {
                return Arrays.copyOf(input, input.length);
            }
        }

        private byte[] buildWithVariant(byte[] input, Variant v) throws IOException {
            byte[] header = Arrays.copyOf(input, 12);
            byte[] qname;
            byte[] suffix = {0x00, 0x01, 0x00, 0x01}; // TYPE=A CLASS=IN

            qname = switch (v) {

                case ZERO_LABEL_MID ->
                    // [4]fuzz [0] [5]local [0]
                    // The [0] after "fuzz" terminates the name prematurely.
                    // "local" becomes garbage after QTYPE offset.
                    new byte[]{
                        0x04, 'f','u','z','z',          // [4]fuzz
                        0x00,                            // ← zero-length label (root)
                        0x05, 'l','o','c','a','l',       // [5]local — now after "root"
                        0x00                             // actual root
                    };

                case ZERO_LABEL_START ->
                    // Name starts with [0] — immediately root, then more labels follow.
                    // Parser sees root label at offset 12 and stops.
                    // "fuzz.local" is then in the position of QTYPE/QCLASS.
                    new byte[]{
                        0x00,                            // ← root label immediately
                        0x04, 'f','u','z','z',           // [4]fuzz — now "QTYPE" position
                        0x05, 'l','o','c','a','l',       // [5]local — garbage
                        0x00
                    };

                case CONSECUTIVE_ZEROS ->
                    // Three consecutive zero-length labels mid-name.
                    // [4]fuzz [0][0][0] [5]local [0]
                    new byte[]{
                        0x04, 'f','u','z','z',
                        0x00, 0x00, 0x00,                // three consecutive zeros
                        0x05, 'l','o','c','a','l',
                        0x00
                    };

                case LABEL_AFTER_ROOT ->
                    // Valid name terminated by root, then extra label bytes before QTYPE.
                    // [4]fuzz [5]local [0] [3]foo [0] [QTYPE] [QCLASS]
                    // The extra [3]foo[0] sits between root label and QTYPE.
                    // Parser that advances past root to read QTYPE will read [3]=0x03
                    // as QTYPE high byte → QTYPE=0x0300 (undefined).
                    new byte[]{
                        0x04, 'f','u','z','z',
                        0x05, 'l','o','c','a','l',
                        0x00,                            // root label
                        0x03, 'f','o','o',               // extra label after root
                        0x00                             // second root
                    };

                case MIXED_PTR_LABEL ->
                    // Valid label [4]fuzz followed immediately by a pointer.
                    // The pointer at offset 12+5=17 points back to offset 12.
                    // Creates: fuzz → (pointer to offset 12) → fuzz → (pointer to offset 12) → loop
                    new byte[]{
                        0x04, 'f','u','z','z',           // [4]fuzz — 5 bytes, ends at offset 17
                        (byte)0xC0, 0x0C                 // pointer back to offset 12 → loop
                    };

                case LONE_DOT ->
                    // The root zone "." — a single zero byte is a valid QNAME.
                    // This is technically valid (querying the root) but rarely tested.
                    // Interesting because QTYPE/QCLASS immediately follow.
                    new byte[]{ 0x00 };
            };

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(header);
            out.write(qname);
            // Only append standard suffix for variants that don't already encode it
            if (v != Variant.MIXED_PTR_LABEL) {
                out.write(suffix);
            } else {
                out.write(suffix); // pointer loop — suffix unreachable but structurally present
            }
            return out.toByteArray();
        }

        @Override
        public String name() {
            return "ZeroLengthLabel(" + (variant != null ? variant : "RANDOM") + ")";
        }
    }
}
