package com.fuzzer.mutator;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * v1 Mutator implementations.
 *
 * Each mutator targets a specific field or structural property of DNS messages.
 * Organized by what they attack:
 *
 *   1. BitFlipMutator       — randomly flip bits in the message
 *   2. BoundaryValueMutator — replace a byte with 0x00, 0xFF, 0x7F, 0x80
 *   3. HeaderFlagsMutator   — set all flag combinations in the DNS header
 *   4. QdCountMutator       — set question count to values that don't match actual questions
 *   5. LabelLengthMutator   — corrupt the first label length byte
 *   6. OversizeLabelMutator — replace domain name with a very long label
 *   7. NullByteMutator      — inject null bytes into the question section
 *   8. RandomTypeMutator    — replace QTYPE with unusual/reserved values
 */
public class Mutators {

    private static final Random RNG = new Random();

    // -------------------------------------------------------------------------
    // 1. Bit Flip
    // -------------------------------------------------------------------------
    public static class BitFlipMutator implements Mutator {
        private final int numBits;

        public BitFlipMutator(int numBits) { this.numBits = numBits; }

        @Override
        public byte[] mutate(byte[] input) {
            byte[] out = Arrays.copyOf(input, input.length);
            for (int i = 0; i < numBits; i++) {
                int pos = RNG.nextInt(out.length);
                int bit = RNG.nextInt(8);
                out[pos] ^= (1 << bit);
            }
            return out;
        }

        @Override public String name() { return "BitFlip(" + numBits + ")"; }
    }

    // -------------------------------------------------------------------------
    // 2. Boundary Value
    // -------------------------------------------------------------------------
    public static class BoundaryValueMutator implements Mutator {
        private static final byte[] BOUNDARIES = {0x00, (byte)0xFF, 0x7F, (byte)0x80, 0x01};

        @Override
        public byte[] mutate(byte[] input) {
            byte[] out = Arrays.copyOf(input, input.length);
            int pos = RNG.nextInt(out.length);
            out[pos] = BOUNDARIES[RNG.nextInt(BOUNDARIES.length)];
            return out;
        }

        @Override public String name() { return "BoundaryValue"; }
    }

    // -------------------------------------------------------------------------
    // 3. Header Flags Corruption
    // Targets bytes 2-3 (the flags word) in the DNS header
    // -------------------------------------------------------------------------
    public static class HeaderFlagsMutator implements Mutator {
        // Interesting flag combinations
        private static final int[] INTERESTING_FLAGS = {
            0xFFFF,  // all bits set
            0x0000,  // all bits clear
            0x8000,  // QR=1 (response) on what is a query
            0x7800,  // all opcodes set
            0x000F,  // all rcode bits set
            0xF800,  // QR + all opcodes
            0x0200,  // TC (truncated) set
            0xAAAA,  // alternating bits
            0x5555,  // alternating bits inverted
        };

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 4) return Arrays.copyOf(input, input.length);
            byte[] out = Arrays.copyOf(input, input.length);
            int flags = INTERESTING_FLAGS[RNG.nextInt(INTERESTING_FLAGS.length)];
            out[2] = (byte)((flags >> 8) & 0xFF);
            out[3] = (byte)(flags & 0xFF);
            return out;
        }

        @Override public String name() { return "HeaderFlags"; }
    }

    // -------------------------------------------------------------------------
    // 4. QDCOUNT Mismatch
    // Set QDCOUNT to values that contradict actual question count
    // -------------------------------------------------------------------------
    public static class QdCountMutator implements Mutator {
        private static final short[] INTERESTING = {0, -1, 100, 255, (short)0xFFFF};

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 6) return Arrays.copyOf(input, input.length);
            byte[] out = Arrays.copyOf(input, input.length);
            short val = INTERESTING[RNG.nextInt(INTERESTING.length)];
            out[4] = (byte)((val >> 8) & 0xFF);
            out[5] = (byte)(val & 0xFF);
            return out;
        }

        @Override public String name() { return "QdCountMismatch"; }
    }

    // -------------------------------------------------------------------------
    // 5. Label Length Corruption
    // The first byte after the header is the length of the first DNS label.
    // Setting this to invalid values causes parsers to misread the name.
    // -------------------------------------------------------------------------
    public static class LabelLengthMutator implements Mutator {
        private static final byte[] INTERESTING = {0x00, (byte)0xFF, 0x3F, 0x40, (byte)0xC0, 0x63};

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 13) return Arrays.copyOf(input, input.length);
            byte[] out = Arrays.copyOf(input, input.length);
            // Label starts at byte 12 (right after 12-byte header)
            out[12] = INTERESTING[RNG.nextInt(INTERESTING.length)];
            return out;
        }

        @Override public String name() { return "LabelLength"; }
    }

    // -------------------------------------------------------------------------
    // 6. Oversize Label
    // Replace domain name with a 255-byte max label — tests bounds checking
    // -------------------------------------------------------------------------
    public static class OversizeLabelMutator implements Mutator {
        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 12) return Arrays.copyOf(input, input.length);

            // Build oversize name: [63]AAAAAA...[63]BBBBBB...[63]CCCCCC...[3]DDD[0]
            byte[] longLabel = new byte[255];
            longLabel[0] = 63;
            Arrays.fill(longLabel, 1, 64, (byte)'A');
            longLabel[64] = 63;
            Arrays.fill(longLabel, 65, 128, (byte)'B');
            longLabel[128] = 63;
            Arrays.fill(longLabel, 129, 192, (byte)'C');
            longLabel[192] = 62;
            Arrays.fill(longLabel, 193, 255, (byte)'D');
            // No root label (intentionally — tests missing terminator)

            // Suffix: QTYPE + QCLASS
            byte[] suffix = {0x00, 0x01, 0x00, 0x01}; // TYPE=A, CLASS=IN

            byte[] header = Arrays.copyOf(input, 12);
            byte[] out = new byte[12 + longLabel.length + suffix.length];
            System.arraycopy(header, 0, out, 0, 12);
            System.arraycopy(longLabel, 0, out, 12, longLabel.length);
            System.arraycopy(suffix, 0, out, 12 + longLabel.length, suffix.length);
            return out;
        }

        @Override public String name() { return "OversizeLabel"; }
    }

    // -------------------------------------------------------------------------
    // 7. Null Byte Injection
    // Inject \x00 bytes at random positions in the question section
    // -------------------------------------------------------------------------
    public static class NullByteMutator implements Mutator {
        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 13) return Arrays.copyOf(input, input.length);
            byte[] out = Arrays.copyOf(input, input.length);
            // Only touch question section (after 12-byte header)
            int pos = 12 + RNG.nextInt(Math.max(1, out.length - 12));
            out[pos] = 0x00;
            return out;
        }

        @Override public String name() { return "NullByteInject"; }
    }

    // -------------------------------------------------------------------------
    // 8. Random QTYPE
    // Replace QTYPE with reserved or unusual values
    // -------------------------------------------------------------------------
    public static class RandomTypeMutator implements Mutator {
        // Interesting QTYPE values: reserved, obsolete, or rarely implemented
        private static final int[] TYPES = {
            0x0000,  // reserved
            0x00FF,  // ANY
            0x00FE,  // MAILB (obsolete)
            0x00FD,  // MAILA (obsolete)
            0x8000,  // private use range
            0xFFFF,  // reserved
            0x0100,  // not a real type
            0x00F9,  // TKEY
            0x00FA,  // TSIG
        };

        @Override
        public byte[] mutate(byte[] input) {
            if (input.length < 14) return Arrays.copyOf(input, input.length);
            byte[] out = Arrays.copyOf(input, input.length);

            // Find end of QNAME (first 0x00 after header) to locate QTYPE
            int nameEnd = 12;
            while (nameEnd < out.length && out[nameEnd] != 0x00) {
                int labelLen = out[nameEnd] & 0xFF;
                if ((labelLen & 0xC0) == 0xC0) { nameEnd += 2; break; }
                nameEnd += labelLen + 1;
            }
            nameEnd++; // skip root label

            if (nameEnd + 1 < out.length) {
                int qtype = TYPES[RNG.nextInt(TYPES.length)];
                out[nameEnd]     = (byte)((qtype >> 8) & 0xFF);
                out[nameEnd + 1] = (byte)(qtype & 0xFF);
            }
            return out;
        }

        @Override public String name() { return "RandomType"; }
    }
}
