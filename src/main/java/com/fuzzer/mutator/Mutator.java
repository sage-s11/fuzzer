package com.fuzzer.mutator;

/**
 * Base interface for all mutators.
 *
 * Each mutator takes a raw byte array (DNS message wire format)
 * and returns a mutated copy. Mutators must never modify the
 * original — always operate on a copy.
 */
public interface Mutator {

    /**
     * Apply this mutation to the input bytes.
     * @param input  original DNS message bytes
     * @return       mutated bytes (copy)
     */
    byte[] mutate(byte[] input);

    /**
     * Human-readable name for this mutator (used in crash logs).
     */
    String name();
}
