package com.fuzzer.mutator;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * MutationEngine
 *
 * Manages a pool of mutators and applies them to DNS message seeds.
 * Supports:
 *   - Round-robin application (cycle through all mutators)
 *   - Random selection
 *   - Stacked mutations (apply N mutators in sequence for combinatorial coverage)
 */
public class MutationEngine {

    private final List<Mutator> mutators = new ArrayList<>();
    private final Random rng = new Random();
    private int roundRobinIndex = 0;

    public MutationEngine() {
        registerDefaults();
    }

    /**
     * Register the default v1 mutator set.
     */
    private void registerDefaults() {
        // v1 — byte-level mutators
        mutators.add(new Mutators.BitFlipMutator(1));
        mutators.add(new Mutators.BitFlipMutator(4));
        mutators.add(new Mutators.BoundaryValueMutator());
        mutators.add(new Mutators.HeaderFlagsMutator());
        mutators.add(new Mutators.QdCountMutator());
        mutators.add(new Mutators.LabelLengthMutator());
        mutators.add(new Mutators.OversizeLabelMutator());
        mutators.add(new Mutators.NullByteMutator());
        mutators.add(new Mutators.RandomTypeMutator());

        // v2 — semantic mutators (structure-aware, reach deeper code paths)
        // Compression pointer loops
        mutators.add(new SemanticMutators.CompressionPointerLoopMutator(
                SemanticMutators.CompressionPointerLoopMutator.Variant.SELF_LOOP));
        mutators.add(new SemanticMutators.CompressionPointerLoopMutator(
                SemanticMutators.CompressionPointerLoopMutator.Variant.TWO_HOP_LOOP));
        mutators.add(new SemanticMutators.CompressionPointerLoopMutator(
                SemanticMutators.CompressionPointerLoopMutator.Variant.FORWARD_PTR));
        mutators.add(new SemanticMutators.CompressionPointerLoopMutator(
                SemanticMutators.CompressionPointerLoopMutator.Variant.CHAIN_DEPTH));

        // EDNS option overflow
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.RDLENGTH_OVERFLOW));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.OPTION_LEN_OVERFLOW));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.ZERO_RDLENGTH));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.NEGATIVE_OPTION_LEN));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.STACKED_OVERFLOW));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.RESERVED_OPTION_CODE));
        mutators.add(new SemanticMutators.EdnsOptionOverflowMutator(
                SemanticMutators.EdnsOptionOverflowMutator.Variant.VERSION_NONZERO));

        // Zero-length label
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.ZERO_LABEL_MID));
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.ZERO_LABEL_START));
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.CONSECUTIVE_ZEROS));
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.LABEL_AFTER_ROOT));
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.MIXED_PTR_LABEL));
        mutators.add(new SemanticMutators.ZeroLengthLabelMutator(
                SemanticMutators.ZeroLengthLabelMutator.Variant.LONE_DOT));
    }

    public void register(Mutator m) {
        mutators.add(m);
    }

    /**
     * Isolate to a single named mutator.
     * All other mutators are removed from the pool.
     * The engine then runs only that one mutator for every iteration.
     *
     * Useful for:
     *   - Confirming a specific mutator is the actual cause of a finding
     *   - Deep-diving a suspicious mutator without noise from others
     *   - Running controlled experiments on one mutation class
     *
     * Mutator name matching is case-insensitive substring match.
     * e.g. "headerflags" matches "HeaderFlags"
     *      "bitflip"     matches "BitFlip(1)" and "BitFlip(4)"
     *      "label"       matches "LabelLength" and "OversizeLabel"
     */
    public void isolate(String mutatorName) {
        if (mutatorName == null || mutatorName.isBlank()) return;
        String lower = mutatorName.toLowerCase();
        List<Mutator> matched = mutators.stream()
                .filter(m -> m.name().toLowerCase().contains(lower))
                .toList();

        if (matched.isEmpty()) {
            System.out.printf("[MUTATION ENGINE] WARNING: No mutator matched '%s'. " +
                    "Available: %s%n", mutatorName, getMutatorNames());
            return;
        }

        mutators.clear();
        mutators.addAll(matched);
        roundRobinIndex = 0;
        System.out.printf("[MUTATION ENGINE] Isolated to %d mutator(s): %s%n",
                mutators.size(), getMutatorNames());
    }

    /**
     * Comma-separated list of currently active mutator names.
     */
    public String getMutatorNames() {
        return mutators.stream().map(Mutator::name)
                .reduce((a, b) -> a + ", " + b).orElse("none");
    }

    /**
     * Apply next mutator in round-robin order.
     */
    public MutationResult mutateRoundRobin(byte[] seed) {
        Mutator m = mutators.get(roundRobinIndex % mutators.size());
        roundRobinIndex++;
        byte[] result = m.mutate(seed);
        return new MutationResult(result, m.name());
    }

    /**
     * Apply a randomly chosen mutator.
     */
    public MutationResult mutateRandom(byte[] seed) {
        Mutator m = mutators.get(rng.nextInt(mutators.size()));
        byte[] result = m.mutate(seed);
        return new MutationResult(result, m.name());
    }

    /**
     * Apply N mutators stacked — for deeper combinatorial fuzzing.
     */
    public MutationResult mutateStacked(byte[] seed, int stackDepth) {
        List<Mutator> pool = new ArrayList<>(mutators);
        Collections.shuffle(pool, rng);
        int depth = Math.min(stackDepth, pool.size());

        byte[] current = seed;
        StringBuilder names = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            current = pool.get(i).mutate(current);
            if (i > 0) names.append("+");
            names.append(pool.get(i).name());
        }
        return new MutationResult(current, names.toString());
    }

    public List<Mutator> getMutators()  { return Collections.unmodifiableList(mutators); }
    public int getMutatorCount()        { return mutators.size(); }

    /**
     * Container for a mutation result — keeps the bytes and the mutator name together.
     */
    public static class MutationResult {
        public final byte[] bytes;
        public final String mutatorName;

        public MutationResult(byte[] bytes, String mutatorName) {
            this.bytes       = bytes;
            this.mutatorName = mutatorName;
        }
    }
}
