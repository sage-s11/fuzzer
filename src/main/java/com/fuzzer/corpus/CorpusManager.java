package com.fuzzer.corpus;

import com.fuzzer.dns.DnsMessage;
import com.fuzzer.dns.DnsQuestion;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * CorpusManager
 *
 * Manages seed DNS messages used as mutation starting points.
 *
 * Seeds are valid, well-formed DNS messages that the target server
 * will respond to correctly. We mutate from these seeds so that
 * the fuzzer starts from a known-good state and only introduces
 * targeted changes.
 *
 * v1: static seed corpus with manual entries.
 * Future: dynamic seed addition based on interesting responses.
 */
public class CorpusManager {

    private final List<SeedEntry> seeds = new ArrayList<>();
    private final Random rng = new Random();

    public CorpusManager() {}

    /**
     * Add a raw seed bytes entry.
     */
    public void addSeed(String label, byte[] bytes) {
        seeds.add(new SeedEntry(label, bytes));
    }

    /**
     * Build and register the default DNS seed corpus.
     * Covers: standard A query, MX query, NS query, AAAA query, ANY query
     */
    public void loadDefaultDnsSeeds(String targetDomain) throws IOException {
        // Standard A query
        DnsMessage a = DnsMessage.standardQuery(0x1337, targetDomain);
        addSeed("A_query", a.toBytes());

        // MX query
        DnsMessage mx = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x1338, true));
        mx.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_MX, DnsQuestion.CLASS_IN));
        addSeed("MX_query", mx.toBytes());

        // NS query
        DnsMessage ns = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x1339, true));
        ns.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_NS, DnsQuestion.CLASS_IN));
        addSeed("NS_query", ns.toBytes());

        // AAAA query
        DnsMessage aaaa = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x133A, true));
        aaaa.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_AAAA, DnsQuestion.CLASS_IN));
        addSeed("AAAA_query", aaaa.toBytes());

        // ANY query
        DnsMessage any = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x133B, true));
        any.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_ANY, DnsQuestion.CLASS_IN));
        addSeed("ANY_query", any.toBytes());

        // Subdomain query (tests label parsing depth)
        DnsMessage sub = DnsMessage.standardQuery(0x133C, "sub.sub." + targetDomain);
        addSeed("subdomain_query", sub.toBytes());

        System.out.printf("[CORPUS] Loaded %d default DNS seeds for domain '%s'%n",
                seeds.size(), targetDomain);
    }

    /**
     * Get a random seed.
     */
    public SeedEntry getRandom() {
        if (seeds.isEmpty()) throw new IllegalStateException("Corpus is empty");
        return seeds.get(rng.nextInt(seeds.size()));
    }

    /**
     * Get seed by label.
     */
    public SeedEntry getByLabel(String label) {
        return seeds.stream()
                .filter(s -> s.label.equals(label))
                .findFirst()
                .orElse(null);
    }

    /**
     * Get all seeds (for round-robin iteration).
     */
    public List<SeedEntry> getAll() {
        return Collections.unmodifiableList(seeds);
    }

    public int size() { return seeds.size(); }

    // -------------------------------------------------------------------------
    public static class SeedEntry {
        public final String label;
        public final byte[] bytes;
        public int timesUsed = 0;
        public int timesInteresting = 0;

        public SeedEntry(String label, byte[] bytes) {
            this.label = label;
            this.bytes = bytes;
        }

        @Override public String toString() {
            return String.format("Seed[%s %db used=%d]", label, bytes.length, timesUsed);
        }
    }
}
