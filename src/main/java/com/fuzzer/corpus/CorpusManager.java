package com.fuzzer.corpus;

import com.fuzzer.dns.DnsMessage;
import com.fuzzer.dns.DnsQuestion;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * CorpusManager — v2 with Corpus Evolution
 *
 * Theory:
 * A static corpus fuzzes the same 6 seeds forever. No matter how many
 * iterations run, the fuzzer never gets smarter — it just repeats the
 * same mutations from the same starting points.
 *
 * Corpus evolution fixes this by treating interesting responses as new
 * seeds. If a mutated input causes the server to behave unusually, that
 * input is promoted into the corpus. Future mutations start from it,
 * exploring the nearby space of inputs that caused the anomaly.
 *
 * "Interesting" is defined by observable response behavior (black-box):
 *   - SERVFAIL (rcode=2)       — server hit an internal error
 *   - Unusual RCODE            — unexpected response code
 *   - High RTT (>200ms)        — server spent time on this input
 *   - Large response (>512b)   — triggered deep processing
 *   - Near-crash (timeout)     — server was stressed but recovered
 *
 * Seeds are scored and deduplicated by payload hash. Low-scoring seeds
 * that are never selected for interesting results are eventually pruned
 * to keep the corpus from growing unboundedly.
 *
 * Generation tracking: each promoted seed records which generation it
 * came from, so we can see how deep the evolution went.
 */
public class CorpusManager {

    // -------------------------------------------------------------------------
    // Tuning constants
    // -------------------------------------------------------------------------
    private static final int    MAX_CORPUS_SIZE     = 200;   // hard cap
    private static final int    MIN_ORIGINAL_SEEDS  = 6;     // never prune originals
    private static final int    PRUNE_THRESHOLD     = 20;    // prune after N uses with no promotion
    private static final double HIGH_RTT_MS         = 200.0; // RTT threshold for "interesting"
    private static final int    LARGE_RESPONSE_BYTES = 512;  // response size threshold

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    private final List<SeedEntry>       seeds        = new ArrayList<>();
    private final Set<Long>             seenHashes   = new HashSet<>();
    private final Random                rng          = new Random();
    private final AtomicLong            totalPromoted = new AtomicLong(0);
    private final AtomicLong            totalPruned   = new AtomicLong(0);

    // Weighted selection — seeds with higher interestingness score get picked more
    private static final double WEIGHT_PROMOTED  = 3.0;   // promoted seeds 3x more likely
    private static final double WEIGHT_ORIGINAL  = 1.0;

    public CorpusManager() {}

    // -------------------------------------------------------------------------
    // Seed loading
    // -------------------------------------------------------------------------

    public void addSeed(String label, byte[] bytes) {
        long hash = hash(bytes);
        if (seenHashes.contains(hash)) return;
        seenHashes.add(hash);
        seeds.add(new SeedEntry(label, bytes, 0, SeedEntry.Origin.ORIGINAL));
    }

    public void loadDefaultDnsSeeds(String targetDomain) throws IOException {
        DnsMessage a = DnsMessage.standardQuery(0x1337, targetDomain);
        addSeed("A_query", a.toBytes());

        DnsMessage mx = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x1338, true));
        mx.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_MX, DnsQuestion.CLASS_IN));
        addSeed("MX_query", mx.toBytes());

        DnsMessage ns = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x1339, true));
        ns.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_NS, DnsQuestion.CLASS_IN));
        addSeed("NS_query", ns.toBytes());

        DnsMessage aaaa = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x133A, true));
        aaaa.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_AAAA, DnsQuestion.CLASS_IN));
        addSeed("AAAA_query", aaaa.toBytes());

        DnsMessage any = new DnsMessage(new com.fuzzer.dns.DnsHeader(0x133B, true));
        any.addQuestion(new DnsQuestion(targetDomain, DnsQuestion.TYPE_ANY, DnsQuestion.CLASS_IN));
        addSeed("ANY_query", any.toBytes());

        DnsMessage sub = DnsMessage.standardQuery(0x133C, "sub.sub." + targetDomain);
        addSeed("subdomain_query", sub.toBytes());

        System.out.printf("[CORPUS] Loaded %d default DNS seeds for domain '%s'%n",
                seeds.size(), targetDomain);
    }

    // -------------------------------------------------------------------------
    // Evolution — called after every response
    // -------------------------------------------------------------------------

    /**
     * Evaluate a mutation result and decide whether to promote it to the corpus.
     *
     * @param mutatedBytes  the payload that was sent
     * @param mutatorName   which mutator produced it
     * @param parentLabel   the seed it was derived from
     * @param rcode         DNS RCODE from response (-1 if no response)
     * @param rttMs         round-trip time in milliseconds
     * @param responseSize  size of response in bytes (0 if no response)
     * @param wasTimeout    true if the server timed out on this input
     * @param parentGen     generation of the parent seed
     * @return true if the payload was promoted to the corpus
     */
    public boolean evaluate(byte[] mutatedBytes, String mutatorName, String parentLabel,
                            int rcode, long rttMs, int responseSize,
                            boolean wasTimeout, int parentGen) {

        InterestingnessResult result = score(rcode, rttMs, responseSize, wasTimeout);
        if (!result.isInteresting) return false;

        long hash = hash(mutatedBytes);
        if (seenHashes.contains(hash)) return false; // already have this payload

        // Corpus is full — prune before adding
        if (seeds.size() >= MAX_CORPUS_SIZE) {
            pruneOne();
        }

        seenHashes.add(hash);
        String label = String.format("evolved[%s→%s gen%d]",
                parentLabel, mutatorName, parentGen + 1);
        SeedEntry promoted = new SeedEntry(label, mutatedBytes,
                parentGen + 1, SeedEntry.Origin.EVOLVED);
        promoted.interestScore = result.score;
        seeds.add(promoted);
        totalPromoted.incrementAndGet();

        System.out.printf("[CORPUS] ► Promoted new seed: %s (score=%.1f, reason=%s)%n",
                label, result.score, result.reason);
        return true;
    }

    /**
     * Score the interestingness of a response.
     * Higher score = more interesting = more likely to produce new seeds.
     */
    private InterestingnessResult score(int rcode, long rttMs,
                                         int responseSize, boolean wasTimeout) {
        double score = 0;
        List<String> reasons = new ArrayList<>();

        // SERVFAIL — server hit internal error processing this input
        if (rcode == 2) {
            score += 5.0;
            reasons.add("SERVFAIL");
        }

        // Unusual RCODE — not NOERROR(0), FORMERR(1), NXDOMAIN(3), REFUSED(5)
        if (rcode > 0 && rcode != 1 && rcode != 3 && rcode != 5 && rcode != 2) {
            score += 3.0;
            reasons.add("unusual_rcode=" + rcode);
        }

        // Timeout — server was stressed but didn't die
        if (wasTimeout) {
            score += 4.0;
            reasons.add("timeout");
        }

        // Slow RTT — server spent significant time on this input
        if (rttMs > HIGH_RTT_MS) {
            score += 2.0;
            reasons.add(String.format("slow_rtt=%dms", rttMs));
        }

        // Large response — triggered deep code paths
        if (responseSize > LARGE_RESPONSE_BYTES) {
            score += 1.5;
            reasons.add(String.format("large_response=%db", responseSize));
        }

        boolean interesting = score >= 1.5;
        String reason = reasons.isEmpty() ? "none" : String.join("+", reasons);
        return new InterestingnessResult(interesting, score, reason);
    }

    // -------------------------------------------------------------------------
    // Pruning — remove low-value evolved seeds when corpus is full
    // -------------------------------------------------------------------------

    private void pruneOne() {
        // Never prune original seeds or seeds that have produced promotions
        // Find the evolved seed with the lowest value: high use count, zero children
        SeedEntry candidate = null;
        int candidateIdx = -1;

        for (int i = MIN_ORIGINAL_SEEDS; i < seeds.size(); i++) {
            SeedEntry s = seeds.get(i);
            if (s.origin == SeedEntry.Origin.ORIGINAL) continue;
            if (s.timesUsed >= PRUNE_THRESHOLD && s.childrenPromoted == 0) {
                if (candidate == null || s.timesUsed > candidate.timesUsed) {
                    candidate = s;
                    candidateIdx = i;
                }
            }
        }

        if (candidateIdx >= 0) {
            seeds.remove(candidateIdx);
            totalPruned.incrementAndGet();
            System.out.printf("[CORPUS] ◄ Pruned stale seed: %s (used=%d, children=0)%n",
                    candidate.label, candidate.timesUsed);
        }
    }

    // -------------------------------------------------------------------------
    // Selection — weighted random, promoted seeds selected more often
    // -------------------------------------------------------------------------

    /**
     * Get a seed using weighted random selection.
     * Promoted seeds are 3x more likely to be selected than originals,
     * reflecting that they're closer to interesting behavior.
     */
    public SeedEntry getRandom() {
        if (seeds.isEmpty()) throw new IllegalStateException("Corpus is empty");

        double totalWeight = seeds.stream()
                .mapToDouble(s -> s.origin == SeedEntry.Origin.EVOLVED
                        ? WEIGHT_PROMOTED : WEIGHT_ORIGINAL)
                .sum();

        double pick = rng.nextDouble() * totalWeight;
        double cumulative = 0;
        for (SeedEntry s : seeds) {
            cumulative += (s.origin == SeedEntry.Origin.EVOLVED
                    ? WEIGHT_PROMOTED : WEIGHT_ORIGINAL);
            if (pick <= cumulative) return s;
        }
        return seeds.get(seeds.size() - 1);
    }

    public SeedEntry getByLabel(String label) {
        return seeds.stream()
                .filter(s -> s.label.equals(label))
                .findFirst().orElse(null);
    }

    public List<SeedEntry> getAll() {
        return Collections.unmodifiableList(seeds);
    }

    public int size()              { return seeds.size(); }
    public long totalPromoted()    { return totalPromoted.get(); }
    public long totalPruned()      { return totalPruned.get(); }

    public void printCorpusStats() {
        long evolved   = seeds.stream().filter(s -> s.origin == SeedEntry.Origin.EVOLVED).count();
        long original  = seeds.stream().filter(s -> s.origin == SeedEntry.Origin.ORIGINAL).count();
        int  maxGen    = seeds.stream().mapToInt(s -> s.generation).max().orElse(0);
        System.out.printf("[CORPUS] Size=%d  original=%d  evolved=%d  maxGen=%d  " +
                "promoted=%d  pruned=%d%n",
                seeds.size(), original, evolved, maxGen,
                totalPromoted.get(), totalPruned.get());
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static long hash(byte[] bytes) {
        long h = 0xcbf29ce484222325L;
        for (byte b : bytes) {
            h ^= (b & 0xFF);
            h *= 0x100000001b3L;
        }
        return h;
    }

    // -------------------------------------------------------------------------
    // Inner types
    // -------------------------------------------------------------------------

    private static class InterestingnessResult {
        final boolean isInteresting;
        final double  score;
        final String  reason;
        InterestingnessResult(boolean i, double s, String r) {
            isInteresting = i; score = s; reason = r;
        }
    }

    public static class SeedEntry {
        public enum Origin { ORIGINAL, EVOLVED }

        public final String label;
        public final byte[] bytes;
        public final int    generation;    // 0 = original seed, N = Nth generation evolved
        public final Origin origin;
        public double interestScore  = 0;
        public int    timesUsed      = 0;
        public int    childrenPromoted = 0; // how many corpus entries came from this seed
        public int    timesInteresting = 0;

        public SeedEntry(String label, byte[] bytes, int generation, Origin origin) {
            this.label      = label;
            this.bytes      = bytes;
            this.generation = generation;
            this.origin     = origin;
        }

        @Override public String toString() {
            return String.format("Seed[%s gen=%d %db used=%d score=%.1f]",
                    label, generation, bytes.length, timesUsed, interestScore);
        }
    }
}
