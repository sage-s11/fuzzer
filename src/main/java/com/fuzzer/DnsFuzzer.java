package com.fuzzer;

import com.fuzzer.corpus.CorpusManager;
import com.fuzzer.crash.CrashClassifier;
import com.fuzzer.crash.CrashDetector;
import com.fuzzer.dns.DnsHeader;
import com.fuzzer.dns.DnsMessage;
import com.fuzzer.fsm.DnsStateMachine;
import com.fuzzer.fsm.StateMachine;
import com.fuzzer.fsm.StateTransition;
import com.fuzzer.harness.UdpHarness;
import com.fuzzer.mutator.MutationEngine;
import com.fuzzer.mutator.MutationEngine.MutationResult;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;

/**
 * DnsFuzzer — Main Orchestrator
 *
 * Ties together:
 *   FSM → selects what kind of message to send
 *   Corpus → provides seed bytes to mutate from
 *   MutationEngine → applies mutations to seeds
 *   UdpHarness → sends mutated bytes to target
 *   CrashDetector → records anomalies
 *
 * Run modes:
 *   ROUND_ROBIN  — cycle through all mutators evenly
 *   RANDOM       — pick mutators randomly
 *   STACKED      — combine multiple mutators per iteration
 */
public class DnsFuzzer {

    public enum RunMode { ROUND_ROBIN, RANDOM, STACKED, ISOLATED }

    // Configuration
    private final String targetHost;
    private final int targetPort;
    private final String targetDomain;
    private final String crashOutputDir;
    private final int timeoutMs;
    private final long maxIterations;
    private final RunMode mode;
    private final String isolatedMutator; // non-null when mode=ISOLATED

    // Components
    private UdpHarness harness;
    private MutationEngine mutator;
    private CrashDetector crashDetector;
    private CorpusManager corpus;
    private StateMachine fsm;

    // Stats
    private long totalSent    = 0;
    private long totalCrashes = 0;
    private long totalTimeouts = 0;
    private long totalErrors  = 0;
    private Instant startTime;

    public DnsFuzzer(Builder b) {
        this.targetHost      = b.targetHost;
        this.targetPort      = b.targetPort;
        this.targetDomain    = b.targetDomain;
        this.crashOutputDir  = b.crashOutputDir;
        this.timeoutMs       = b.timeoutMs;
        this.maxIterations   = b.maxIterations;
        this.mode            = b.mode;
        this.isolatedMutator = b.isolatedMutator;
    }

    public void init() throws IOException {
        System.out.println("[FUZZER] Initializing DNS Fuzzer...");
        harness       = new UdpHarness(targetHost, targetPort, timeoutMs);
        mutator       = new MutationEngine();
        crashDetector = new CrashDetector(crashOutputDir);
        corpus        = new CorpusManager();
        fsm           = DnsStateMachine.build();

        corpus.loadDefaultDnsSeeds(targetDomain);

        // If isolated mode, restrict engine to only the named mutator
        if (mode == RunMode.ISOLATED && isolatedMutator != null) {
            mutator.isolate(isolatedMutator);
        }

        System.out.printf("[FUZZER] Target     : %s:%d%n", targetHost, targetPort);
        System.out.printf("[FUZZER] Domain     : %s%n", targetDomain);
        System.out.printf("[FUZZER] Mode       : %s%n", mode);
        if (mode == RunMode.ISOLATED) {
            System.out.printf("[FUZZER] Isolated   : %s%n",
                    isolatedMutator != null ? isolatedMutator : "NONE — all mutators active");
        }
        System.out.printf("[FUZZER] Max iters  : %d%n", maxIterations);
        System.out.printf("[FUZZER] Timeout    : %dms%n", timeoutMs);
        System.out.printf("[FUZZER] Mutators   : %d%n", mutator.getMutatorCount());
        System.out.printf("[FUZZER] Seeds      : %d%n", corpus.size());
        System.out.printf("[FUZZER] Crash dir  : %s%n", crashOutputDir);
    }

    public void run() throws IOException {
        // --- Warm-up: verify target is alive ---
        System.out.println("\n[FUZZER] Running liveness probe...");
        byte[] warmupQuery = DnsMessage.standardQuery(0xBEEF, targetDomain).toBytes();
        UdpHarness.SendResult probe = harness.send(warmupQuery);

        if (!probe.hasResponse()) {
            System.out.printf("[FUZZER] ABORT: Target %s:%d is not responding. " +
                    "Is BIND9 running? (status: %s)%n", targetHost, targetPort, probe.status);
            return;
        }
        System.out.printf("[FUZZER] Target alive — RTT: %dms%n", probe.rttMs);

        // --- Main fuzz loop ---
        startTime = Instant.now();
        System.out.printf("%n[FUZZER] Starting fuzz loop — %d iterations%n%n", maxIterations);
        printHeader();

        for (long i = 0; i < maxIterations; i++) {
            // Pick a seed
            CorpusManager.SeedEntry seed = corpus.getRandom();
            seed.timesUsed++;

            // Apply mutation
            MutationResult mutation = switch (mode) {
                case ROUND_ROBIN -> mutator.mutateRoundRobin(seed.bytes);
                case RANDOM      -> mutator.mutateRandom(seed.bytes);
                case STACKED     -> mutator.mutateStacked(seed.bytes, 3);
                case ISOLATED    -> mutator.mutateRoundRobin(seed.bytes); // engine already isolated
            };

            // Send to target
            UdpHarness.SendResult result;
            try {
                result = harness.send(mutation.bytes);
            } catch (IOException e) {
                result = new UdpHarness.SendResult(
                        UdpHarness.SendResult.Status.PORT_UNREACHABLE, null, 0);
            }

            totalSent++;

            // Evaluate result
            if (result.isCrash()) {
                totalCrashes++;
                CrashDetector.CrashRecord cr = crashDetector.reportHardCrash(
                        mutation.bytes, mutation.mutatorName, i);
                printCrash(i, seed.label, mutation.mutatorName, cr);

                // Wait for target to restart, then re-probe
                System.out.println("[FUZZER] Waiting for target recovery...");
                waitForRecovery(warmupQuery);

            } else if (result.isTimeout()) {
                totalTimeouts++;
                CrashDetector.CrashRecord cr = crashDetector.reportTimeout(
                        mutation.bytes, mutation.mutatorName, i);
                if (cr != null) {
                    printCrash(i, seed.label, mutation.mutatorName, cr);
                }

            } else if (result.hasResponse()) {
                crashDetector.resetTimeoutCounter();
                // Check for error RCODEs
                DnsHeader respHeader = DnsMessage.parseResponseHeader(result.responseBytes);
                if (respHeader.rcode == 2) { // SERVFAIL = rcode 2
                    totalErrors++;
                    crashDetector.reportRcodeAnomaly(
                            mutation.bytes, result.responseBytes,
                            mutation.mutatorName, i, respHeader.rcode);
                }
            }

            // Progress report every 500 iterations
            if (i > 0 && i % 500 == 0) {
                printProgress(i);
            }
        }

        printSummary();
        printTriageReport();
        harness.close();
    }

    private void printTriageReport() {
        if (crashDetector.getCrashCount() == 0) return;
        System.out.println("\n" + crashDetector.triage().toReport());
    }

    private void waitForRecovery(byte[] probe) {
        for (int attempt = 0; attempt < 30; attempt++) {
            try {
                Thread.sleep(1000);
                harness.reconnect();
                UdpHarness.SendResult r = harness.send(probe);
                if (r.hasResponse()) {
                    System.out.println("[FUZZER] Target recovered — resuming");
                    return;
                }
            } catch (Exception ignored) {}
        }
        System.out.println("[FUZZER] Target did not recover after 30s — continuing anyway");
    }

    private void printHeader() {
        System.out.printf("%-8s %-20s %-25s %-15s %-8s%n",
                "ITER", "SEED", "MUTATOR", "STATUS", "CRASHES");
        System.out.println("-".repeat(80));
    }

    private void printCrash(long iter, String seed, String mutatorName, CrashDetector.CrashRecord cr) {
        boolean expected = cr.classification != null && cr.classification.isExpected();
        if (expected) {
            // Expected drops: dimmed row, no <<< CRASH label
            System.out.printf("%-8d %-20s %-25s %-15s%n",
                    iter, seed, mutatorName, cr.type.name());
        } else {
            totalCrashes++;
            System.out.printf("%-8d %-20s %-25s %-15s %-8d  <<< CRASH%n",
                    iter, seed, mutatorName, cr.type.name(), totalCrashes);
        }
    }

    private void printProgress(long iter) {
        Duration elapsed = Duration.between(startTime, Instant.now());
        double rate = (double) totalSent / Math.max(1, elapsed.toSeconds());
        System.out.printf("%n[PROGRESS] iter=%-8d sent=%-8d crashes=%-4d timeouts=%-4d " +
                "servfails=%-4d rate=%.0f/s elapsed=%ds%n%n",
                iter, totalSent, totalCrashes, totalTimeouts,
                totalErrors, rate, elapsed.toSeconds());
        printHeader();
    }

    private void printSummary() {
        Duration elapsed = Duration.between(startTime, Instant.now());
        long realSoftCrashes = crashDetector.getCrashes().stream()
                .filter(c -> c.type == CrashDetector.CrashRecord.CrashType.SOFT_CRASH_TIMEOUT)
                .filter(c -> c.classification == null || !c.classification.isExpected())
                .count();
        long expectedDrops = crashDetector.getCrashes().stream()
                .filter(c -> c.classification != null && c.classification.isExpected())
                .count();

        System.out.println("\n" + "=".repeat(60));
        System.out.println("  FUZZING COMPLETE");
        System.out.println("=".repeat(60));
        System.out.printf("  Total iterations  : %d%n", totalSent);
        System.out.printf("  Hard crashes      : %d%n", totalCrashes);
        System.out.printf("  Soft crashes      : %d%n", realSoftCrashes);
        System.out.printf("  Expected drops    : %d  (RFC-compliant, not bugs)%n", expectedDrops);
        System.out.printf("  RCODE anomalies   : %d%n", totalErrors);
        System.out.printf("  Total timeouts    : %d%n", totalTimeouts);
        System.out.printf("  Actionable findings: %d%n",
                crashDetector.triage().getActionable().size());
        System.out.printf("  Elapsed time      : %ds%n", elapsed.toSeconds());
        System.out.printf("  Rate              : %.0f msg/s%n",
                (double) totalSent / Math.max(1, elapsed.toSeconds()));
        System.out.printf("  Crash output dir  : %s%n", crashOutputDir);
        System.out.println("=".repeat(60));
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------
    public static class Builder {
        String targetHost     = "127.0.0.1";
        int    targetPort     = 53;
        String targetDomain   = "example.com";
        String crashOutputDir = "crashes";
        int    timeoutMs      = 2000;
        long   maxIterations  = 10_000;
        RunMode mode          = RunMode.ROUND_ROBIN;
        String isolatedMutator = null;

        public Builder target(String host, int port)    { this.targetHost = host; this.targetPort = port; return this; }
        public Builder domain(String domain)             { this.targetDomain = domain; return this; }
        public Builder crashDir(String dir)              { this.crashOutputDir = dir; return this; }
        public Builder timeout(int ms)                   { this.timeoutMs = ms; return this; }
        public Builder iterations(long n)                { this.maxIterations = n; return this; }
        public Builder mode(RunMode mode)                { this.mode = mode; return this; }
        public Builder isolate(String mutatorName)       { this.isolatedMutator = mutatorName; this.mode = RunMode.ISOLATED; return this; }
        public DnsFuzzer build()                         { return new DnsFuzzer(this); }
    }
}
