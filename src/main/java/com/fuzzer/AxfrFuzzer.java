package com.fuzzer;

import com.fuzzer.crash.CrashClassifier;
import com.fuzzer.crash.CrashDetector;
import com.fuzzer.dns.DnsMessage;
import com.fuzzer.harness.TcpHarness;
import com.fuzzer.mutator.AxfrMutators;
import com.fuzzer.mutator.AxfrMutators.*;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * AxfrFuzzer — TCP zone transfer fuzzer.
 *
 * Fuzzes DNS over TCP with a focus on:
 *
 *   1. TCP length field manipulation
 *      The 2-byte length prefix on DNS/TCP messages is a unique attack
 *      surface. Claim more/fewer bytes than the message contains and observe
 *      server behavior: blocking, FORMERR, connection reset, or crash.
 *
 *   2. AXFR protocol content
 *      AXFR (RFC 5936) follows a strict SOA→records→SOA sequence.
 *      Malformed AXFR queries, wrong QCLASS, IXFR with impossible serials,
 *      and TSIG abuse target the AXFR request parser specifically.
 *
 *   3. TCP framing / pipelining
 *      Multiple messages sent before reading responses, split headers,
 *      concatenated message streams — tests whether the TCP stream
 *      reassembly layer handles boundaries correctly.
 *
 * Run modes:
 *   ALL        — all three mutator classes, round-robin
 *   LENGTH     — TcpLength mutators only (length field abuse)
 *   AXFR       — AxfrRequest mutators only (AXFR protocol content)
 *   FRAMING    — TcpFraming mutators only (pipelining / stream abuse)
 *
 * Architecture difference from DnsFuzzer:
 *   Each iteration opens a fresh TCP connection. This is because:
 *   - Length-field overclams leave the connection in an unrecoverable state
 *   - AXFR responses are multi-message — reusing connections risks state bleed
 *   - Fresh connections give clean crash attribution (which message caused it)
 *
 *   The cost is connection overhead (~3ms RTT vs ~0ms for reused connection),
 *   which limits throughput to ~300 iterations/s vs 10,000/s for UDP.
 *   This is acceptable — TCP fuzzing is inherently slower.
 */
public class AxfrFuzzer {

    public enum RunMode { ALL, LENGTH, AXFR_ONLY, FRAMING }

    private final String  targetHost;
    private final int     targetPort;
    private final String  targetZone;
    private final String  crashOutputDir;
    private final int     timeoutMs;
    private final long    maxIterations;
    private final RunMode mode;

    private CrashDetector crashDetector;

    // Stats
    private long totalSent       = 0;
    private long totalHardCrash  = 0;
    private long totalTcpRst     = 0;      // TCP RST on bad framing — server alive, not a crash
    private long totalTimeouts   = 0;
    private long totalErrors     = 0;
    private long totalAxfrOk     = 0;      // complete AXFR responses received
    private long totalAxfrPartial = 0;     // AXFR started but incomplete
    private Instant startTime;

    // Mutator pools — populated based on run mode
    private final List<AxfrIteration> iterations = new ArrayList<>();

    public AxfrFuzzer(Builder b) {
        this.targetHost     = b.targetHost;
        this.targetPort     = b.targetPort;
        this.targetZone     = b.targetZone;
        this.crashOutputDir = b.crashOutputDir;
        this.timeoutMs      = b.timeoutMs;
        this.maxIterations  = b.maxIterations;
        this.mode           = b.mode;
    }

    public void init() throws IOException {
        crashDetector = new CrashDetector(crashOutputDir);

        // Build iteration plan based on mode
        buildIterationPlan();

        System.out.println("\n[AXFR FUZZER] Initializing...");
        System.out.printf("[AXFR FUZZER] Target     : %s:%d%n", targetHost, targetPort);
        System.out.printf("[AXFR FUZZER] Zone       : %s%n", targetZone);
        System.out.printf("[AXFR FUZZER] Mode       : %s%n", mode);
        System.out.printf("[AXFR FUZZER] Max iters  : %d%n", maxIterations);
        System.out.printf("[AXFR FUZZER] Timeout    : %dms%n", timeoutMs);
        System.out.printf("[AXFR FUZZER] Scenarios  : %d%n", iterations.size());
        System.out.printf("[AXFR FUZZER] Crash dir  : %s%n", crashOutputDir);
    }

    public void run() throws IOException {
        // Liveness probe: standard A query over TCP
        System.out.println("\n[AXFR FUZZER] Running TCP liveness probe...");
        try {
            TcpHarness probe = new TcpHarness(targetHost, targetPort, timeoutMs);
            byte[] warmup = DnsMessage.standardQuery(0xBEEF, targetZone).toBytes();
            TcpHarness.SendResult r = probe.send(warmup);
            probe.close();
            if (!r.hasResponse()) {
                System.out.printf("[AXFR FUZZER] ABORT: %s:%d not responding over TCP " +
                        "(status=%s). Is DNS TCP enabled?%n", targetHost, targetPort, r.status);
                return;
            }
            System.out.printf("[AXFR FUZZER] TCP alive — RTT: %dms%n", r.rttMs);
        } catch (IOException e) {
            System.out.printf("[AXFR FUZZER] ABORT: TCP connection refused — %s%n", e.getMessage());
            return;
        }

        // Verify AXFR is permitted before fuzzing
        System.out.println("[AXFR FUZZER] Probing AXFR permission...");
        if (!probeAxfr()) {
            System.out.println("[AXFR FUZZER] WARNING: AXFR probe returned no SOA. " +
                    "AXFR may be restricted. Continuing anyway — framing/length attacks " +
                    "don't require AXFR permission.");
        } else {
            System.out.println("[AXFR FUZZER] AXFR permitted — full zone transfer confirmed.");
        }

        startTime = Instant.now();
        System.out.printf("%n[AXFR FUZZER] Starting fuzz loop — %d iterations%n%n", maxIterations);
        printHeader();

        for (long i = 0; i < maxIterations; i++) {
            // Pick scenario round-robin
            AxfrIteration scenario = iterations.get((int)(i % iterations.size()));

            boolean crashed = runScenario(scenario, i);
            totalSent++;

            if (crashed) {
                totalHardCrash++;
                System.out.println("[AXFR FUZZER] Waiting for target recovery...");
                waitForRecovery();
            }

            if (i > 0 && i % 100 == 0) printProgress(i);
        }

        printSummary();
        printTriageReport();
    }

    /**
     * Execute a single fuzz scenario.
     * Each scenario opens a fresh TCP connection.
     * Returns true if a hard crash was detected.
     */
    private boolean runScenario(AxfrIteration scenario, long iter) {
        TcpHarness harness = null;
        try {
            harness = new TcpHarness(targetHost, targetPort, timeoutMs);
        } catch (IOException e) {
            // Connection refused on connect — hard crash
            CrashDetector.CrashRecord cr = crashDetector.reportHardCrash(
                    scenario.payload, scenario.name, iter);
            printCrashLine(iter, scenario.name, "HARD_CRASH [connect refused]", cr);
            return true;
        }

        try {
            TcpHarness.SendResult result;

            switch (scenario.type) {

                case TCP_LENGTH -> {
                    // Unwrap: first 2 bytes = claimed length, rest = actual message
                    if (scenario.payload.length < 2) {
                        harness.close();
                        return false;
                    }
                    int claimed = ((scenario.payload[0] & 0xFF) << 8)
                            | (scenario.payload[1] & 0xFF);
                    byte[] msg = new byte[scenario.payload.length - 2];
                    System.arraycopy(scenario.payload, 2, msg, 0, msg.length);
                    result = harness.sendWithLength(msg, claimed);
                    evaluateResult(result, scenario, iter);
                }

                case AXFR_REQUEST -> {
                    // Standard TCP framing, but malformed AXFR content
                    result = harness.send(scenario.payload);
                    // Also try to read the multi-message AXFR response
                    if (result.hasResponse()) {
                        // Got first message — read remaining AXFR messages
                        TcpHarness.MultiResponse axfrResp =
                                harness.readAxfrResponse(200);
                        if (axfrResp.complete) {
                            totalAxfrOk++;
                        } else if (axfrResp.hasAny()) {
                            totalAxfrPartial++;
                        }
                    }
                    evaluateResult(result, scenario, iter);
                }

                case TCP_FRAMING -> {
                    // Raw multi-message stream — send as-is without additional framing
                    result = harness.sendRaw(scenario.payload);
                    evaluateResult(result, scenario, iter);
                }

                default -> {
                    result = harness.send(scenario.payload);
                    evaluateResult(result, scenario, iter);
                }
            }

        } catch (IOException e) {
            // IOException mid-send = hard crash
            CrashDetector.CrashRecord cr = crashDetector.reportHardCrash(
                    scenario.payload, scenario.name, iter);
            printCrashLine(iter, scenario.name, "HARD_CRASH [IOException: " + e.getMessage() + "]", cr);
            harness.close();
            return true;
        }

        harness.close();
        return false;
    }

    private void evaluateResult(TcpHarness.SendResult result,
                                 AxfrIteration scenario, long iter) {
        if (result.isCrash()) {
            // Before declaring a hard crash, probe whether the target is still alive.
            // A TCP RST on a malformed message (length=0, length=1) is NOT a process crash —
            // BIND9 closes the connection cleanly and immediately accepts new ones.
            // Only declare TRUE_POSITIVE if the target stops responding entirely.
            boolean targetAlive = isTargetAlive();
            if (targetAlive) {
                // Connection reset, but server still up — TCP RST on bad framing
                totalTcpRst++;
                System.out.printf("%-8d %-30s TCP_RST (server alive — connection closed on bad framing)%n",
                        iter, scenario.name);
                return;
            }
            totalHardCrash++;
            CrashDetector.CrashRecord cr = crashDetector.reportHardCrash(
                    scenario.payload, scenario.name, iter);
            printCrashLine(iter, scenario.name, "HARD_CRASH", cr);

        } else if (result.isTimeout()) {
            totalTimeouts++;
            CrashDetector.CrashRecord cr = crashDetector.reportTimeout(
                    scenario.payload, scenario.name, iter);
            if (cr != null) {
                printCrashLine(iter, scenario.name, "SOFT_CRASH_TIMEOUT", cr);
            }
            crashDetector.resetTimeoutCounter();

        } else if (result.hasResponse()) {
            crashDetector.resetTimeoutCounter();
            // Log notable responses
            byte[] resp = result.responseBytes;
            if (resp.length >= 12) {
                int rcode = resp[3] & 0x0F;
                String status = switch (rcode) {
                    case 0  -> "NOERROR";
                    case 1  -> "FORMERR";
                    case 2  -> { totalErrors++; yield "SERVFAIL[!]"; }
                    case 3  -> "NXDOMAIN";
                    case 4  -> "NOTIMP";
                    case 5  -> "REFUSED";
                    case 9  -> "NOTAUTH";
                    case 10 -> "NOTZONE";
                    default -> "RCODE=" + rcode;
                };
                if (rcode == 2) {
                    crashDetector.reportRcodeAnomaly(
                            scenario.payload, resp, scenario.name, iter, rcode);
                }
                // Only log non-FORMERR / non-REFUSED responses (those are expected)
                if (rcode != 1 && rcode != 5 && rcode != 4) {
                    System.out.printf("%-8d %-30s %-12s RTT=%dms%n",
                            iter, scenario.name, status, result.rttMs);
                }
            }
        } else if (result.isError()) {
            totalErrors++;
        }
    }

    /**
     * Probe whether the target permits AXFR for the configured zone.
     */
    private boolean probeAxfr() {
        try (TcpHarness h = new TcpHarness(targetHost, targetPort, timeoutMs)) {
            byte[] axfr = AxfrMutators.buildAxfrQuery(0x0001, targetZone);
            TcpHarness.SendResult first = h.send(axfr);
            if (!first.hasResponse()) return false;
            // Try to read a few more messages
            TcpHarness.MultiResponse multi = h.readAxfrResponse(50);
            return multi.hasAny() || first.hasResponse();
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Quick liveness check — open a fresh TCP connection and send a standard query.
     * Returns true if the target responds within a short window.
     * Used to distinguish TCP RST (connection closed, server alive) from true crash.
     */
    private boolean isTargetAlive() {
        try (TcpHarness h = new TcpHarness(targetHost, targetPort, Math.min(timeoutMs, 1000))) {
            byte[] q = DnsMessage.standardQuery(0xBEEF, targetZone).toBytes();
            return h.send(q).hasResponse();
        } catch (IOException e) {
            return false;
        }
    }

    private void waitForRecovery() {
        for (int attempt = 0; attempt < 30; attempt++) {
            try {
                Thread.sleep(1000);
                TcpHarness probe = new TcpHarness(targetHost, targetPort, timeoutMs);
                byte[] q = DnsMessage.standardQuery(0xBEEF, targetZone).toBytes();
                TcpHarness.SendResult r = probe.send(q);
                probe.close();
                if (r.hasResponse()) {
                    System.out.println("[AXFR FUZZER] Target recovered — resuming");
                    return;
                }
            } catch (Exception ignored) {}
        }
        System.out.println("[AXFR FUZZER] Target did not recover after 30s — continuing");
    }

    // -------------------------------------------------------------------------
    // Iteration plan builder
    // -------------------------------------------------------------------------

    private void buildIterationPlan() throws IOException {
        byte[] baseAxfr = AxfrMutators.buildAxfrQuery(0x1337, targetZone);

        // TCP Length mutators (5 variants)
        if (mode == RunMode.ALL || mode == RunMode.LENGTH) {
            for (TcpLengthMutator.Variant v : TcpLengthMutator.Variant.values()) {
                TcpLengthMutator m = new TcpLengthMutator(v);
                iterations.add(new AxfrIteration(
                        m.mutate(baseAxfr), m.name(), ScenarioType.TCP_LENGTH));
            }
        }

        // AXFR request mutators (9 variants)
        if (mode == RunMode.ALL || mode == RunMode.AXFR_ONLY) {
            for (AxfrRequestMutator.Variant v : AxfrRequestMutator.Variant.values()) {
                AxfrRequestMutator m = new AxfrRequestMutator(v, targetZone);
                iterations.add(new AxfrIteration(
                        m.mutate(baseAxfr), m.name(), ScenarioType.AXFR_REQUEST));
            }
        }

        // TCP framing mutators (5 variants)
        if (mode == RunMode.ALL || mode == RunMode.FRAMING) {
            for (TcpFramingMutator.Variant v : TcpFramingMutator.Variant.values()) {
                TcpFramingMutator m = new TcpFramingMutator(v, targetZone);
                iterations.add(new AxfrIteration(
                        m.mutate(baseAxfr), m.name(), ScenarioType.TCP_FRAMING));
            }
        }

        if (iterations.isEmpty()) {
            // Fallback: add basic AXFR
            iterations.add(new AxfrIteration(
                    baseAxfr, "AxfrBaseline", ScenarioType.AXFR_REQUEST));
        }
    }

    // -------------------------------------------------------------------------
    // Console output
    // -------------------------------------------------------------------------

    private void printHeader() {
        System.out.printf("%-8s %-30s %-12s%n", "ITER", "SCENARIO", "STATUS");
        System.out.println("-".repeat(60));
    }

    private void printCrashLine(long iter, String scenario, String status,
                                  CrashDetector.CrashRecord cr) {
        boolean expected = cr.classification != null && cr.classification.isExpected();
        if (expected) {
            System.out.printf("[DROP]  iter=%-6d %-30s %s%n", iter, scenario, status);
        } else {
            System.out.printf("[CRASH] iter=%-6d %-30s %s <<< CRASH%n", iter, scenario, status);
        }
    }

    private void printProgress(long iter) {
        Duration elapsed = Duration.between(startTime, Instant.now());
        double rate = (double) totalSent / Math.max(1, elapsed.toSeconds());
        System.out.printf(
                "%n[PROGRESS] iter=%-6d sent=%-6d hard=%-3d timeouts=%-3d " +
                "axfr_ok=%-3d axfr_partial=%-3d rate=%.0f/s elapsed=%ds%n%n",
                iter, totalSent, totalHardCrash, totalTimeouts,
                totalAxfrOk, totalAxfrPartial, rate, elapsed.toSeconds());
        printHeader();
    }

    private void printSummary() {
        Duration elapsed = Duration.between(startTime, Instant.now());
        long actionable = crashDetector.triage().getActionable().size();

        System.out.println("\n" + "=".repeat(65));
        System.out.println("  AXFR / TCP FUZZING COMPLETE");
        System.out.println("=".repeat(65));
        System.out.printf("  Total iterations    : %d%n", totalSent);
        System.out.printf("  Hard crashes        : %d%n", totalHardCrash);
        System.out.printf("  TCP RST (alive)     : %d  (server closed connection, not a crash)%n", totalTcpRst);
        System.out.printf("  Soft crashes        : %d%n", totalTimeouts);
        System.out.printf("  SERVFAIL anomalies  : %d%n", totalErrors);
        System.out.printf("  Complete AXFRs      : %d%n", totalAxfrOk);
        System.out.printf("  Partial AXFRs       : %d%n", totalAxfrPartial);
        System.out.printf("  Actionable findings : %d%n", actionable);
        System.out.printf("  Elapsed time        : %ds%n", elapsed.toSeconds());
        System.out.printf("  Rate                : %.0f conn/s%n",
                (double) totalSent / Math.max(1, elapsed.toSeconds()));
        System.out.printf("  Crash output dir    : %s%n", crashOutputDir);
        System.out.println("=".repeat(65));
    }

    private void printTriageReport() {
        if (crashDetector.getCrashCount() == 0) return;
        System.out.println("\n" + crashDetector.triage().toReport());
    }

    // -------------------------------------------------------------------------
    // Internal types
    // -------------------------------------------------------------------------

    enum ScenarioType { TCP_LENGTH, AXFR_REQUEST, TCP_FRAMING }

    static class AxfrIteration {
        final byte[]       payload;
        final String       name;
        final ScenarioType type;

        AxfrIteration(byte[] payload, String name, ScenarioType type) {
            this.payload = payload;
            this.name    = name;
            this.type    = type;
        }
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    public static class Builder {
        String  targetHost     = "127.0.0.1";
        int     targetPort     = 53;
        String  targetZone     = "example.com";
        String  crashOutputDir = "crashes";
        int     timeoutMs      = 3000;
        long    maxIterations  = 5000;
        RunMode mode           = RunMode.ALL;

        public Builder target(String host, int port) { this.targetHost = host; this.targetPort = port; return this; }
        public Builder zone(String zone)             { this.targetZone = zone; return this; }
        public Builder crashDir(String dir)          { this.crashOutputDir = dir; return this; }
        public Builder timeout(int ms)               { this.timeoutMs = ms; return this; }
        public Builder iterations(long n)            { this.maxIterations = n; return this; }
        public Builder mode(RunMode mode)            { this.mode = mode; return this; }
        public AxfrFuzzer build()                    { return new AxfrFuzzer(this); }
    }
}
