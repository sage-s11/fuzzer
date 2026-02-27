package com.fuzzer.crash;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.HexFormat;

/**
 * CrashDetector
 *
 * Detects and records crash events.
 *
 * A "crash" in DNS fuzzing can be:
 *   - HARD CRASH   : Port unreachable (ICMP) — server process terminated
 *   - SOFT CRASH   : Consistent timeout after input (server hung/wedged)
 *   - RCODE ANOMALY: Server returned an unexpected RCODE for the input type
 *
 * All crashes are saved to disk with:
 *   - The exact bytes that triggered the crash
 *   - The mutator that produced them
 *   - Timestamp, iteration number, crash type
 *   - Hex dump for quick inspection
 *   - Classifier verdict (auto-triaged at record time)
 */
public class CrashDetector {

    private final Path outputDir;
    private final List<CrashRecord> crashes = new ArrayList<>();
    private final CrashClassifier classifier = new CrashClassifier();
    private int consecutiveTimeouts = 0;

    // How many consecutive timeouts before we declare a soft crash
    private static final int TIMEOUT_THRESHOLD = 3;

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS").withZone(ZoneId.systemDefault());

    public CrashDetector(String outputDir) throws IOException {
        this.outputDir = Paths.get(outputDir);
        Files.createDirectories(this.outputDir);
    }

    /**
     * Report a hard crash (connection refused / port unreachable).
     */
    public CrashRecord reportHardCrash(byte[] trigger, String mutatorName, long iteration) {
        CrashRecord record = new CrashRecord(
                CrashRecord.CrashType.HARD_CRASH, trigger, mutatorName, iteration);
        crashes.add(record);
        saveToDisk(record);
        consecutiveTimeouts = 0;
        return record;
    }

    /**
     * Report a timeout. If threshold exceeded, treated as soft crash.
     */
    public CrashRecord reportTimeout(byte[] trigger, String mutatorName, long iteration) {
        consecutiveTimeouts++;
        if (consecutiveTimeouts >= TIMEOUT_THRESHOLD) {
            CrashRecord record = new CrashRecord(
                    CrashRecord.CrashType.SOFT_CRASH_TIMEOUT, trigger, mutatorName, iteration);
            crashes.add(record);
            saveToDisk(record);
            consecutiveTimeouts = 0;
            return record;
        }
        return null;
    }

    /**
     * Report an unexpected RCODE (e.g., SERVFAIL where NXDOMAIN was expected).
     */
    public CrashRecord reportRcodeAnomaly(byte[] trigger, byte[] response,
                                           String mutatorName, long iteration, int rcode) {
        CrashRecord record = new CrashRecord(
                CrashRecord.CrashType.RCODE_ANOMALY, trigger, mutatorName, iteration);
        record.responseBytes = response;
        record.rcode = rcode;
        crashes.add(record);
        saveToDisk(record);
        return record;
    }

    public void resetTimeoutCounter() { consecutiveTimeouts = 0; }

    public List<CrashRecord> getCrashes() { return Collections.unmodifiableList(crashes); }
    public int getCrashCount()            { return crashes.size(); }

    private void saveToDisk(CrashRecord record) {
        // Auto-triage every finding at record time
        CrashClassifier.ClassificationResult triage = classifier.classify(record);
        record.classification = triage;

        String ts = TS_FMT.format(record.timestamp);
        String filename = String.format("%s_%s_iter%d_%s.bin",
                record.type.name().toLowerCase(),
                triage.verdict.name().toLowerCase(),
                record.iteration, ts);
        Path binPath    = outputDir.resolve(filename);
        Path reportPath = outputDir.resolve(filename.replace(".bin", ".txt"));

        try {
            Files.write(binPath, record.triggerBytes);
            Files.writeString(reportPath, record.toReport());

            // Print line varies by priority — expected drops are dimmed
            if (triage.isExpected()) {
                System.out.printf("[DROP]  %s — %s — iter=%d [%s — expected, not a bug]%n",
                        record.type, record.mutatorName, record.iteration, triage.verdict);
            } else if (triage.priority == CrashClassifier.Priority.CRITICAL) {
                System.out.printf("[!!!]   %s — %s — iter=%d [%s/%s] ← CRITICAL%n",
                        record.type, record.mutatorName, record.iteration,
                        triage.priority, triage.verdict);
            } else {
                System.out.printf("[CRASH] %s — %s — iter=%d [%s/%s] — saved to %s%n",
                        record.type, record.mutatorName, record.iteration,
                        triage.priority, triage.verdict, binPath.getFileName());
            }
        } catch (IOException e) {
            System.err.println("[CRASH DETECTOR] Failed to write crash: " + e.getMessage());
        }
    }

    /**
     * Run full triage on all collected crashes and return a structured report.
     * Call this at the end of a fuzz run for a clean summary.
     */
    public CrashClassifier.TriageReport triage() {
        return classifier.triageAll(crashes);
    }

    public CrashClassifier getClassifier() { return classifier; }

    // -------------------------------------------------------------------------
    // Crash Record
    // -------------------------------------------------------------------------
    public static class CrashRecord {
        public enum CrashType { HARD_CRASH, SOFT_CRASH_TIMEOUT, RCODE_ANOMALY }

        public final CrashType type;
        public final byte[] triggerBytes;
        public final String mutatorName;
        public final long iteration;
        public final Instant timestamp;
        public byte[] responseBytes;
        public int rcode = -1;
        public CrashClassifier.ClassificationResult classification; // set after triage

        public CrashRecord(CrashType type, byte[] triggerBytes, String mutatorName, long iteration) {
            this.type         = type;
            this.triggerBytes = triggerBytes;
            this.mutatorName  = mutatorName;
            this.iteration    = iteration;
            this.timestamp    = Instant.now();
        }

        public String toReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== CRASH REPORT ===\n");
            sb.append("Type      : ").append(type).append("\n");
            sb.append("Timestamp : ").append(timestamp).append("\n");
            sb.append("Iteration : ").append(iteration).append("\n");
            sb.append("Mutator   : ").append(mutatorName).append("\n");
            if (rcode >= 0) sb.append("RCODE     : ").append(rcode).append("\n");
            if (classification != null) {
                sb.append("\n--- TRIAGE ---\n");
                sb.append("Verdict   : ").append(classification.verdict).append("\n");
                sb.append("Priority  : ").append(classification.priority).append("\n");
                sb.append("Reasoning : ").append(classification.reasoning).append("\n");
                sb.append("Actionable: ").append(classification.isActionable()).append("\n");
            }
            sb.append("\n--- PAYLOAD ---\n");
            sb.append("Size      : ").append(triggerBytes.length).append(" bytes\n");
            sb.append("Hex Dump  :\n").append(hexDump(triggerBytes)).append("\n");
            if (responseBytes != null) {
                sb.append("Response  : ").append(responseBytes.length).append(" bytes\n");
                sb.append(hexDump(responseBytes)).append("\n");
            }
            return sb.toString();
        }

        private String hexDump(byte[] data) {
            StringBuilder sb = new StringBuilder();
            HexFormat hex = HexFormat.of().withUpperCase();
            for (int i = 0; i < data.length; i += 16) {
                sb.append(String.format("%04X  ", i));
                int end = Math.min(i + 16, data.length);
                for (int j = i; j < end; j++) {
                    sb.append(hex.toHexDigits(data[j])).append(' ');
                }
                // Padding
                for (int j = end; j < i + 16; j++) sb.append("   ");
                sb.append(" |");
                for (int j = i; j < end; j++) {
                    char c = (char)(data[j] & 0xFF);
                    sb.append(Character.isISOControl(c) ? '.' : c);
                }
                sb.append("|\n");
            }
            return sb.toString();
        }
    }
}
