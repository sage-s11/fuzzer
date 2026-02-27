package com.fuzzer;

/**
 * Main entry point for the DNS Protocol Fuzzer.
 *
 * Usage:
 *   java -jar fuzzer.jar [options]
 *
 * Options:
 *   --host <ip>           Target DNS server IP (default: 127.0.0.1)
 *   --port <port>         Target DNS server port (default: 53)
 *   --domain <domain>     Domain to fuzz queries against (default: example.com)
 *   --crashes <dir>       Directory to save crash files (default: ./crashes)
 *   --timeout <ms>        Response timeout in milliseconds (default: 2000)
 *   --iterations <n>      Number of fuzz iterations (default: 10000)
 *   --mode <mode>         Mutation mode: ROUND_ROBIN | RANDOM | STACKED (default: ROUND_ROBIN)
 *   --isolate <mutator>   Run only the named mutator (substring match, sets mode=ISOLATED)
 *
 * Mutator names (for --isolate):
 *   HeaderFlags, BitFlip, BoundaryValue, QdCountMismatch,
 *   LabelLength, OversizeLabel, NullByteInject, RandomType
 *
 * Examples:
 *   # Full fuzz run against local BIND9
 *   java -jar fuzzer.jar --host 127.0.0.1 --port 5353 --domain fuzz.local --iterations 50000
 *
 *   # Isolate HeaderFlags only — confirm it as root cause
 *   java -jar fuzzer.jar --isolate HeaderFlags --port 5353 --domain fuzz.local --iterations 5000
 *
 *   # Isolate all Label mutators (substring match catches both LabelLength + OversizeLabel)
 *   java -jar fuzzer.jar --isolate label --port 5353 --domain fuzz.local --iterations 5000
 *
 *   # Stacked mutations, custom crash directory
 *   java -jar fuzzer.jar --mode STACKED --crashes /tmp/dns-crashes --iterations 100000
 */
public class Main {

    public static void main(String[] args) throws Exception {
        DnsFuzzer.Builder builder = new DnsFuzzer.Builder();

        // Parse CLI args
        for (int i = 0; i < args.length - 1; i++) {
            switch (args[i]) {
                case "--host"       -> builder.target(args[++i], builder.targetPort);
                case "--port"       -> builder.target(builder.targetHost, Integer.parseInt(args[++i]));
                case "--domain"     -> builder.domain(args[++i]);
                case "--crashes"    -> builder.crashDir(args[++i]);
                case "--timeout"    -> builder.timeout(Integer.parseInt(args[++i]));
                case "--iterations" -> builder.iterations(Long.parseLong(args[++i]));
                case "--mode"       -> builder.mode(DnsFuzzer.RunMode.valueOf(args[++i].toUpperCase()));
                case "--isolate"    -> builder.isolate(args[++i]);
                case "--help"       -> { printHelp(); return; }
            }
        }

        printBanner();

        DnsFuzzer fuzzer = builder.build();
        fuzzer.init();
        fuzzer.run();
    }

    private static void printBanner() {
        System.out.println("""
                ╔══════════════════════════════════════════════╗
                ║    DNS STATEFUL PROTOCOL FUZZER  v1.1        ║
                ║    Stateful DNS Mutation Engine              ║
                ║    + Crash Classifier  + Isolated Mode       ║
                ╚══════════════════════════════════════════════╝
                """);
    }

    private static void printHelp() {
        System.out.println("""
                DNS Protocol Fuzzer v1.1

                Usage: java -jar fuzzer.jar [options]

                Options:
                  --host <ip>           Target DNS server IP        (default: 127.0.0.1)
                  --port <port>         Target DNS server port       (default: 53)
                  --domain <domain>     Domain to fuzz against       (default: example.com)
                  --crashes <dir>       Crash output directory       (default: ./crashes)
                  --timeout <ms>        Response timeout ms          (default: 2000)
                  --iterations <n>      Fuzz iteration count         (default: 10000)
                  --mode <mode>         ROUND_ROBIN | RANDOM | STACKED (default: ROUND_ROBIN)
                  --isolate <mutator>   Run only this mutator (substring match)
                  --help                Show this help

                Mutator names (use with --isolate):
                  HeaderFlags       Corrupt DNS header flag bits
                  BitFlip           Flip random bits (matches BitFlip(1) and BitFlip(4))
                  BoundaryValue     Replace bytes with 0x00/0xFF/0x7F/0x80
                  QdCountMismatch   Set QDCOUNT to impossible values
                  LabelLength       Corrupt label length bytes
                  OversizeLabel     Replace domain with 255-byte label chain
                  NullByteInject    Inject null bytes into question section
                  RandomType        Replace QTYPE with reserved values
                  label             Matches both LabelLength AND OversizeLabel

                Examples:
                  # Standard run
                  java -jar fuzzer.jar --port 5353 --domain fuzz.local --iterations 10000

                  # Confirm HeaderFlags is root cause
                  java -jar fuzzer.jar --isolate HeaderFlags --port 5353 --domain fuzz.local

                  # Deep-dive label encoding edge cases
                  java -jar fuzzer.jar --isolate label --port 5353 --timeout 200 --iterations 20000

                  # Stacked mutations
                  java -jar fuzzer.jar --mode STACKED --port 5353 --timeout 200 --iterations 50000
                """);
    }
}
