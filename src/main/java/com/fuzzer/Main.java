package com.fuzzer;

/**
 * Main entry point for the DNS Protocol Fuzzer.
 *
 * UDP mode (default):
 *   java -jar fuzzer.jar [options]
 *
 * TCP/AXFR mode:
 *   java -jar fuzzer.jar --tcp [options]
 *
 * Options (UDP):
 *   --host <ip>           Target DNS server IP (default: 127.0.0.1)
 *   --port <port>         Target DNS server port (default: 53)
 *   --domain <domain>     Domain to fuzz queries against (default: example.com)
 *   --crashes <dir>       Directory to save crash files (default: ./crashes)
 *   --timeout <ms>        Response timeout in milliseconds (default: 2000)
 *   --iterations <n>      Number of fuzz iterations (default: 10000)
 *   --mode <mode>         Mutation mode: ROUND_ROBIN | RANDOM | STACKED (default: ROUND_ROBIN)
 *   --isolate <mutator>   Run only the named mutator (substring match)
 *
 * Options (TCP/AXFR — requires --tcp):
 *   --tcp                 Enable TCP mode (routes to AxfrFuzzer)
 *   --zone <zone>         Zone to request AXFR for (default: example.com)
 *   --axfr-mode <mode>    ALL | LENGTH | AXFR_ONLY | FRAMING (default: ALL)
 *   --port, --host, --crashes, --timeout, --iterations as above
 */
public class Main {

    public static void main(String[] args) throws Exception {
        boolean tcp = false;
        for (String arg : args) {
            if (arg.equals("--tcp")) { tcp = true; break; }
        }

        if (tcp) {
            runAxfrFuzzer(args);
        } else {
            runUdpFuzzer(args);
        }
    }

    private static void runUdpFuzzer(String[] args) throws Exception {
        DnsFuzzer.Builder builder = new DnsFuzzer.Builder();

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

    private static void runAxfrFuzzer(String[] args) throws Exception {
        AxfrFuzzer.Builder builder = new AxfrFuzzer.Builder();

        for (int i = 0; i < args.length; i++) {
            if (i + 1 >= args.length) break;
            switch (args[i]) {
                case "--host"       -> builder.target(args[++i], builder.targetPort);
                case "--port"       -> builder.target(builder.targetHost, Integer.parseInt(args[++i]));
                case "--zone"       -> builder.zone(args[++i]);
                case "--domain"     -> builder.zone(args[++i]);
                case "--crashes"    -> builder.crashDir(args[++i]);
                case "--timeout"    -> builder.timeout(Integer.parseInt(args[++i]));
                case "--iterations" -> builder.iterations(Long.parseLong(args[++i]));
                case "--axfr-mode"  -> builder.mode(AxfrFuzzer.RunMode.valueOf(args[++i].toUpperCase()));
                case "--help"       -> { printHelp(); return; }
            }
        }

        printBanner();
        AxfrFuzzer fuzzer = builder.build();
        fuzzer.init();
        fuzzer.run();
    }

    private static void printBanner() {
        System.out.println("""
                ╔══════════════════════════════════════════════╗
                ║    DNS STATEFUL PROTOCOL FUZZER  v1.2        ║
                ║    UDP + TCP/AXFR  •  Semantic Mutators      ║
                ║    Crash Classifier  •  Isolated Mode        ║
                ╚══════════════════════════════════════════════╝
                """);
    }

    private static void printHelp() {
        System.out.println("""
                DNS Protocol Fuzzer v1.2

                Usage: java -jar fuzzer.jar [--tcp] [options]

                UDP mode (default):
                  --host <ip>           Target DNS server IP        (default: 127.0.0.1)
                  --port <port>         Target DNS server port       (default: 53)
                  --domain <domain>     Domain to fuzz against       (default: example.com)
                  --crashes <dir>       Crash output directory       (default: ./crashes)
                  --timeout <ms>        Response timeout ms          (default: 2000)
                  --iterations <n>      Fuzz iteration count         (default: 10000)
                  --mode <mode>         ROUND_ROBIN | RANDOM | STACKED (default: ROUND_ROBIN)
                  --isolate <mutator>   Run only this mutator (substring match)

                TCP/AXFR mode (add --tcp):
                  --tcp                 Enable TCP/AXFR fuzzer
                  --zone <zone>         Zone for AXFR requests       (default: example.com)
                  --axfr-mode <mode>    ALL | LENGTH | AXFR_ONLY | FRAMING (default: ALL)
                  --port, --host, --crashes, --timeout, --iterations as above

                Examples:
                  # Standard UDP fuzz
                  java -jar fuzzer.jar --port 5353 --domain fuzz.local --iterations 10000

                  # TCP/AXFR full sweep
                  java -jar fuzzer.jar --tcp --port 5353 --zone fuzz.local --iterations 5000

                  # TCP length field attacks only
                  java -jar fuzzer.jar --tcp --port 5353 --zone fuzz.local --axfr-mode LENGTH

                  # AXFR protocol mutations only
                  java -jar fuzzer.jar --tcp --port 5353 --zone fuzz.local --axfr-mode AXFR_ONLY

                  # TCP framing / pipelining attacks
                  java -jar fuzzer.jar --tcp --port 5353 --zone fuzz.local --axfr-mode FRAMING
                """);
    }
}
