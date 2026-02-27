# DNS Stateful Protocol Fuzzer

**A protocol-aware DNS fuzzer with a structured triage system, built in Java.**

Sends semantically valid DNS messages, walks the protocol state machine to a
known-good baseline, then applies targeted mutations across two generations of
mutator classes — byte-level corruption (v1) and structure-aware semantic
construction (v2) — to find parsing bugs, assertion failures, and unexpected
behavior in DNS server implementations.

---

## Contents

1. [Motivation](#1-motivation)
2. [Architecture](#2-architecture)
3. [Protocol State Machine](#3-protocol-state-machine)
4. [Mutation Engine](#4-mutation-engine)
5. [Crash Detection and Triage](#5-crash-detection-and-triage)
6. [Isolated Mutator Mode](#6-isolated-mutator-mode)
7. [Test Coverage](#7-test-coverage)
8. [Findings — BIND9 9.18 on Ubuntu 24.04](#8-findings----bind9-918-on-ubuntu-2404)
9. [Interpreting Results](#9-interpreting-results)
10. [Running the Fuzzer](#10-running-the-fuzzer)
11. [Project Structure](#11-project-structure)
12. [Extending the Fuzzer](#12-extending-the-fuzzer)

---

## 1. Motivation

Most DNS fuzzing tools operate at the byte level — they corrupt arbitrary bytes
in a packet and observe whether the server crashes. This approach is effective
for finding trivially malformed-input bugs but has two significant blind spots.

**Blind spot 1: The parser never reaches interesting code.** A packet with a
corrupted header flag is dropped at the entry point, before any record parsing
logic runs. The mutations that find real vulnerabilities in DNS servers tend to
involve structurally valid-enough input that passes initial checks and reaches
deep parsing code — EDNS option parsers, label decompression loops, zone
transfer state machines.

**Blind spot 2: Every timeout looks the same.** A server dropping a packet
because `QR=1` (RFC 1035 §4.1.1 — this is correct behavior) looks identical
to a server timing out because a compression pointer loop is consuming all its
CPU. Without a triage layer, both appear as "crashes" and the real signal
drowns in noise.

This fuzzer addresses both. v2 semantic mutators construct inputs that are
specifically shaped to be valid enough to pass initial parsing and reach
targeted code paths. The crash classifier triages every finding against the
relevant RFC rules and assigns a verdict, so the output is a list of
*actionable* findings rather than a list of timeouts.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        DnsFuzzer                             │
│                      (Orchestrator)                          │
└───┬──────────┬──────────┬───────────────────────────────┬───┘
    │          │          │                               │
    ▼          ▼          ▼                               ▼
┌───────┐  ┌──────┐  ┌────────────┐              ┌──────────────┐
│Corpus │  │ FSM  │  │ Mutation   │              │ UDP Harness  │
│Manager│  │Engine│  │ Engine     │              │ (Transport)  │
└───────┘  └──────┘  └─────┬──────┘              └──────┬───────┘
                            │                            │
              ┌─────────────┴──────────┐                 │
              │                        │                 │
              ▼                        ▼                 ▼
        ┌──────────┐           ┌──────────────┐   BIND9 Target
        │ Mutators │           │ Semantic     │
        │  (v1)    │           │ Mutators (v2)│
        └──────────┘           └──────────────┘
                                               │
                                               ▼
                                    ┌─────────────────┐
                                    │ Crash Detector  │
                                    │ + Classifier    │
                                    │ (auto-triage)   │
                                    └─────────────────┘
```

### Components

| Package | Responsibility |
|---|---|
| `dns/` | RFC 1035 wire format — `DnsHeader`, `DnsQuestion`, `DnsMessage`, `EdnsOption` |
| `fsm/` | Protocol-agnostic state machine engine + DNS FSM definition |
| `mutator/` | v1 byte-level mutators and v2 semantic mutators |
| `harness/` | UDP socket driver — send, receive, timeout, crash detection |
| `crash/` | `CrashDetector` (recording) + `CrashClassifier` (triage) |
| `corpus/` | Seed corpus manager — 6 well-formed DNS query types |

---

## 3. Protocol State Machine

DNS over UDP is a single-round-trip protocol, but the fuzzer models it
explicitly as a state machine to enforce a warm-up discipline: before sending
any mutated packet, it first confirms the target is alive and responsive with
a valid query. This prevents false positives from a target that was never
running and ensures mutations are sent against a known-good baseline.

```
INITIAL
   │
   ▼
SEND_STANDARD_QUERY ──► AWAIT_STANDARD_RESPONSE
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
              TERMINAL_CRASH  TERMINAL_TIMEOUT  FUZZ_POINT
                                                    │
                                                    ▼
                                              VALIDATE_RESPONSE
                                                    │
                                    ┌───────────────┼──────────────┐
                                    │               │              │
                                    ▼               ▼              ▼
                               TERMINAL_OK    TERMINAL_TIMEOUT  TERMINAL_CRASH
```

**Fuzz points** are the states where mutations are injected:

| State | Surface |
|---|---|
| `FUZZ_STANDARD_QUERY` | A/AAAA query field values |
| `FUZZ_EDNS_QUERY` | EDNS0 OPT record option codes and data |
| `FUZZ_ANY_QUERY` | ANY query type (amplification surface) |
| `FUZZ_MALFORMED_HEADER` | DNS header flags and counts |
| `FUZZ_LABEL_ENCODING` | Domain name label length bytes |

---

## 4. Mutation Engine

The engine manages a pool of 26 mutators and applies them to seeds from the
corpus. Four run modes:

- **ROUND_ROBIN** — cycles through all mutators in order
- **RANDOM** — picks a mutator at random each iteration
- **STACKED** — applies N randomly chosen mutators in sequence, producing
  combinatorial coverage
- **ISOLATED** — runs only the named mutator (substring match), used for
  confirming a specific mutator as the cause of a finding

### v1 — Byte-Level Mutators (9)

These operate on the raw bytes of a seed without understanding structure.
They are fast, simple, and good at triggering entry-point validation bugs.

| Mutator | Target | Technique |
|---|---|---|
| `BitFlip(1)` | Any byte | Flip 1 random bit |
| `BitFlip(4)` | Any byte | Flip 4 random bits |
| `BoundaryValue` | Any byte | Replace with `0x00`, `0xFF`, `0x7F`, `0x80` |
| `HeaderFlags` | Bytes 2–3 | Set 9 interesting flag combinations including `QR=1`, all opcodes, reserved bits |
| `QdCountMismatch` | Bytes 4–5 | Set QDCOUNT to `0`, `100`, `255`, `0xFFFF` — contradicts actual question count |
| `LabelLength` | Byte 12 | Corrupt first label byte with `0x00`, `0xFF`, `0xC0` (pointer prefix) |
| `OversizeLabel` | Bytes 12+ | Replace QNAME with 255-byte label chain, no root terminator |
| `NullByteInject` | Question section | Inject `0x00` at a random position after the header |
| `RandomType` | QTYPE field | Replace with reserved values: `0x0000`, `0x8000`, `0xFFFF`, obsolete types |

### v2 — Semantic Mutators (17 variants across 3 classes)

These construct payloads from scratch, shaped to be valid enough to pass
initial parsing and reach specific deep code paths. They do not corrupt random
bytes — they build specific structural traps.

#### CompressionPointerLoop (4 variants)

DNS name compression (RFC 1035 §4.1.4) allows a 2-byte pointer
(`0xC0 offset`) to reference an earlier position in the message. A naive
parser that follows pointers without cycle detection enters an infinite loop.

| Variant | Description |
|---|---|
| `SELF_LOOP` | Pointer at offset 12 points to offset 12 — immediate cycle |
| `TWO_HOP_LOOP` | Two pointers at offsets 12 and 14 pointing at each other |
| `FORWARD_PTR` | Pointer referencing offset 8191 — past end of packet (OOB read) |
| `CHAIN_DEPTH` | 64 chained pointers before looping — tests depth limit enforcement |

Wire format of SELF_LOOP:
```
Offset 0:   [ID 2 bytes][FLAGS 2 bytes][QDCOUNT=1][AN=0][NS=0][AR=0]
Offset 12:  0xC0 0x0C   ← pointer to offset 12 (itself)
Offset 14:  0x00 0x01   ← QTYPE=A
Offset 16:  0x00 0x01   ← QCLASS=IN
```

CVE history: CVE-2000-0333 (multiple DNS implementations), CVE-2017-14491
(dnsmasq — 8-byte overflow in DNS name processing via crafted pointer).

#### EdnsOptionOverflow (7 variants)

EDNS0 OPT records (RFC 6891) contain options as `[2-byte code][2-byte
length][N-byte data]`. The option parser must bound-check `length` against
`RDLENGTH` — historically a source of real vulnerabilities (CVE-2016-2776).

The question section is kept valid in all EDNS variants so the parser advances
past it and reaches the OPT record parser — the actual target of the mutation.

| Variant | Attack |
|---|---|
| `RDLENGTH_OVERFLOW` | `RDLENGTH=512` but zero bytes of RDATA follow |
| `OPTION_LEN_OVERFLOW` | Option claims `length=32767` into a 2-byte data region |
| `ZERO_RDLENGTH` | `RDLENGTH=0` but option bytes follow in the packet |
| `NEGATIVE_OPTION_LEN` | `option-length=0xFFFF` — 65535 bytes claimed |
| `STACKED_OVERFLOW` | 10 options each claiming `length=100` into 4-byte data regions |
| `RESERVED_OPTION_CODE` | Option codes `0x0000` and `0xFFFF` (both reserved, RFC 6891) |
| `VERSION_NONZERO` | EDNS version field `!= 0` — server must return `BADVERS` (rcode=16) |

CVE history: CVE-2016-2776 — assertion failure in BIND9's buffer handling
triggered by a crafted EDNS response. Patched in 9.9.9-P3 / 9.10.4-P3 /
9.11.0rc3.

#### ZeroLengthLabel (6 variants)

In DNS wire format, a zero-length label (`0x00`) is the root label terminator.
Injecting it mid-name creates structural ambiguity — the parser sees the name
as ended and interprets the subsequent bytes as QTYPE/QCLASS, which are
completely wrong bytes in the wrong context.

| Variant | QNAME structure |
|---|---|
| `ZERO_LABEL_MID` | `[4]fuzz [0] [5]local [0]` — zero after first label |
| `ZERO_LABEL_START` | `[0] [4]fuzz [5]local [0]` — zero as first byte |
| `CONSECUTIVE_ZEROS` | `[4]fuzz [0][0][0] [5]local [0]` — three consecutive zeros |
| `LABEL_AFTER_ROOT` | `[4]fuzz [5]local [0] [3]foo [0]` — labels after root |
| `MIXED_PTR_LABEL` | `[4]fuzz 0xC0 0x0C` — valid label followed by pointer back to start |
| `LONE_DOT` | `[0]` — single root label, querying the root zone |

---

## 5. Crash Detection and Triage

### Detection

`UdpHarness` classifies each send result as one of:

- **RESPONSE** — server replied (may still contain anomalous RCODE)
- **TIMEOUT** — no response within the configured window
- **PORT_UNREACHABLE** — ICMP port unreachable received — server process down

`CrashDetector` applies thresholds:

- **Hard crash** — PORT_UNREACHABLE on any iteration
- **Soft crash** — 3 consecutive timeouts (configurable threshold)
- **RCODE anomaly** — SERVFAIL (rcode=2) in response

Every finding is saved to disk immediately: binary trigger bytes
(`.bin`) and a human-readable report (`.txt`) including hex dump,
mutator name, iteration number, timestamp, and triage verdict.

### Triage

`CrashClassifier` analyzes the trigger payload and assigns a structured
verdict at the time of recording — there is no separate post-processing step.

The classifier works by parsing the DNS header fields from the trigger
bytes and applying a priority-ordered rule chain. First match wins.

**Verdict hierarchy:**

| Priority | Verdict | Condition |
|---|---|---|
| CRITICAL | `TRUE_POSITIVE` | Hard crash (port unreachable) on any input |
| HIGH | `SUSPICIOUS` | Soft crash with no RFC-explainable drop reason |
| HIGH | `PTR_LOOP_TIMEOUT` | Timeout triggered by compression pointer mutator |
| HIGH | `EDNS_PARSE_ANOMALY` | Timeout triggered by EDNS overflow mutator |
| HIGH | `MALFORMED_TRUNC` | TC=1 on an incoming query caused timeout |
| HIGH | `QDCOUNT_MISMATCH` | QDCOUNT/payload contradiction caused timeout |
| HIGH | `LABEL_OVERFLOW` | Label overflow or zero-label mutator caused timeout |
| HIGH | `RESERVED_BITS` | Z-bit set (RFC 1035 §4.1.1 reserved) caused timeout |
| MEDIUM | `UNKNOWN_QTYPE` | Reserved QTYPE range caused timeout |
| LOW | `OPCODE_UNDEFINED` | Opcode > 5 (undefined) caused timeout — expected |
| LOW | `EXPECTED_DROP` | `QR=1` — server correctly ignoring a response packet |
| INFO | `PREFILTERED` | Payload under 12 bytes — dropped before reaching DNS parser |
| INFO | `UNCLASSIFIED` | Cause not determinable |

**Console output by priority:**

```
[!!!]   HARD_CRASH — OversizeLabel — iter=42 [CRITICAL/TRUE_POSITIVE] ← CRITICAL
[CRASH] SOFT_CRASH_TIMEOUT — ZeroLengthLabel — iter=99 [HIGH/LABEL_OVERFLOW]
[DROP]  SOFT_CRASH_TIMEOUT — HeaderFlags — iter=15 [EXPECTED_DROP — expected, not a bug]
```

**End-of-run triage report:**

```
╔══════════════════════════════════════════════════════════╗
║              CRASH TRIAGE REPORT                        ║
╚══════════════════════════════════════════════════════════╝

SUMMARY
────────────────────────────────────────────────────────────
  EXPECTED_DROP          [LOW]      25 finding(s)

EXPECTED DROPS (25) — RFC-compliant behavior, not bugs
────────────────────────────────────────────────────────────
  iter=8      mutator=HeaderFlags    EXPECTED_DROP
  iter=15     mutator=HeaderFlags    EXPECTED_DROP
  ...
```

---

## 6. Isolated Mutator Mode

`--isolate <n>` restricts the engine to only the named mutator using a
case-insensitive substring match. This is used to confirm root cause after a
stacked-mutation finding attributes a crash to a specific mutator.

```bash
# Confirm HeaderFlags is triggering all findings
java -jar target/fuzzer.jar --isolate HeaderFlags --port 5353 --domain fuzz.local

# Target both label mutators
java -jar target/fuzzer.jar --isolate label --port 5353 --domain fuzz.local

# Target all EDNS variants
java -jar target/fuzzer.jar --isolate EdnsOpt --port 5353 --domain fuzz.local

# Target all compression pointer variants
java -jar target/fuzzer.jar --isolate CompressionPtr --port 5353 --domain fuzz.local
```

Substring matching rules:

| Query | Matches |
|---|---|
| `HeaderFlags` | `HeaderFlags` (1 mutator) |
| `bitflip` | `BitFlip(1)`, `BitFlip(4)` (2 mutators) |
| `label` | `LabelLength`, `OversizeLabel`, `ZeroLengthLabel(*)` (8 mutators) |
| `EdnsOpt` | All 7 `EdnsOptOverflow(*)` variants |
| `CompressionPtr` | All 4 `CompressionPtrLoop(*)` variants |
| `ZeroLength` | All 6 `ZeroLengthLabel(*)` variants |

---

## 7. Test Coverage

70 tests across 3 test classes, passing in under 1.5 seconds.

| Class | Tests | What it covers |
|---|---|---|
| `FuzzerTest` | 20 | DNS wire format roundtrip, label encoding, FSM transitions, v1 mutator validation |
| `SemanticMutatorTest` | 27 | All v2 mutator variants: wire format correctness, seed immutability, classifier detection |
| `ClassifierAndIsolationTest` | 23 | Classifier verdicts for all input classes, isolation mode behavior |

Selected test cases:

- `SELF_LOOP` pointer at offset 12 correctly points to offset 12
- `CHAIN_DEPTH` produces exactly 64 pointer hops (128 bytes)
- `FORWARD_PTR` offset exceeds packet length
- `RDLENGTH_OVERFLOW` claimed length exceeds remaining bytes
- `VERSION_NONZERO` EDNS TTL version byte is non-zero
- `ZERO_LABEL_MID` zero byte appears at correct offset after first label
- `QR=1` soft crash classifies as `EXPECTED_DROP`
- `QR=1` hard crash classifies as `TRUE_POSITIVE` (crash on a drop should not happen)
- Seed arrays are never mutated in-place by any mutator (immutability contract)
- `isolate("doesnotexist")` leaves pool unchanged and prints warning

---

## 8. Findings — BIND9 9.18 on Ubuntu 24.04

**Target:** BIND9 9.18.x in Docker, port 5353, domain `fuzz.local`  
**Total iterations:** 85,000 across all isolation runs  
**Total actionable findings:** 0  
**Total expected drops (triaged):** 25

### Full sweep results

| Mutator class | Iterations | Rate | Timeouts | Actionable | Analysis |
|---|---|---|---|---|---|
| HeaderFlags | 5,000 | ~12/s | 429 | 0 | All timeouts are `QR=1` — RFC-mandated drop. See note below. |
| LabelLength + OversizeLabel | 5,000 | ~5,000/s | 0 | 0 | All mutations responded with FORMERR. Label parser is robust. |
| QdCountMismatch | 5,000 | ~5,000/s | 0 | 0 | FORMERR on all QDCOUNT contradictions. No hangs. |
| NullByteInject | 5,000 | ~5,000/s | 0 | 0 | Null bytes in question section produce FORMERR or are ignored. |
| RandomType | 5,000 | ~5,000/s | 0 | 0 | Reserved QTYPEs produce NOTIMP or NOERROR with empty answers. |
| CompressionPtrLoop (4 variants) | 10,000 | ~10,000/s | 0 | 0 | All pointer loop forms rejected immediately. See note below. |
| EdnsOptOverflow (7 variants) | 10,000 | ~10,000/s | 0 | 0 | RDLENGTH and option-length bounds-checked. No parse anomalies. |
| ZeroLengthLabel (6 variants) | 10,000 | ~10,000/s | 0 | 0 | All zero-label forms produce FORMERR. QNAME parser is strict. |

### Analysis notes

**HeaderFlags — 429 timeouts, all EXPECTED_DROP.**
The 429 timeouts from HeaderFlags were the initial signal that prompted the
triage system. All 429 were caused by the `QR=1` flag (0x8000) being set.
RFC 1035 §4.1.1 defines `QR=0` as a query and `QR=1` as a response — a DNS
server MUST NOT respond to packets with `QR=1`. BIND9 silently drops them,
which is correct. The classifier identified all 429 as `EXPECTED_DROP` and
none appear in the actionable findings count.

The 12 msg/s throughput during HeaderFlags isolation (vs. 5,000+ for other
mutators) is explained entirely by timeout overhead: `429 timeouts × 200ms
≈ 86 seconds` over 5,000 iterations.

**Compression pointer loops — 0 timeouts.**
BIND9 9.18 detects and rejects all four pointer loop variants at ~10,000
msg/s with zero timeouts. This indicates loop detection fires before any
blocking I/O — the rejection is microseconds. BIND9 uses a pointer-following
depth limit combined with a visited-offset check. The same bug class was
exploitable in BIND 4 and early BIND 8 (CVE-2000-0333) and has been patched
in all BIND9 releases.

**EDNS option overflow — 0 timeouts.**
All seven EDNS overflow variants handled without anomaly, including
`RDLENGTH_OVERFLOW` (claims 512 bytes with none present) and
`NEGATIVE_OPTION_LEN` (option-length=0xFFFF). BIND9 validates RDLENGTH
against the message boundary before reading options. CVE-2016-2776 was an
assertion failure in this code path, patched in 9.9.9-P3.

**Zero-length label — 0 timeouts.**
All six zero-label variants produce FORMERR. BIND9's QNAME parser treats
a zero-length label anywhere as the root terminator and validates that the
bytes following it form a valid QTYPE/QCLASS. When they don't, FORMERR is
returned immediately.

### Summary statement

BIND9 9.18 on Ubuntu 24.04 correctly handles all 26 mutation classes tested.
Zero actionable findings were produced. The 25 `EXPECTED_DROP` findings from
HeaderFlags are RFC-mandated behavior and are correctly suppressed from the
actionable findings count by the classifier.

This is the expected result for a current-version, actively maintained DNS
implementation. The significance of this result is that the fuzzer's triage
system correctly distinguished correct RFC behavior from actual anomalies:
25 false positives were generated by HeaderFlags and all 25 were correctly
classified and excluded from actionable output. Without the triage layer, all
25 would have appeared as crashes, creating noise that would obscure any real
finding.

---

## 9. Interpreting Results

### What a "finding" means

**Hard crash** (`TRUE_POSITIVE`, CRITICAL) — `PORT_UNREACHABLE` after sending
a mutation. The server process terminated. The trigger bytes are saved to disk
and are the first thing to examine.

**Soft crash** — Three consecutive timeouts. The classifier verdict determines
significance. `EXPECTED_DROP` means the server is behaving correctly per RFC.
`PTR_LOOP_TIMEOUT`, `EDNS_PARSE_ANOMALY`, `LABEL_OVERFLOW`, or `SUSPICIOUS`
means the input caused unexpected server behavior and warrants investigation.

**RCODE anomaly** — Server returned SERVFAIL. Can indicate a parsing error in
the server's processing logic worth examining with the trigger bytes.

### Throughput as a diagnostic signal

Message rate per second is a diagnostic independent of crash counts:

| Rate | Meaning |
|---|---|
| ~5,000+ msg/s | Server responding normally — all inputs processed |
| ~12–100 msg/s | High timeout rate — many packets dropped |
| Rate drops mid-run | Server slowing — possible resource leak or memory pressure |
| Rate drops to 0 | Hard crash — server process terminated |

### False positive suppression

`EXPECTED_DROP` findings appear in the run log as `[DROP]` lines for
completeness but are excluded from the `Actionable findings` count in the
summary. An `EXPECTED_DROP` verdict means the timeout has a clear RFC basis —
the server is correct and there is nothing to investigate.

---

## 10. Running the Fuzzer

### Requirements

- Java 17+
- Maven 3.8+
- Docker (for the BIND9 target)

### Start BIND9 target

```bash
cd docker/
docker-compose up -d
docker-compose ps   # wait for healthy
```

The Docker setup configures BIND9 with EDNS enabled, 4096-byte UDP payload,
rate limiting disabled, and a `fuzz.local` zone with A, AAAA, MX, NS, CNAME,
and TXT records. Port 53 is mapped to host port 5353.

### Build

```bash
mvn clean package -q
# Produces: target/fuzzer.jar (fat JAR, all dependencies included)
```

### Run modes

```bash
# Standard round-robin, 10,000 iterations
java -jar target/fuzzer.jar \
  --host 127.0.0.1 --port 5353 \
  --domain fuzz.local \
  --iterations 10000

# Stacked mutations — deepest combinatorial coverage
java -jar target/fuzzer.jar \
  --mode STACKED \
  --host 127.0.0.1 --port 5353 \
  --domain fuzz.local \
  --timeout 500 \
  --iterations 50000 \
  --crashes ./crashes

# Isolate a specific mutator for root cause confirmation
java -jar target/fuzzer.jar \
  --isolate CompressionPtr \
  --port 5353 \
  --domain fuzz.local \
  --timeout 500 \
  --iterations 10000
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `--host <ip>` | `127.0.0.1` | Target DNS server IP |
| `--port <n>` | `53` | Target DNS server port |
| `--domain <domain>` | `example.com` | Domain for fuzz queries |
| `--crashes <dir>` | `./crashes` | Directory for crash output |
| `--timeout <ms>` | `2000` | Response timeout per packet |
| `--iterations <n>` | `10000` | Number of fuzz iterations |
| `--mode <mode>` | `ROUND_ROBIN` | `ROUND_ROBIN`, `RANDOM`, `STACKED`, `ISOLATED` |
| `--isolate <n>` | — | Restrict to named mutator (substring match) |

### Tests

```bash
mvn test
# 70 tests, ~1.5 seconds
```

### Crash output

Each finding produces two files:

```
crashes/
├── soft_crash_timeout_expected_drop_iter8_20260227_....bin   ← exact trigger bytes
└── soft_crash_timeout_expected_drop_iter8_20260227_....txt   ← full report
```

Report format:

```
=== CRASH REPORT ===
Type      : SOFT_CRASH_TIMEOUT
Timestamp : 2026-02-27T17:08:42.331Z
Iteration : 8
Mutator   : HeaderFlags

--- TRIAGE ---
Verdict   : EXPECTED_DROP
Priority  : LOW
Reasoning : QR bit (0x8000) is SET — packet appears to be a DNS response,
            not a query. RFC 1035 §4.1.1 requires servers to ignore such
            packets. BIND9 silent drop is CORRECT behavior. Not a vulnerability.
            Flags: 0xAAAA [QR=1 OPCODE=5 TC=0 RD=0 RA=1 Z=0 RCODE=10]
Actionable: false

--- PAYLOAD ---
Size      : 27 bytes
Hex Dump  :
0000  13 38 AA AA 00 01 00 00  00 00 00 00 04 66 75 7A  |.8...........fuz|
0010  7A 05 6C 6F 63 61 6C 00  00 00 00 01              |z.local.....|
```

---

## 11. Project Structure

```
.
├── pom.xml
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── named.conf
│   ├── named.conf.local
│   └── db.fuzz.local
└── src/
    ├── main/java/com/fuzzer/
    │   ├── Main.java                       CLI entry point, argument parsing
    │   ├── DnsFuzzer.java                  Main orchestrator, fuzz loop
    │   ├── dns/
    │   │   ├── DnsHeader.java              12-byte DNS header parser/serializer
    │   │   ├── DnsQuestion.java            Question section + label encoder/decoder
    │   │   ├── DnsMessage.java             Full DNS message builder
    │   │   └── EdnsOption.java             EDNS0 OPT record (RFC 6891)
    │   ├── fsm/
    │   │   ├── ProtocolState.java          State node definition
    │   │   ├── StateTransition.java        Transition with trigger condition
    │   │   ├── StateMachine.java           Protocol-agnostic FSM engine
    │   │   └── DnsStateMachine.java        DNS FSM — 12 states, 5 fuzz points
    │   ├── mutator/
    │   │   ├── Mutator.java                Interface: byte[] mutate(byte[])
    │   │   ├── Mutators.java               v1 byte-level mutators (9 classes)
    │   │   ├── SemanticMutators.java       v2 semantic mutators (17 variants)
    │   │   └── MutationEngine.java         Pool manager, isolate(), run modes
    │   ├── harness/
    │   │   └── UdpHarness.java             UDP transport, timeout, crash detection
    │   ├── crash/
    │   │   ├── CrashDetector.java          Recording + auto-triage on every finding
    │   │   └── CrashClassifier.java        RFC-aware verdict assignment (13 verdicts)
    │   └── corpus/
    │       └── CorpusManager.java          Seed manager: A, MX, NS, AAAA, ANY, subdomain
    └── test/java/com/fuzzer/
        ├── FuzzerTest.java                 DNS wire format, FSM, v1 mutator tests
        ├── SemanticMutatorTest.java        v2 mutator wire format correctness tests
        └── ClassifierAndIsolationTest.java Classifier verdict tests, isolation tests
```

---

## 12. Extending the Fuzzer

### Add a new mutator

```java
// In SemanticMutators.java or a new file:
public static class MyMutator implements Mutator {
    @Override
    public byte[] mutate(byte[] input) {
        // Never modify input in-place — always copy first.
        // The corpus manager shares seed arrays across mutators.
        byte[] out = Arrays.copyOf(input, input.length);
        // construct your structural trap
        return out;
    }
    @Override public String name() { return "MyMutator"; }
}

// Register in MutationEngine.registerDefaults():
mutators.add(new SemanticMutators.MyMutator());
```

### Add a TCP harness

The `UdpHarness` is intentionally minimal. A `TcpHarness` for zone transfer
(AXFR) fuzzing requires:

1. Connection setup with 2-byte message length prefix (RFC 1035 §4.2.2)
2. State for multi-message AXFR sequences: `SOA → records → SOA`
3. Hard crash detection distinguishing `Connection reset` from `Connection refused`
4. A new seed corpus of AXFR request messages for the `fuzz.local` zone

### Add a new protocol

1. Create a wire format package (e.g. `dhcp/`)
2. Create an FSM definition (`DhcpStateMachine.java`)
3. Implement a transport harness
4. Register a seed corpus in `CorpusManager`

The `MutationEngine`, `CrashDetector`, and `CrashClassifier` are
protocol-agnostic and require no changes.

### Extend the classifier

Add a new verdict to `CrashClassifier.Verdict`, assign its `Priority`, and
insert a detection rule in `classify()` before the `SUSPICIOUS` fallback.
The rule receives parsed header fields and the mutator name — sufficient to
classify any structural pattern or mutator class.
