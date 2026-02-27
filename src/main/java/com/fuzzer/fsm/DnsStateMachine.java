package com.fuzzer.fsm;

/**
 * DNS Protocol State Machine (v1 - hardcoded)
 *
 * DNS over UDP is a single-round-trip protocol:
 *   INITIAL → SEND_QUERY → AWAIT_RESPONSE → [VALIDATE] → TERMINAL
 *
 * Fuzz points are injected at:
 *   - FUZZ_STANDARD_QUERY  : Mutate a normal A query
 *   - FUZZ_EDNS_QUERY      : Mutate EDNS0 OPT record fields
 *   - FUZZ_ANY_QUERY       : Mutate an ANY query (amplification surface)
 *   - FUZZ_MALFORMED_HEADER: Corrupt the DNS header flags/counts
 *   - FUZZ_LABEL_ENCODING  : Corrupt the domain name label encoding
 */
public class DnsStateMachine {

    // State names
    public static final String S_INITIAL           = "INITIAL";
    public static final String S_SEND_STANDARD     = "SEND_STANDARD_QUERY";
    public static final String S_AWAIT_STANDARD    = "AWAIT_STANDARD_RESPONSE";
    public static final String S_FUZZ_STANDARD     = "FUZZ_STANDARD_QUERY";
    public static final String S_FUZZ_EDNS         = "FUZZ_EDNS_QUERY";
    public static final String S_FUZZ_ANY          = "FUZZ_ANY_QUERY";
    public static final String S_FUZZ_HEADER       = "FUZZ_MALFORMED_HEADER";
    public static final String S_FUZZ_LABEL        = "FUZZ_LABEL_ENCODING";
    public static final String S_VALIDATE          = "VALIDATE_RESPONSE";
    public static final String S_TERMINAL_OK       = "TERMINAL_OK";
    public static final String S_TERMINAL_CRASH    = "TERMINAL_CRASH";
    public static final String S_TERMINAL_TIMEOUT  = "TERMINAL_TIMEOUT";

    public static StateMachine build() {
        // Define states
        ProtocolState initial        = new ProtocolState(S_INITIAL,        ProtocolState.StateType.INITIAL,     "Start");
        ProtocolState sendStandard   = new ProtocolState(S_SEND_STANDARD,  ProtocolState.StateType.SEND,        "Send valid A query to warm up");
        ProtocolState awaitStandard  = new ProtocolState(S_AWAIT_STANDARD, ProtocolState.StateType.RECEIVE,     "Wait for valid response");
        ProtocolState fuzzStandard   = new ProtocolState(S_FUZZ_STANDARD,  ProtocolState.StateType.FUZZ_POINT,  "Mutate standard A query fields");
        ProtocolState fuzzEdns       = new ProtocolState(S_FUZZ_EDNS,      ProtocolState.StateType.FUZZ_POINT,  "Mutate EDNS0 OPT record");
        ProtocolState fuzzAny        = new ProtocolState(S_FUZZ_ANY,       ProtocolState.StateType.FUZZ_POINT,  "Mutate ANY query");
        ProtocolState fuzzHeader     = new ProtocolState(S_FUZZ_HEADER,    ProtocolState.StateType.FUZZ_POINT,  "Corrupt DNS header fields");
        ProtocolState fuzzLabel      = new ProtocolState(S_FUZZ_LABEL,     ProtocolState.StateType.FUZZ_POINT,  "Corrupt label encoding");
        ProtocolState validate       = new ProtocolState(S_VALIDATE,       ProtocolState.StateType.VALIDATE,    "Validate response type");
        ProtocolState termOk         = new ProtocolState(S_TERMINAL_OK,    ProtocolState.StateType.TERMINAL,    "Completed normally");
        ProtocolState termCrash      = new ProtocolState(S_TERMINAL_CRASH, ProtocolState.StateType.TERMINAL,    "Target crash detected");
        ProtocolState termTimeout    = new ProtocolState(S_TERMINAL_TIMEOUT,ProtocolState.StateType.TERMINAL,   "No response - possible crash");

        StateMachine fsm = new StateMachine("DNS", initial);

        // Warm-up path: send valid query first to confirm target is alive
        fsm.addTransition(new StateTransition(initial,       sendStandard,  StateTransition.Trigger.ALWAYS,          "start"));
        fsm.addTransition(new StateTransition(sendStandard,  awaitStandard, StateTransition.Trigger.ALWAYS,          "sent"));
        fsm.addTransition(new StateTransition(awaitStandard, fuzzStandard,  StateTransition.Trigger.VALID_RESPONSE,  "target alive - begin fuzzing"));
        fsm.addTransition(new StateTransition(awaitStandard, termTimeout,   StateTransition.Trigger.TIMEOUT,         "no response on warmup"));
        fsm.addTransition(new StateTransition(awaitStandard, termCrash,     StateTransition.Trigger.CRASH_DETECTED,  "crash on warmup"));

        // Fuzz state chain — each fuzz point leads to validate
        fsm.addTransition(new StateTransition(fuzzStandard,  validate,      StateTransition.Trigger.ALWAYS,          "sent mutated standard query"));
        fsm.addTransition(new StateTransition(fuzzEdns,      validate,      StateTransition.Trigger.ALWAYS,          "sent mutated EDNS query"));
        fsm.addTransition(new StateTransition(fuzzAny,       validate,      StateTransition.Trigger.ALWAYS,          "sent mutated ANY query"));
        fsm.addTransition(new StateTransition(fuzzHeader,    validate,      StateTransition.Trigger.ALWAYS,          "sent corrupt header"));
        fsm.addTransition(new StateTransition(fuzzLabel,     validate,      StateTransition.Trigger.ALWAYS,          "sent corrupt label"));

        // Validate transitions
        fsm.addTransition(new StateTransition(validate,      termOk,        StateTransition.Trigger.VALID_RESPONSE,  "response received - log and continue"));
        fsm.addTransition(new StateTransition(validate,      termOk,        StateTransition.Trigger.ERROR_RESPONSE,  "error response - log RCODE"));
        fsm.addTransition(new StateTransition(validate,      termTimeout,   StateTransition.Trigger.TIMEOUT,         "no response after mutation"));
        fsm.addTransition(new StateTransition(validate,      termCrash,     StateTransition.Trigger.CRASH_DETECTED,  "crash detected after mutation"));

        return fsm;
    }
}
