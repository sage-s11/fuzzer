package com.fuzzer.fsm;

/**
 * Represents a transition between two protocol states.
 *
 * Transitions are conditional — they fire when a trigger condition
 * is met (e.g., server responded with NOERROR, or a timeout occurred).
 */
public class StateTransition {

    public enum Trigger {
        VALID_RESPONSE,     // Server sent a well-formed response
        ERROR_RESPONSE,     // Server sent an error (SERVFAIL, FORMERR, etc.)
        TIMEOUT,            // No response within deadline
        CRASH_DETECTED,     // Target process disappeared / connection refused
        ALWAYS              // Unconditional transition
    }

    private final ProtocolState from;
    private final ProtocolState to;
    private final Trigger trigger;
    private final String label;

    public StateTransition(ProtocolState from, ProtocolState to, Trigger trigger, String label) {
        this.from    = from;
        this.to      = to;
        this.trigger = trigger;
        this.label   = label;
    }

    public ProtocolState getFrom()  { return from; }
    public ProtocolState getTo()    { return to; }
    public Trigger getTrigger()     { return trigger; }
    public String getLabel()        { return label; }

    @Override
    public String toString() {
        return String.format("Transition[%s --%s--> %s]",
                from.getName(), trigger, to.getName());
    }
}
