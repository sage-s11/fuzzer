package com.fuzzer.fsm;

/**
 * Represents a single state in a protocol FSM.
 *
 * A state describes:
 * - What kind of message is expected/sent at this point
 * - What transitions are valid from here
 * - Whether this is a terminal state (end of conversation)
 * - Whether this is a fuzz point (safe to mutate here)
 */
public class ProtocolState {

    public enum StateType {
        INITIAL,      // Starting state before any message
        SEND,         // We send a message to target
        RECEIVE,      // We wait for a response
        VALIDATE,     // We check if response is valid before proceeding
        FUZZ_POINT,   // Safe mutation point - mutate and send
        TERMINAL      // End of conversation
    }

    private final String name;
    private final StateType type;
    private final String description;
    private boolean isFuzzable;

    public ProtocolState(String name, StateType type, String description) {
        this.name        = name;
        this.type        = type;
        this.description = description;
        this.isFuzzable  = (type == StateType.FUZZ_POINT);
    }

    public ProtocolState setFuzzable(boolean fuzzable) {
        this.isFuzzable = fuzzable;
        return this;
    }

    public String getName()        { return name; }
    public StateType getType()     { return type; }
    public String getDescription() { return description; }
    public boolean isFuzzable()    { return isFuzzable; }

    @Override
    public String toString() {
        return String.format("State[%s/%s fuzzable=%b]", name, type, isFuzzable);
    }
}
