package com.fuzzer.fsm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Finite State Machine engine.
 *
 * Manages the current state of a protocol conversation, evaluates
 * transition triggers, and tracks which states have been visited.
 *
 * This is protocol-agnostic. DNS, DHCP, or any future protocol
 * simply registers its own states and transitions here.
 */
public class StateMachine {

    private final String protocolName;
    private ProtocolState currentState;
    private final ProtocolState initialState;

    private final List<ProtocolState> states = new ArrayList<>();
    private final Map<String, List<StateTransition>> transitionMap = new HashMap<>();

    // Execution tracking
    private final List<String> visitedStates = new ArrayList<>();
    private int transitionCount = 0;

    public StateMachine(String protocolName, ProtocolState initialState) {
        this.protocolName = protocolName;
        this.initialState = initialState;
        this.currentState = initialState;
        addState(initialState);
    }

    public void addState(ProtocolState state) {
        if (!states.contains(state)) {
            states.add(state);
        }
    }

    public void addTransition(StateTransition transition) {
        addState(transition.getFrom());
        addState(transition.getTo());
        transitionMap
                .computeIfAbsent(transition.getFrom().getName(), k -> new ArrayList<>())
                .add(transition);
    }

    /**
     * Attempt to transition based on a trigger.
     * Returns the new state if transition fired, null if no matching transition.
     */
    public ProtocolState transition(StateTransition.Trigger trigger) {
        List<StateTransition> available = transitionMap.get(currentState.getName());
        if (available == null) return null;

        for (StateTransition t : available) {
            if (t.getTrigger() == trigger || t.getTrigger() == StateTransition.Trigger.ALWAYS) {
                visitedStates.add(currentState.getName());
                currentState = t.getTo();
                transitionCount++;
                return currentState;
            }
        }
        return null;
    }

    public void reset() {
        currentState = initialState;
        visitedStates.clear();
        transitionCount = 0;
    }

    public ProtocolState getCurrentState()    { return currentState; }
    public boolean isTerminal()               { return currentState.getType() == ProtocolState.StateType.TERMINAL; }
    public boolean isFuzzPoint()              { return currentState.isFuzzable(); }
    public List<String> getVisitedStates()    { return visitedStates; }
    public int getTransitionCount()           { return transitionCount; }
    public String getProtocolName()           { return protocolName; }

    /**
     * Return all fuzzable states in this FSM.
     */
    public List<ProtocolState> getFuzzableStates() {
        List<ProtocolState> result = new ArrayList<>();
        for (ProtocolState s : states) {
            if (s.isFuzzable()) result.add(s);
        }
        return result;
    }

    @Override
    public String toString() {
        return String.format("FSM[%s current=%s transitions=%d]",
                protocolName, currentState.getName(), transitionCount);
    }
}
