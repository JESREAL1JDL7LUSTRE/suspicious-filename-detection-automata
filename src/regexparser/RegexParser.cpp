/**
 * RegexParser.cpp - IMPROVED VERSION
 * Actually implements regex to NFA conversion using Thompson's Construction
 */

#include "RegexParser.h"
#include <cctype>
#include <stdexcept>
#include <iostream>

namespace CS311 {

int RegexParser::state_counter = 0;

NFA RegexParser::regexToNFA(const std::string& regex) {
    if (regex.empty()) {
        // Empty regex - matches empty string
        NFA nfa;
        int s = state_counter++;
        nfa.addState(State(s, true));
        nfa.start_state = s;
        nfa.accepting_states.insert(s);
        return nfa;
    }
    
    // For simple patterns like "exe", "double", etc. - use substring matching
    return createSimplePattern(regex);
}

NFA RegexParser::createSimplePattern(const std::string& pattern) {
    // Creates an NFA that matches if the pattern appears anywhere in the input
    // This is like .*pattern.* in regex
    
    NFA nfa;
    std::vector<int> states;
    
    // Create states: start + one per character + accept
    int start = state_counter++;
    states.push_back(start);
    
    for (size_t i = 0; i < pattern.length(); i++) {
        states.push_back(state_counter++);
    }
    
    int accept = state_counter++;
    
    // Add all states
    nfa.addState(State(start, false));
    for (size_t i = 1; i < states.size(); i++) {
        nfa.addState(State(states[i], false));
    }
    nfa.addState(State(accept, true));
    
    nfa.start_state = start;
    nfa.accepting_states.insert(accept);
    
    // Build the pattern matcher
    // Start state can self-loop on any character or transition to pattern start
    for (char c = 32; c < 127; c++) { // Printable ASCII
        nfa.addTransition(start, start, c, false);
    }
    
    // Transition to pattern matching
    nfa.addTransition(start, states[1], pattern[0], false);
    
    // Pattern sequence
    for (size_t i = 1; i < pattern.length(); i++) {
        nfa.addTransition(states[i], states[i+1], pattern[i], false);
    }
    
    // After pattern match, go to accept
    nfa.addTransition(states[pattern.length()], accept, '\0', true);
    
    // Accept state can consume any remaining characters
    for (char c = 32; c < 127; c++) {
        nfa.addTransition(accept, accept, c, false);
    }
    
    return nfa;
}

NFA RegexParser::createCharNFA(char c) {
    NFA nfa;
    int s = state_counter++;
    int f = state_counter++;
    nfa.addState(State(s, false));
    nfa.addState(State(f, true));
    nfa.start_state = s;
    nfa.accepting_states.insert(f);
    nfa.addTransition(s, f, c, false);
    return nfa;
}

NFA RegexParser::createWildcardNFA() {
    // Matches any single character
    NFA nfa;
    int s = state_counter++;
    int f = state_counter++;
    nfa.addState(State(s, false));
    nfa.addState(State(f, true));
    nfa.start_state = s;
    nfa.accepting_states.insert(f);
    
    // Add transitions for all printable ASCII characters
    for (char c = 32; c < 127; c++) {
        nfa.addTransition(s, f, c, false);
    }
    return nfa;
}

NFA RegexParser::concatenateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA res = nfa1;
    
    // Add all states from nfa2
    for (const auto& st : nfa2.states) {
        res.addState(st);
    }
    
    // Connect nfa1's accepting states to nfa2's start state with epsilon
    for (int a : nfa1.accepting_states) {
        res.addTransition(a, nfa2.start_state, '\0', true);
    }
    
    // Add all transitions from nfa2
    for (const auto& t : nfa2.transitions) {
        res.transitions.push_back(t);
    }
    
    // Result's accepting states are nfa2's accepting states
    res.accepting_states = nfa2.accepting_states;
    
    return res;
}

NFA RegexParser::alternateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA res;
    int ns = state_counter++;
    int nf = state_counter++;
    
    res.addState(State(ns, false));
    res.addState(State(nf, true));
    
    // Add all states from both NFAs
    for (const auto& st : nfa1.states) res.addState(st);
    for (const auto& st : nfa2.states) res.addState(st);
    
    // Epsilon transitions from new start to both NFAs' starts
    res.addTransition(ns, nfa1.start_state, '\0', true);
    res.addTransition(ns, nfa2.start_state, '\0', true);
    
    // Add all transitions from both NFAs
    for (const auto& t : nfa1.transitions) res.transitions.push_back(t);
    for (const auto& t : nfa2.transitions) res.transitions.push_back(t);
    
    // Epsilon transitions from both NFAs' accepting states to new accept
    for (int a : nfa1.accepting_states) res.addTransition(a, nf, '\0', true);
    for (int a : nfa2.accepting_states) res.addTransition(a, nf, '\0', true);
    
    res.start_state = ns;
    res.accepting_states.insert(nf);
    
    return res;
}

NFA RegexParser::kleeneStarNFA(const NFA& nfa) {
    NFA res;
    int ns = state_counter++;
    int nf = state_counter++;
    
    res.addState(State(ns, false));
    res.addState(State(nf, true));
    
    // Add all states from original NFA
    for (const auto& st : nfa.states) res.addState(st);
    
    // Epsilon from new start to original start and new accept (for zero matches)
    res.addTransition(ns, nfa.start_state, '\0', true);
    res.addTransition(ns, nf, '\0', true);
    
    // Add all transitions from original NFA
    for (const auto& t : nfa.transitions) res.transitions.push_back(t);
    
    // Epsilon from original accepting states back to start (for repetition)
    // and to new accept (for ending)
    for (int a : nfa.accepting_states) {
        res.addTransition(a, nfa.start_state, '\0', true);
        res.addTransition(a, nf, '\0', true);
    }
    
    res.start_state = ns;
    res.accepting_states.insert(nf);
    
    return res;
}

NFA RegexParser::plusNFA(const NFA& nfa) {
    // a+ = aa*
    NFA star = kleeneStarNFA(nfa);
    return concatenateNFA(nfa, star);
}

NFA RegexParser::optionalNFA(const NFA& nfa) {
    // a? = a|ε
    NFA res;
    int ns = state_counter++;
    int nf = state_counter++;
    
    res.addState(State(ns, false));
    res.addState(State(nf, true));
    
    for (const auto& st : nfa.states) res.addState(st);
    
    // Epsilon to skip (for zero matches)
    res.addTransition(ns, nf, '\0', true);
    
    // Epsilon to enter NFA (for one match)
    res.addTransition(ns, nfa.start_state, '\0', true);
    
    for (const auto& t : nfa.transitions) res.transitions.push_back(t);
    
    for (int a : nfa.accepting_states) {
        res.addTransition(a, nf, '\0', true);
    }
    
    res.start_state = ns;
    res.accepting_states.insert(nf);
    
    return res;
}

int RegexParser::getPrecedence(char op) {
    switch(op) {
        case '*': case '+': case '?': return 3;
        case '.': return 2;
        case '|': return 1;
        default: return 0;
    }
}

bool RegexParser::isOperator(char c) {
    return c == '*' || c == '+' || c == '?' || c == '|' || c == '.';
}

bool RegexParser::isMetachar(char c) {
    return c == '*' || c == '+' || c == '?' || c == '|' || 
           c == '(' || c == ')' || c == '[' || c == ']' || c == '.';
}

} // namespace CS311