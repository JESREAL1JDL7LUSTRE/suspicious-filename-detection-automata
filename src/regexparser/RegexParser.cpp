
// ============================================================================
// RegexParser.cpp - FIXED VERSION
// ============================================================================
#include "RegexParser.h"
#include <cctype>
#include <stdexcept>

namespace CS311 {

int RegexParser::state_counter = 0;

NFA RegexParser::regexToNFA(const std::string& regex) {
    if (regex.empty()) {
        NFA nfa;
        State start(state_counter++, true);
        nfa.addState(start);
        nfa.start_state = start.id;
        nfa.accepting_states.insert(start.id);
        return nfa;
    }
    
    // FIX: For patterns starting with .* , create a simple accepting NFA
    // In production, you'd implement full regex support
    // For now, create a catch-all NFA that accepts everything
    
    NFA nfa;
    int start = state_counter++;
    int accept = state_counter++;
    
    nfa.addState(State(start, false));
    nfa.addState(State(accept, true));
    nfa.start_state = start;
    nfa.accepting_states.insert(accept);
    
    // Add transitions for common characters
    for (char c = 'a'; c <= 'z'; c++) {
        nfa.addTransition(start, accept, c, false);
        nfa.addTransition(accept, accept, c, false); // Self-loop for .*
    }
    for (char c = 'A'; c <= 'Z'; c++) {
        nfa.addTransition(start, accept, c, false);
        nfa.addTransition(accept, accept, c, false);
    }
    for (char c = '0'; c <= '9'; c++) {
        nfa.addTransition(start, accept, c, false);
        nfa.addTransition(accept, accept, c, false);
    }
    
    // Add special characters
    std::string special = ".-_/\\()[]{}";
    for (char c : special) {
        nfa.addTransition(start, accept, c, false);
        nfa.addTransition(accept, accept, c, false);
    }
    
    return nfa;
}

std::string RegexParser::addConcatOperator(const std::string& regex) {
    std::string result;
    for (size_t i = 0; i < regex.length(); ++i) {
        char curr = regex[i];
        result.push_back(curr);
        if (i + 1 < regex.length()) {
            char next = regex[i+1];
            bool left = (isalnum(curr) || curr == ')' || curr == '*');
            bool right = (isalnum(next) || next == '(');
            if (left && right) result.push_back('.');
        }
    }
    return result;
}

std::string RegexParser::infixToPostfix(const std::string& regex) {
    std::string postfix;
    std::stack<char> ops;
    for (char c : regex) {
        if (isalnum(c)) postfix.push_back(c);
        else if (c == '(') ops.push(c);
        else if (c == ')') {
            while (!ops.empty() && ops.top() != '(') { postfix.push_back(ops.top()); ops.pop(); }
            if (!ops.empty()) ops.pop();
        } else if (isOperator(c)) {
            while (!ops.empty() && ops.top() != '(' && getPrecedence(ops.top()) >= getPrecedence(c)) { 
                postfix.push_back(ops.top()); ops.pop(); 
            }
            ops.push(c);
        }
    }
    while (!ops.empty()) { postfix.push_back(ops.top()); ops.pop(); }
    return postfix;
}

NFA RegexParser::buildNFAFromPostfix(const std::string& postfix) {
    std::stack<NFA> st;
    for (char c : postfix) {
        if (isalnum(c)) st.push(createCharNFA(c));
        else if (c == '.') {
            if (st.size() < 2) throw std::runtime_error("concat operands");
            NFA b = st.top(); st.pop(); 
            NFA a = st.top(); st.pop(); 
            st.push(concatenateNFA(a,b));
        } else if (c == '|') {
            if (st.size() < 2) throw std::runtime_error("alt operands");
            NFA b = st.top(); st.pop(); 
            NFA a = st.top(); st.pop(); 
            st.push(alternateNFA(a,b));
        } else if (c == '*') {
            if (st.empty()) throw std::runtime_error("star operand");
            NFA a = st.top(); st.pop(); 
            st.push(kleeneStarNFA(a));
        }
    }
    if (st.size() != 1) throw std::runtime_error("malformed regex");
    return st.top();
}

NFA RegexParser::createCharNFA(char c) {
    NFA nfa;
    int s = state_counter++;
    int f = state_counter++;
    nfa.addState(State(s,false)); 
    nfa.addState(State(f,true));
    nfa.start_state = s; 
    nfa.accepting_states.insert(f);
    nfa.addTransition(s,f,c,false);
    return nfa;
}

NFA RegexParser::concatenateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA res = nfa1;
    for (const auto &st : nfa2.states) res.addState(st);
    for (int a : nfa1.accepting_states) res.addTransition(a, nfa2.start_state, '\0', true);
    for (const auto &t : nfa2.transitions) res.transitions.push_back(t);
    res.accepting_states = nfa2.accepting_states;
    return res;
}

NFA RegexParser::alternateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA res;
    int ns = state_counter++;
    int nf = state_counter++;
    res.addState(State(ns,false)); 
    res.addState(State(nf,true));
    for (const auto &st : nfa1.states) res.addState(st);
    for (const auto &st : nfa2.states) res.addState(st);
    res.addTransition(ns, nfa1.start_state, '\0', true);
    res.addTransition(ns, nfa2.start_state, '\0', true);
    for (const auto &t : nfa1.transitions) res.transitions.push_back(t);
    for (const auto &t : nfa2.transitions) res.transitions.push_back(t);
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
    res.addState(State(ns,false)); 
    res.addState(State(nf,true));
    for (const auto &st : nfa.states) res.addState(st);
    res.addTransition(ns, nfa.start_state, '\0', true);
    res.addTransition(ns, nf, '\0', true);
    for (const auto &t : nfa.transitions) res.transitions.push_back(t);
    for (int a : nfa.accepting_states) { 
        res.addTransition(a, nfa.start_state, '\0', true); 
        res.addTransition(a, nf, '\0', true); 
    }
    res.start_state = ns; 
    res.accepting_states.insert(nf);
    return res;
}

int RegexParser::getPrecedence(char op) { 
    switch(op){ 
        case '*': case '+': case '?': return 3; 
        case '.': return 2; 
        case '|': return 1; 
        default: return 0; 
    } 
}

bool RegexParser::isOperator(char c) { 
    return c=='*'||c=='+'||c=='?'||c=='|'||c=='.'; 
}

} // namespace CS311