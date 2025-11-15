
// ============================================================
// RegexParser.cpp
// ============================================================

#include "RegexParser.h"
#include <cctype>
#include <stdexcept>

namespace CS311 {

int RegexParser::state_counter = 0;

NFA RegexParser::regexToNFA(const std::string& regex) {
    if (regex.empty()) {
        // Empty regex - create NFA that accepts empty string
        NFA nfa;
        State start(state_counter++, true);
        nfa.addState(start);
        nfa.start_state = start.id;
        nfa.accepting_states.insert(start.id);
        return nfa;
    }
    
    // Step 1: Add explicit concatenation operators
    std::string processedRegex = addConcatOperator(regex);
    
    // Step 2: Convert to postfix
    std::string postfix = infixToPostfix(processedRegex);
    
    // Step 3: Build NFA from postfix
    NFA nfa = buildNFAFromPostfix(postfix);
    
    return nfa;
}

std::string RegexParser::addConcatOperator(const std::string& regex) {
    std::string result;
    
    for (size_t i = 0; i < regex.length(); i++) {
        result += regex[i];
        
        if (i + 1 < regex.length()) {
            char curr = regex[i];
            char next = regex[i + 1];
            
            // Add '.' for concatenation between:
            // - char and char: ab -> a.b
            // - char and '(': a( -> a.(
            // - ')' and char: )a -> ).a
            // - ')' and '(': )( -> ).(
            // - '*' and char: *a -> *.a
            // - '*' and '(': *( -> *.(
            
            bool needConcat = false;
            
            if ((isalnum(curr) || curr == ')' || curr == '*') &&
                (isalnum(next) || next == '(')) {
                needConcat = true;
            }
            
            if (needConcat && next != '|' && next != '*' && next != '+' && next != '?') {
                result += '.';  // Concatenation operator
            }
        }
    }
    
    return result;
}

std::string RegexParser::infixToPostfix(const std::string& regex) {
    std::string postfix;
    std::stack<char> operators;
    
    for (char c : regex) {
        if (isalnum(c) || c == '\\') {
            // Operand - add to output
            postfix += c;
        }
        else if (c == '(') {
            operators.push(c);
        }
        else if (c == ')') {
            // Pop until matching '('
            while (!operators.empty() && operators.top() != '(') {
                postfix += operators.top();
                operators.pop();
            }
            if (!operators.empty()) operators.pop();  // Remove '('
        }
        else if (isOperator(c)) {
            // Pop operators with higher or equal precedence
            while (!operators.empty() && operators.top() != '(' &&
                   getPrecedence(operators.top()) >= getPrecedence(c)) {
                postfix += operators.top();
                operators.pop();
            }
            operators.push(c);
        }
    }
    
    // Pop remaining operators
    while (!operators.empty()) {
        postfix += operators.top();
        operators.pop();
    }
    
    return postfix;
}

NFA RegexParser::buildNFAFromPostfix(const std::string& postfix) {
    std::stack<NFA> nfaStack;
    
    for (char c : postfix) {
        if (isalnum(c)) {
            // Character - create single-char NFA
            nfaStack.push(createCharNFA(c));
        }
        else if (c == '.') {
            // Concatenation
            if (nfaStack.size() < 2) {
                throw std::runtime_error("Invalid regex: not enough operands for concatenation");
            }
            NFA nfa2 = nfaStack.top(); nfaStack.pop();
            NFA nfa1 = nfaStack.top(); nfaStack.pop();
            nfaStack.push(concatenateNFA(nfa1, nfa2));
        }
        else if (c == '|') {
            // Alternation
            if (nfaStack.size() < 2) {
                throw std::runtime_error("Invalid regex: not enough operands for alternation");
            }
            NFA nfa2 = nfaStack.top(); nfaStack.pop();
            NFA nfa1 = nfaStack.top(); nfaStack.pop();
            nfaStack.push(alternateNFA(nfa1, nfa2));
        }
        else if (c == '*') {
            // Kleene star
            if (nfaStack.empty()) {
                throw std::runtime_error("Invalid regex: no operand for Kleene star");
            }
            NFA nfa = nfaStack.top(); nfaStack.pop();
            nfaStack.push(kleeneStarNFA(nfa));
        }
    }
    
    if (nfaStack.size() != 1) {
        throw std::runtime_error("Invalid regex: malformed expression");
    }
    
    return nfaStack.top();
}

NFA RegexParser::createCharNFA(char c) {
    NFA nfa;
    
    int start = state_counter++;
    int accept = state_counter++;
    
    nfa.addState(State(start, false));
    nfa.addState(State(accept, true));
    
    nfa.start_state = start;
    nfa.accepting_states.insert(accept);
    nfa.addTransition(start, accept, c, false);
    
    return nfa;
}

NFA RegexParser::concatenateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA result = nfa1;
    
    // Add all states from nfa2
    for (const auto& state : nfa2.states) {
        result.addState(state);
    }
    
    // Connect nfa1 accepting states to nfa2 start with epsilon
    for (int accept : nfa1.accepting_states) {
        result.addTransition(accept, nfa2.start_state, '\0', true);
    }
    
    // Add all transitions from nfa2
    for (const auto& trans : nfa2.transitions) {
        result.transitions.push_back(trans);
    }
    
    // Update accepting states (only nfa2's accepting states)
    result.accepting_states = nfa2.accepting_states;
    
    return result;
}

NFA RegexParser::alternateNFA(const NFA& nfa1, const NFA& nfa2) {
    NFA result;
    
    int new_start = state_counter++;
    int new_accept = state_counter++;
    
    result.addState(State(new_start, false));
    result.addState(State(new_accept, true));
    
    // Add all states from both NFAs
    for (const auto& state : nfa1.states) result.addState(state);
    for (const auto& state : nfa2.states) result.addState(state);
    
    // Epsilon from new start to both NFA starts
    result.addTransition(new_start, nfa1.start_state, '\0', true);
    result.addTransition(new_start, nfa2.start_state, '\0', true);
    
    // Add all transitions from both NFAs
    for (const auto& trans : nfa1.transitions) result.transitions.push_back(trans);
    for (const auto& trans : nfa2.transitions) result.transitions.push_back(trans);
    
    // Epsilon from both NFA accepting states to new accept
    for (int accept : nfa1.accepting_states) {
        result.addTransition(accept, new_accept, '\0', true);
    }
    for (int accept : nfa2.accepting_states) {
        result.addTransition(accept, new_accept, '\0', true);
    }
    
    result.start_state = new_start;
    result.accepting_states.insert(new_accept);
    
    return result;
}

NFA RegexParser::kleeneStarNFA(const NFA& nfa) {
    NFA result;
    
    int new_start = state_counter++;
    int new_accept = state_counter++;
    
    result.addState(State(new_start, false));
    result.addState(State(new_accept, true));
    
    // Add all states from original NFA
    for (const auto& state : nfa.states) result.addState(state);
    
    // Epsilon from new start to NFA start and new accept (for zero repetitions)
    result.addTransition(new_start, nfa.start_state, '\0', true);
    result.addTransition(new_start, new_accept, '\0', true);
    
    // Add all transitions from original NFA
    for (const auto& trans : nfa.transitions) result.transitions.push_back(trans);
    
    // Epsilon from NFA accepting states to NFA start (for repetition) and new accept
    for (int accept : nfa.accepting_states) {
        result.addTransition(accept, nfa.start_state, '\0', true);
        result.addTransition(accept, new_accept, '\0', true);
    }
    
    result.start_state = new_start;
    result.accepting_states.insert(new_accept);
    
    return result;
}

int RegexParser::getPrecedence(char op) {
    switch (op) {
        case '*': case '+': case '?': return 3;
        case '.': return 2;
        case '|': return 1;
        default: return 0;
    }
}

bool RegexParser::isOperator(char c) {
    return c == '*' || c == '+' || c == '?' || c == '|' || c == '.';
}

} // namespace CS311