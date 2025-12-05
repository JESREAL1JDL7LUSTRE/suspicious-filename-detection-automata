/**
 * File: Utils.h
 * Purpose: Core data structures for automata and dataset entries
 */

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <set>
#include <map>
#include <stack>
#include <utility>
#include <iostream>

namespace CS311 {

struct State {
    int id;
    bool is_accepting;
    std::string label;
    State() : id(-1), is_accepting(false), label("") {}
    State(int id, bool accepting = false, std::string lbl = "")
        : id(id), is_accepting(accepting), label(lbl) {}
};

struct Transition {
    int from_state;
    int to_state;
    char symbol;
    bool is_epsilon;
    Transition(int from, int to, char sym, bool epsilon = false)
        : from_state(from), to_state(to), symbol(sym), is_epsilon(epsilon) {}
};

struct NFA {
    std::vector<State> states;
    std::vector<Transition> transitions;
    int start_state;
    std::set<int> accepting_states;
    std::set<char> alphabet;
    NFA() : start_state(0) {}
    void addState(const State& state) { states.push_back(state); }
    void addTransition(int from, int to, char symbol, bool epsilon = false) {
        transitions.push_back(Transition(from, to, symbol, epsilon));
        if (!epsilon && symbol != '\0') alphabet.insert(symbol);
    }
    int getStateCount() const { return states.size(); }
};

struct DFA {
    std::vector<State> states;
    std::map<std::pair<int, char>, int> transition_table;
    int start_state;
    std::set<int> accepting_states;
    std::set<char> alphabet;
    DFA() : start_state(0) {}
    void addState(const State& state) { states.push_back(state); }
    void addTransition(int from, char symbol, int to) { transition_table[{from, symbol}] = to; alphabet.insert(symbol); }
    int getNextState(int current, char symbol) const {
        auto it = transition_table.find({current, symbol});
        return (it != transition_table.end()) ? it->second : -1;
    }
    int getStateCount() const { return states.size(); }
    bool accepts(const std::string& input, bool verbose = false) const {
        int current = start_state;
        int prev_state = start_state;
        
        // SOUNDNESS CHECK: Verify start_state is valid
        if (start_state < 0 || start_state >= (int)states.size()) {
            std::cerr << "[INVARIANT VIOLATION] Invalid start state: " << start_state 
                     << " (valid range: 0-" << (states.size()-1) << ")" << std::endl;
            return false;
        }
        
        for (char c : input) {
            prev_state = current;
            current = getNextState(current, c);
            
            // SOUNDNESS CHECK: Verify current state is in Q (set of states)
            if (current != -1) {
                bool state_exists = false;
                for (const auto& s : states) {
                    if (s.id == current) {
                        state_exists = true;
                        break;
                    }
                }
                if (!state_exists) {
                    std::cerr << "[INVARIANT VIOLATION] Current state " << current 
                             << " not in Q. Valid states: ";
                    for (const auto& s : states) {
                        std::cerr << s.id << " ";
                    }
                    std::cerr << std::endl;
                    return false;
                }
            }
            
            if (verbose && prev_state != -1) {
                std::cout << "  State: q" << prev_state << " → q" << current << " (symbol: '" << c << "')" << std::endl;
                std::cout.flush(); // Flush immediately so frontend receives it in real-time
            }
            if (current == -1) {
                std::cerr << "[INVARIANT FAIL][DFA] Undefined transition from q" << prev_state
                          << " on '" << c << "'" << std::endl;
                return false;
            }
        }
        if (verbose && current != -1) {
            std::cout << "  Final state: q" << current << std::endl;
            std::cout.flush(); // Flush immediately so frontend receives it in real-time
        }
        return accepting_states.count(current) > 0;
    }
};

struct PDA {
    std::vector<State> states;
    std::stack<std::string> pda_stack;
    int current_state;
    int start_state;
    std::set<int> accepting_states;
    PDA() : current_state(0), start_state(0) { pda_stack.push("BOTTOM"); }
    void reset() { current_state = start_state; while (!pda_stack.empty()) pda_stack.pop(); pda_stack.push("BOTTOM"); }
    void push(const std::string& symbol) { pda_stack.push(symbol); }
    std::string pop() { if (pda_stack.size() > 1) { std::string top = pda_stack.top(); pda_stack.pop(); return top; } return ""; }
    std::string peek() const { return pda_stack.empty() ? "" : pda_stack.top(); }
    bool isAccepting() const { return accepting_states.count(current_state) > 0 && pda_stack.size() == 1; }
    int getStackDepth() const { return (int)pda_stack.size() - 1; }
};

struct FilenameEntry {
    std::string filename;
    std::string technique;
    std::string category;
    std::string detected_by;
    bool is_malicious;
    FilenameEntry() : is_malicious(true) {}
};

struct TCPTrace {
    std::string trace_id;
    std::vector<std::string> sequence;
    bool valid;
    std::string description;
    std::string category;
    TCPTrace() : valid(false) {}
};

struct DFAMetrics {
    int total_patterns;
    int total_nfa_states;
    int total_dfa_states_before_min;
    int total_dfa_states_after_min;
    double state_reduction_min_percent;
    int filenames_tested;
    int true_positives;
    int false_positives;
    int false_negatives;
    double detection_accuracy;
    double avg_matching_time_ms;
    double total_execution_time_ms;
    int estimated_memory_kb;
    DFAMetrics() : total_patterns(0), total_nfa_states(0), total_dfa_states_before_min(0), total_dfa_states_after_min(0), state_reduction_min_percent(0), filenames_tested(0), true_positives(0), false_positives(0), false_negatives(0), detection_accuracy(0), avg_matching_time_ms(0), total_execution_time_ms(0), estimated_memory_kb(0) {}
};

struct PDAMetrics {
    int total_traces;
    int valid_traces;
    int invalid_traces;
    int correctly_accepted;
    int correctly_rejected;
    int false_positives;
    int false_negatives;
    double validation_accuracy;
    double avg_stack_depth;
    int max_stack_depth;
    double avg_validation_time_ms;
    double total_execution_time_ms;
    PDAMetrics() : total_traces(0), valid_traces(0), invalid_traces(0), correctly_accepted(0), correctly_rejected(0), false_positives(0), false_negatives(0), validation_accuracy(0), avg_stack_depth(0), max_stack_depth(0), avg_validation_time_ms(0), total_execution_time_ms(0) {}
};

inline void printSeparator(int length = 60) { std::cout << std::string(length, '=') << std::endl; }
inline void printHeader(const std::string& title) {
    std::cout << "\n";
    std::cout << "+-" << std::string(title.length() + 2, '-') << "-+" << std::endl;
    std::cout << "| " << title << " |" << std::endl;
    std::cout << "+-" << std::string(title.length() + 2, '-') << "-+" << std::endl;
    std::cout << std::endl;
}

// Escape a string for safe inclusion inside DOT label="..." fields.
// Replaces backslash with "\\" and double-quote with "\"" so Graphviz parses correctly.
inline std::string escapeDotLabel(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\') {
            out += "\\\\"; // becomes two backslashes in DOT source
        } else if (c == '"') {
            out += "\\\""; // escaped double-quote
        } else {
            out.push_back(c);
        }
    }
    return out;
}

} // namespace CS311

#endif // UTILS_H
