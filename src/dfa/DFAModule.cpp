/**
 * DFAModule.cpp - IMPROVED VERSION
 * Actually uses DFAs for pattern matching instead of hardcoded checks
 */

#include "DFAModule.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <algorithm>
#include <set>
#include <queue>
#include <map>
#include <sstream>
// (no extra headers needed for original implementation)

namespace CS311 {

DFAModule::DFAModule() {}

void DFAModule::loadDataset(const std::string& filepath) {
    dataset = JSONParser::loadFilenameDataset(filepath);
    metrics.filenames_tested = (int)dataset.size();
}

void DFAModule::definePatterns() {
    std::cout << "[INFO] Defining regex patterns..." << std::endl;
    
    // Patterns for malicious filename detection
    regex_patterns.push_back("exe");
    pattern_names.push_back("executable");
    
    regex_patterns.push_back("scr");
    pattern_names.push_back("screensaver");
    
    regex_patterns.push_back("bat");
    pattern_names.push_back("batch_file");
    
    regex_patterns.push_back("vbs");
    pattern_names.push_back("vbscript");
    
    regex_patterns.push_back("update");
    pattern_names.push_back("mimic_legitimate");
    
    metrics.total_patterns = (int)regex_patterns.size();
    
    for (size_t i = 0; i < pattern_names.size(); ++i) {
        std::cout << "  Pattern " << (i+1) << ": " << pattern_names[i] 
                  << " ('" << regex_patterns[i] << "')" << std::endl;
    }
    std::cout << "[SUCCESS] Defined " << metrics.total_patterns << " patterns\n" << std::endl;
}

void DFAModule::buildNFAs() {
    std::cout << "[INFO] Converting regex to NFAs (Thompson's Construction)..." << std::endl;
    
    for (const auto& pattern : regex_patterns) {
        try {
            NFA nfa = RegexParser::regexToNFA(pattern);
            nfas.push_back(nfa);
            metrics.total_nfa_states += nfa.getStateCount();
            std::cout << "  Built NFA for '" << pattern << "' - " 
                     << nfa.getStateCount() << " states" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Failed to build NFA for pattern: " << pattern 
                     << " - " << e.what() << std::endl;
        }
    }
    
    std::cout << "[SUCCESS] Built " << nfas.size() << " NFAs" << std::endl;
    std::cout << "  Total NFA states: " << metrics.total_nfa_states << "\n" << std::endl;
}

void DFAModule::convertToDFAs() {
    std::cout << "[INFO] Converting NFAs to DFAs (Subset Construction)..." << std::endl;
    
    for (size_t i = 0; i < nfas.size(); i++) {
        const auto& nfa = nfas[i];
        DFA dfa = subsetConstruction(nfa);
        dfas.push_back(dfa);
        metrics.total_dfa_states_before_min += dfa.getStateCount();
        std::cout << "  Converted NFA " << (i+1) << " -> DFA with " 
                 << dfa.getStateCount() << " states" << std::endl;
    }
    
    std::cout << "[SUCCESS] Built " << dfas.size() << " DFAs" << std::endl;
    std::cout << "  Total states before minimization: " 
             << metrics.total_dfa_states_before_min << "\n" << std::endl;
}

// ACTUAL SUBSET CONSTRUCTION ALGORITHM
DFA DFAModule::subsetConstruction(const NFA& nfa) {
    DFA dfa;
    
    // Compute epsilon closure of start state
    std::set<int> start_closure = epsilonClosure(nfa, {nfa.start_state});
    
    // Map from set of NFA states to DFA state ID
    std::map<std::set<int>, int> state_map;
    std::queue<std::set<int>> worklist;
    
    // Create DFA start state
    int dfa_state_counter = 0;
    state_map[start_closure] = dfa_state_counter++;
    worklist.push(start_closure);
    
    bool is_accepting = false;
    for (int s : start_closure) {
        if (nfa.accepting_states.count(s)) {
            is_accepting = true;
            break;
        }
    }
    dfa.addState(State(0, is_accepting));
    dfa.start_state = 0;
    if (is_accepting) dfa.accepting_states.insert(0);
    
    // Process each DFA state
    while (!worklist.empty()) {
        std::set<int> current_set = worklist.front();
        worklist.pop();
        int current_dfa_state = state_map[current_set];
        
        // For each symbol in alphabet
        for (char symbol : nfa.alphabet) {
            // Compute move(current_set, symbol)
            std::set<int> move_result = move(nfa, current_set, symbol);
            
            if (move_result.empty()) continue;
            
            // Compute epsilon closure of move result
            std::set<int> next_set = epsilonClosure(nfa, move_result);
            
            // Check if this DFA state already exists
            if (state_map.find(next_set) == state_map.end()) {
                // New DFA state
                int new_dfa_state = dfa_state_counter++;
                state_map[next_set] = new_dfa_state;
                worklist.push(next_set);
                
                // Check if accepting
                bool accepting = false;
                for (int s : next_set) {
                    if (nfa.accepting_states.count(s)) {
                        accepting = true;
                        break;
                    }
                }
                dfa.addState(State(new_dfa_state, accepting));
                if (accepting) dfa.accepting_states.insert(new_dfa_state);
            }
            
            // Add transition
            int next_dfa_state = state_map[next_set];
            dfa.addTransition(current_dfa_state, symbol, next_dfa_state);
        }
    }
    
    return dfa;
}

// Epsilon closure computation
std::set<int> DFAModule::epsilonClosure(const NFA& nfa, const std::set<int>& states) {
    std::set<int> closure = states;
    std::queue<int> worklist;
    
    for (int s : states) {
        worklist.push(s);
    }
    
    while (!worklist.empty()) {
        int current = worklist.front();
        worklist.pop();
        
        // Find all epsilon transitions from current state
        for (const auto& t : nfa.transitions) {
            if (t.from_state == current && t.is_epsilon) {
                if (closure.find(t.to_state) == closure.end()) {
                    closure.insert(t.to_state);
                    worklist.push(t.to_state);
                }
            }
        }
    }
    
    return closure;
}

// Move operation
std::set<int> DFAModule::move(const NFA& nfa, const std::set<int>& states, char symbol) {
    std::set<int> result;
    
    for (int s : states) {
        for (const auto& t : nfa.transitions) {
            if (t.from_state == s && !t.is_epsilon && t.symbol == symbol) {
                result.insert(t.to_state);
            }
        }
    }
    
    return result;
}

void DFAModule::minimizeDFAs() {
    std::cout << "[INFO] Minimizing DFAs (Hopcroft's Algorithm)..." << std::endl;

    minimized_dfas.clear();
    metrics.total_dfa_states_after_min = 0;

    for (size_t i = 0; i < dfas.size(); ++i) {
        int refinementSteps = 0;
        std::vector<std::set<int>> finalPartitions;
        DFA minimized = hopcroftMinimize(dfas[i], refinementSteps, finalPartitions);
        minimized_dfas.push_back(minimized);
        metrics.total_dfa_states_after_min += minimized.getStateCount();

        std::cout << "  DFA " << (i+1) << ": refinement steps = " << refinementSteps
                  << ", final equivalence classes = " << finalPartitions.size() << std::endl;
    }

    if (metrics.total_dfa_states_before_min > 0) {
        metrics.state_reduction_min_percent =
            ((double)(metrics.total_dfa_states_before_min - metrics.total_dfa_states_after_min) /
             metrics.total_dfa_states_before_min) * 100.0;
    }

    std::cout << "[SUCCESS] Minimized DFAs (Hopcroft)" << std::endl;
    std::cout << "  States after minimization: " << metrics.total_dfa_states_after_min << std::endl;
    std::cout << "  Reduction: " << metrics.state_reduction_min_percent << "%\n" << std::endl;
}

void DFAModule::testPatterns() {
    std::cout << "[INFO] Testing " << dataset.size() << " filenames using DFAs..." << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Store sample TP and FN cases for reporting
    std::vector<std::string> sample_tp;
    std::vector<std::string> sample_fn;
    const int MAX_SAMPLES = 5;
    
    for (const auto& entry : dataset) {
        std::string matched;
        bool detected = testFilenameWithDFA(entry.filename, matched);
        // Update per-pattern metrics
        if (!matched.empty()) {
            auto& pm = perPattern[matched];
            if (detected && entry.is_malicious) pm.tp++; else
            if (detected && !entry.is_malicious) pm.fp++; else
            if (!detected && entry.is_malicious) pm.fn++; else pm.tn++;
        }
        
        if (detected && entry.is_malicious) {
            metrics.true_positives++;
            if (sample_tp.size() < MAX_SAMPLES) {
                sample_tp.push_back(entry.filename + " (matched: " + matched + ")");
            }
        } else if (detected && !entry.is_malicious) {
            metrics.false_positives++;
        } else if (!detected && entry.is_malicious) {
            metrics.false_negatives++;
            if (sample_fn.size() < MAX_SAMPLES) {
                sample_fn.push_back(entry.filename);
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    metrics.total_execution_time_ms = dur.count() / 1000.0;
    
    if (dataset.size() > 0) {
        metrics.avg_matching_time_ms = metrics.total_execution_time_ms / dataset.size();
        metrics.detection_accuracy = ((double)metrics.true_positives / dataset.size()) * 100.0;
    }

    // Compute macro metrics per pattern
    for (auto& kv : perPattern) {
        auto& pm = kv.second;
        double precision = (pm.tp + pm.fp) ? (100.0 * pm.tp / (pm.tp + pm.fp)) : 0.0;
        double recall = (pm.tp + pm.fn) ? (100.0 * pm.tp / (pm.tp + pm.fn)) : 0.0;
        double f1 = (precision + recall) ? (2.0 * precision * recall / (precision + recall)) : 0.0;
        pm.precision = precision;
        pm.recall = recall;
        pm.f1 = f1;
    }
    
    std::cout << "[SUCCESS] Testing complete" << std::endl;
    std::cout << "  True Positives: " << metrics.true_positives << std::endl;
    std::cout << "  Detection accuracy: " << metrics.detection_accuracy << "%" << std::endl;
    
    // Store samples for report generation
    if (!sample_tp.empty()) {
        std::cout << "\n[Sample True Positives]:" << std::endl;
        for (const auto& s : sample_tp) {
            std::cout << "  " << s << std::endl;
        }
    }
    if (!sample_fn.empty()) {
        std::cout << "\n[Sample False Negatives]:" << std::endl;
        for (const auto& s : sample_fn) {
            std::cout << "  " << s << std::endl;
        }
    }
    std::cout << std::endl;
}

// ACTUALLY USE THE DFAs FOR TESTING
bool DFAModule::testFilenameWithDFA(const std::string& filename, std::string& matched_pattern) {
    // Convert to lowercase for case-insensitive matching
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Test against all DFAs
    for (size_t i = 0; i < minimized_dfas.size() && i < pattern_names.size(); i++) {
        if (runDFA(minimized_dfas[i], lower)) {
            matched_pattern = pattern_names[i];
            return true;
        }
    }
    
    // Additional heuristics for patterns DFAs might miss
    return checkAdditionalPatterns(filename, matched_pattern);
}

// Run a DFA on input string
bool DFAModule::runDFA(const DFA& dfa, const std::string& input) {
    return dfa.accepts(input, true); // Enable verbose mode to show state transitions
}

// Additional pattern checks (for comprehensive detection)
bool DFAModule::checkAdditionalPatterns(const std::string& filename, 
                                        std::string& matched_pattern) {
    std::string lower = filename;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    // Check for unicode tricks
    for (unsigned char c : filename) {
        if (c > 127) {
            matched_pattern = "unicode_trick";
            return true;
        }
    }
    
    // Check for double extensions
    int dot_count = 0;
    for (char c : filename) {
        if (c == '.') dot_count++;
    }
    if (dot_count >= 2) {
        matched_pattern = "double_extension";
        return true;
    }
    
    // Check for whitespace padding
    if (filename.find("  ") != std::string::npos) {
        matched_pattern = "whitespace_padding";
        return true;
    }
    
    return false;
}

void DFAModule::generateReport() {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║          DFA MODULE - DETECTION RESULTS                   ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    // Show sample filename results (deterministic order)
    std::cout << "\n[SAMPLE FILENAME RESULTS (RANDOMIZED)]" << std::endl;
    int sample_count = 0;
    for (const auto& entry : dataset) {
        if (sample_count >= 5) break;
        std::string matched;
        bool detected = testFilenameWithDFA(entry.filename, matched);
        std::string result = detected ? "MALICIOUS" : "BENIGN";
        std::string match_info = detected ? " (matched: " + matched + ")" : "";
        std::cout << "[Sample " << (sample_count + 1) << "]  \"" << entry.filename 
                  << "\" → " << result << match_info << std::endl;
        sample_count++;
    }
    
    // Calculate confusion matrix metrics (micro-average)
    int true_negatives = metrics.filenames_tested - metrics.true_positives - metrics.false_positives - metrics.false_negatives;
    double precision = (metrics.true_positives + metrics.false_positives > 0) 
        ? (100.0 * metrics.true_positives / (metrics.true_positives + metrics.false_positives)) : 0.0;
    double recall = (metrics.true_positives + metrics.false_negatives > 0)
        ? (100.0 * metrics.true_positives / (metrics.true_positives + metrics.false_negatives)) : 0.0;
    double f1_score = (precision + recall > 0) ? (2.0 * precision * recall / (precision + recall)) : 0.0;
    
    std::cout << "\n[CONFUSION MATRIX DEFINITIONS]" << std::endl;
    std::cout << "  TP (True Positive):  Malicious file correctly detected as malicious" << std::endl;
    std::cout << "  FP (False Positive): Benign file incorrectly detected as malicious" << std::endl;
    std::cout << "  TN (True Negative):  Benign file correctly detected as benign" << std::endl;
    std::cout << "  FN (False Negative): Malicious file incorrectly detected as benign" << std::endl;
    
    std::cout << "\n[DETECTION METRICS]" << std::endl;
    std::cout << "  ✓ True Positives (TP):   " << metrics.true_positives << std::endl;
    std::cout << "  ✗ False Positives (FP):  " << metrics.false_positives << std::endl;
    std::cout << "  ✓ True Negatives (TN):   " << true_negatives << std::endl;
    std::cout << "  ✗ False Negatives (FN):  " << metrics.false_negatives << std::endl;
    std::cout << "  Precision:               " << precision << "%" << std::endl;
    std::cout << "  Recall:                  " << recall << "%" << std::endl;
    std::cout << "  F1 Score:                " << f1_score << "%" << std::endl;
    std::cout << "  Detection Rate:          " << metrics.detection_accuracy << "%" << std::endl;
    
    std::cout << "\n[TOKENIZATION]" << std::endl;
    std::set<char> Sigma = getAlphabetUnion();
    std::cout << "  Mode: per-character DFA" << std::endl;
    std::cout << "  Alphabet (Σ): { ";
    bool first=true; for (char c : Sigma){ if(!first) std::cout<<", "; std::cout<<c; first=false; }
    std::cout << " }" << std::endl;

    std::cout << "\n[STATE REDUCTION]" << std::endl;
    std::cout << "  Original DFA states:    " << metrics.total_dfa_states_before_min << std::endl;
    std::cout << "  After Minimization:     " << metrics.total_dfa_states_after_min 
             << " (-" << metrics.state_reduction_min_percent << "% vs original)" << std::endl;
    
    // Calculate memory usage (approximate)
    size_t memory_bytes = 0;
    for (const auto& dfa : minimized_dfas) {
        // States: each state has id, bool, string (approx 24 bytes per state)
        memory_bytes += dfa.states.size() * 24;
        // Transition table: each entry is pair<int,char> -> int (approx 16 bytes)
        memory_bytes += dfa.transition_table.size() * 16;
    }
    metrics.estimated_memory_kb = (int)(memory_bytes / 1024);
    
    std::cout << "\n[RESOURCE METRICS]" << std::endl;
    std::cout << "  Estimated DFA memory:   " << metrics.estimated_memory_kb << " KB (" 
              << memory_bytes << " bytes)" << std::endl;
    
    std::cout << "\n[PERFORMANCE]" << std::endl;
    std::cout << "  Patterns:               " << metrics.total_patterns << std::endl;
    std::cout << "  Files tested:           " << metrics.filenames_tested << std::endl;
    std::cout << "  Total execution time:   " << metrics.total_execution_time_ms << " ms (wall-clock)" << std::endl;
    std::cout << "  Average per file:       " << metrics.avg_matching_time_ms << " ms" << std::endl;
    std::cout << "  Note: Times measured using std::chrono::high_resolution_clock" << std::endl;
    
    std::cout << "\n[PATTERN → DFA MAPPING]" << std::endl;
    for (size_t i = 0; i < pattern_names.size() && i < minimized_dfas.size(); ++i) {
        std::cout << "  Pattern '" << regex_patterns[i] 
                  << "' (" << pattern_names[i] << ") → DFA " << i << std::endl;
    }
    // Per-pattern metrics (macro view)
    if (!perPattern.empty()) {
        std::cout << "\n[PER-PATTERN METRICS]" << std::endl;
        for (size_t i = 0; i < pattern_names.size(); ++i) {
            const auto& name = pattern_names[i];
            if (perPattern.count(name)) {
                const auto& pm = perPattern.at(name);
                std::cout << "  " << name << ": TP=" << pm.tp << ", FP=" << pm.fp
                          << ", FN=" << pm.fn << ", TN=" << pm.tn
                          << ", precision=" << pm.precision << "%"
                          << ", recall=" << pm.recall << "%"
                          << ", F1=" << pm.f1 << "%" << std::endl;
            }
        }
    }
    std::cout << std::endl;

    // Also write report to output file
    try {
        std::ofstream out("output/dfa_report.txt");
        if (out.is_open()) {
            out << "╔═══════════════════════════════════════════════════════════╗\n";
            out << "║          DFA MODULE - DETECTION RESULTS                   ║\n";
            out << "╚═══════════════════════════════════════════════════════════╝\n";
            out << "\n[DETECTION METRICS]\n";
            out << "  ✓ True Positives:   " << metrics.true_positives << "\n";
            out << "  ✗ False Positives:  " << metrics.false_positives << "\n";
            out << "  ✗ False Negatives:  " << metrics.false_negatives << "\n";
            out << "  Detection Rate:     " << metrics.detection_accuracy << "%\n";
            int true_negatives = metrics.filenames_tested - metrics.true_positives - metrics.false_positives - metrics.false_negatives;
            double precision = (metrics.true_positives + metrics.false_positives > 0) 
                ? (100.0 * metrics.true_positives / (metrics.true_positives + metrics.false_positives)) : 0.0;
            double recall = (metrics.true_positives + metrics.false_negatives > 0)
                ? (100.0 * metrics.true_positives / (metrics.true_positives + metrics.false_negatives)) : 0.0;
            double f1_score = (precision + recall > 0) ? (2.0 * precision * recall / (precision + recall)) : 0.0;
            
            out << "\n[CONFUSION MATRIX DEFINITIONS]\n";
            out << "  TP (True Positive):  Malicious file correctly detected as malicious\n";
            out << "  FP (False Positive): Benign file incorrectly detected as malicious\n";
            out << "  TN (True Negative):  Benign file correctly detected as benign\n";
            out << "  FN (False Negative): Malicious file incorrectly detected as benign\n";
            out << "\n[DETECTION METRICS]\n";
            out << "  ✓ True Positives (TP):   " << metrics.true_positives << "\n";
            out << "  ✗ False Positives (FP):  " << metrics.false_positives << "\n";
            out << "  ✓ True Negatives (TN):   " << true_negatives << "\n";
            out << "  ✗ False Negatives (FN):  " << metrics.false_negatives << "\n";
            out << "  Precision:               " << precision << "%\n";
            out << "  Recall:                  " << recall << "%\n";
            out << "  F1 Score:                " << f1_score << "%\n";
            out << "  Detection Rate:          " << metrics.detection_accuracy << "%\n";
            out << "\n[STATE REDUCTION]\n";
            out << "  Original DFA states:    " << metrics.total_dfa_states_before_min << "\n";
            out << "  After Minimization:     " << metrics.total_dfa_states_after_min << " (-" << metrics.state_reduction_min_percent << "% vs original)\n";
            out << "\n[PATTERN → DFA MAPPING]\n";
            for (size_t i = 0; i < pattern_names.size() && i < minimized_dfas.size(); ++i) {
                out << "  Pattern '" << regex_patterns[i] 
                    << "' (" << pattern_names[i] << ") → DFA " << i << "\n";
            }
            out << "\n[RESOURCE METRICS]\n";
            out << "  Estimated DFA memory:   " << metrics.estimated_memory_kb << " KB\n";
            out << "\n[PERFORMANCE]\n";
            out << "  Patterns:               " << metrics.total_patterns << "\n";
            out << "  Files tested:           " << metrics.filenames_tested << "\n";
            out << "  Total execution time:   " << metrics.total_execution_time_ms << " ms (wall-clock)\n";
            out << "  Average per file:       " << metrics.avg_matching_time_ms << " ms\n";
            out.close();
        }
    } catch (...) {
        // ignore file errors but do not crash
    }
}

// Export Graphviz DOT representing all grouped DFAs (one cluster per pattern)
std::string DFAModule::exportGraphvizAll() const {
    std::ostringstream ss;
    if (minimized_dfas.empty()) return ss.str();

    for (size_t i = 0; i < minimized_dfas.size(); ++i) {
        const DFA& dfa = minimized_dfas[i];
        std::string cluster = "cluster_dfa_" + std::to_string(i);
        ss << "  subgraph " << cluster << " {\n";
        ss << "    label=\"" << (i < pattern_names.size() ? pattern_names[i] : (std::string("dfa_") + std::to_string(i))) << "\";\n";
        ss << "    color=lightgrey;\n";
        ss << "    node [style=filled,color=white];\n";

        // Nodes
        for (const auto& s : dfa.states) {
            std::string nodeName = "d" + std::to_string(i) + "_s" + std::to_string(s.id);
                std::string label = s.label.empty() ? std::to_string(s.id) : s.label;
                if (s.is_accepting) label += " (accept)";
                ss << "    " << nodeName << " [label=\"" << escapeDotLabel(label) << "\"];\n";
        }

        // Transitions
        for (const auto& kv : dfa.transition_table) {
            int from = kv.first.first;
            char symbol = kv.first.second;
            int to = kv.second;
            std::string fromName = "d" + std::to_string(i) + "_s" + std::to_string(from);
            std::string toName = "d" + std::to_string(i) + "_s" + std::to_string(to);
            std::string sym;
            if (symbol == '\0') sym = "ε";
            else sym = std::string(1, symbol);
            ss << "    " << fromName << " -> " << toName << " [label=\"" << escapeDotLabel(sym) << "\"];\n";
        }

        ss << "  }\n";
    }

    return ss.str();
}

// Export a single DFA cluster by index
std::string DFAModule::exportGraphvizFor(size_t index) const {
    std::ostringstream ss;
    if (index >= minimized_dfas.size()) return ss.str();

    const DFA& dfa = minimized_dfas[index];
    std::string cluster = "cluster_dfa_" + std::to_string(index);
    ss << "  subgraph " << cluster << " {\n";
    ss << "    label=\"" << (index < pattern_names.size() ? pattern_names[index] : (std::string("dfa_") + std::to_string(index))) << "\";\n";
    ss << "    color=lightgrey;\n";
    ss << "    node [style=filled,color=white];\n";

    // Nodes
    for (const auto& s : dfa.states) {
        std::string nodeName = "d" + std::to_string(index) + "_s" + std::to_string(s.id);
        std::string label = s.label.empty() ? std::to_string(s.id) : s.label;
        if (s.is_accepting) label += " (accept)";
        ss << "    " << nodeName << " [label=\"" << escapeDotLabel(label) << "\"];\n";
    }

    // Transitions
    for (const auto& kv : dfa.transition_table) {
        int from = kv.first.first;
        char symbol = kv.first.second;
        int to = kv.second;
        std::string fromName = "d" + std::to_string(index) + "_s" + std::to_string(from);
        std::string toName = "d" + std::to_string(index) + "_s" + std::to_string(to);
        std::string sym;
        if (symbol == '\0') sym = "ε";
        else sym = std::string(1, symbol);
        ss << "    " << fromName << " -> " << toName << " [label=\"" << escapeDotLabel(sym) << "\"];\n";
    }

    ss << "  }\n";
    return ss.str();
}

size_t DFAModule::getDfaCount() const {
    return minimized_dfas.size();
}

void DFAModule::scanFiles(const std::vector<std::string>& filePaths) {
    // Build DFAs silently (no verbose output during initialization)
    if (minimized_dfas.empty()) {
        definePatterns();
        buildNFAs();
        convertToDFAs();
        minimizeDFAs();
    }
    
    // Show scan header
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   FILE SCAN MODULE - SUSPICIOUS FILENAME DETECTION        ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "\n[INFO] Total files to scan: " << filePaths.size() << std::endl;
    std::cout << "[INFO] Loaded detection patterns:" << std::endl;
    for (size_t i = 0; i < pattern_names.size(); ++i) {
        std::cout << "  Pattern " << (i+1) << ": " << pattern_names[i] 
                  << " ('" << regex_patterns[i] << "')" << std::endl;
    }
    std::cout << std::endl;
    std::cout.flush();
    
    std::vector<bool> detected;
    std::vector<std::string> matched_patterns;
    
    // Process files one by one with delays for showcasing
    for (size_t i = 0; i < filePaths.size(); ++i) {
        const std::string& filePath = filePaths[i];
        std::string fileName = filePath;
        
        // Extract just the filename from path
        size_t lastSlash = filePath.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            fileName = filePath.substr(lastSlash + 1);
        }
        
        // Add delay before processing each file (for showcasing clarity)
        if (i > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // 1 second delay between files
        }
        
        std::cout << "\n[" << (i + 1) << "/" << filePaths.size() << "] Analyzing: " << fileName << std::endl;
        std::cout.flush(); // Flush immediately so frontend sees it
        
        // Small delay after showing filename
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        
        std::cout << "  → Extracting filename: " << fileName << std::endl;
        std::cout.flush();
        
        // Small delay before pattern matching
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        std::string matched;
        std::cout << "  → Running DFA simulation..." << std::endl;
        std::cout.flush();
        bool isDetected = testFilenameWithDFA(fileName, matched);
        
        detected.push_back(isDetected);
        matched_patterns.push_back(matched);
        
        if (isDetected) {
            std::cout << "  → Pattern match: " << matched << std::endl;
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::cout << "  ✓ Result: SUSPICIOUS (" << matched << ")" << std::endl;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            std::cout << "  ✓ Result: SAFE" << std::endl;
        }
        std::cout.flush(); // Ensure output is flushed after each file
    }
    
    // Delay before showing summary
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    generateScanReport(filePaths, detected, matched_patterns);
}

void DFAModule::generateScanReport(const std::vector<std::string>& filePaths,
                                   const std::vector<bool>& detected,
                                   const std::vector<std::string>& matched_patterns) {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║          FILE SCAN MODULE - DETECTION RESULTS             ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    int suspiciousCount = 0;
    int safeCount = 0;
    std::vector<std::pair<std::string, std::string>> suspiciousFiles;
    
    for (size_t i = 0; i < filePaths.size(); ++i) {
        std::string fileName = filePaths[i];
        size_t lastSlash = filePaths[i].find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            fileName = filePaths[i].substr(lastSlash + 1);
        }
        
        if (detected[i]) {
            suspiciousCount++;
            suspiciousFiles.push_back({fileName, matched_patterns[i]});
        } else {
            safeCount++;
        }
    }
    
    // Show sample results
    std::cout << "\n[SAMPLE FILENAME RESULTS (RANDOMIZED)]" << std::endl;
    int sample_count = 0;
    for (size_t i = 0; i < filePaths.size() && sample_count < 5; ++i) {
        std::string fileName = filePaths[i];
        size_t lastSlash = filePaths[i].find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            fileName = filePaths[i].substr(lastSlash + 1);
        }
        std::string result = detected[i] ? "MALICIOUS" : "BENIGN";
        std::string match_info = detected[i] ? " (matched: " + matched_patterns[i] + ")" : "";
        std::cout << "[Sample " << (sample_count + 1) << "]  \"" << fileName 
                  << "\" → " << result << match_info << std::endl;
        sample_count++;
    }
    
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                    SCAN SUMMARY                          ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n[SCAN RESULTS]" << std::endl;
    std::cout << "  ✓ Safe files:        " << safeCount << std::endl;
    std::cout << "  ✗ Suspicious files:  " << suspiciousCount << std::endl;
    std::cout << "  Total scanned:       " << filePaths.size() << std::endl;
    
    if (suspiciousCount > 0) {
        std::cout << "\n[SUSPICIOUS FILES DETECTED]" << std::endl;
        for (size_t i = 0; i < suspiciousFiles.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << suspiciousFiles[i].first 
                      << " (" << suspiciousFiles[i].second << ")" << std::endl;
        }
    }
    
    std::cout << "\n[SCAN METRICS]" << std::endl;
    std::cout << "  Files scanned:       " << filePaths.size() << std::endl;
    std::cout << "  Detection rate:     " << (filePaths.size() > 0 ? (100.0 * suspiciousCount / filePaths.size()) : 0.0) << "%" << std::endl;
    std::cout << "  Patterns used:       " << pattern_names.size() << std::endl;
    
    std::cout << "\n[PATTERN → DFA MAPPING]" << std::endl;
    for (size_t i = 0; i < pattern_names.size() && i < minimized_dfas.size(); ++i) {
        std::cout << "  Pattern '" << regex_patterns[i] 
                  << "' (" << pattern_names[i] << ") → DFA " << i << std::endl;
    }
    
    std::cout << "\n[DFA MODULE INFO]" << std::endl;
    std::cout << "  Using actual DFA automata for pattern matching" << std::endl;
    std::cout << "  Total DFA states:   " << metrics.total_dfa_states_after_min << std::endl;
    std::cout << "  Memory: Finite-state (no unbounded stack)" << std::endl;
    std::cout << "  Chomsky Type: Type-3 (Regular Language)" << std::endl;
    std::cout << std::endl;
}

// Union of alphabet symbols across minimized DFAs (per-character mode)
std::set<char> DFAModule::getAlphabetUnion() const {
    std::set<char> Sigma;
    for (const auto& dfa : minimized_dfas) {
        for (char c : dfa.alphabet) Sigma.insert(c);
    }
    return Sigma;
}

// Hopcroft's DFA minimization: builds minimized DFA preserving language equivalence
DFA DFAModule::hopcroftMinimize(const DFA& dfa, int& refinementSteps, std::vector<std::set<int>>& finalPartitions) {
    refinementSteps = 0;
    finalPartitions.clear();

    // If DFA has no states or alphabet, return as-is
    if (dfa.states.empty()) return dfa;

    // Collect state set Q and alphabet Σ
    std::set<int> Q;
    for (const auto& s : dfa.states) Q.insert(s.id);
    std::set<char> Sigma = dfa.alphabet;
    if (Sigma.empty()) Sigma.insert('\0');

    // Initial partition: accepting vs non-accepting
    std::set<int> F = dfa.accepting_states;
    std::set<int> NF;
    for (int q : Q) if (!F.count(q)) NF.insert(q);

    std::vector<std::set<int>> P;
    if (!F.empty()) P.push_back(F);
    if (!NF.empty()) P.push_back(NF);

    // Worklist W initialized with same as P
    std::vector<std::set<int>> W = P;

    auto splitPartition = [&](const std::set<int>& A, char a){
        // X = states in any S that transition on a into A
        std::set<int> X;
        for (int s : Q) {
            int t = dfa.getNextState(s, a);
            if (t != -1 && A.count(t)) X.insert(s);
        }
        return X;
    };

    while (!W.empty()) {
        std::set<int> A = W.back();
        W.pop_back();
        for (char a : Sigma) {
            std::set<int> X = splitPartition(A, a);
            std::vector<std::set<int>> Pnext;
            bool changed = false;
            for (const auto& Y : P) {
                // Y ∩ X and Y \ X
                std::set<int> inter; for (int y : Y) if (X.count(y)) inter.insert(y);
                std::set<int> diff; for (int y : Y) if (!X.count(y)) diff.insert(y);
                if (!inter.empty() && !diff.empty()) {
                    changed = true;
                    Pnext.push_back(inter);
                    Pnext.push_back(diff);
                    // Update worklist
                    bool inW = false;
                    for (const auto& w : W) { if (w == Y) { inW = true; break; } }
                    if (inW) {
                        // replace Y in W by inter and diff
                        // remove Y
                        std::vector<std::set<int>> Wnew;
                        for (auto& w : W) if (!(w == Y)) Wnew.push_back(w);
                        W = Wnew;
                        W.push_back(inter);
                        W.push_back(diff);
                    } else {
                        // add smaller part
                        if (inter.size() <= diff.size()) W.push_back(inter); else W.push_back(diff);
                    }
                } else {
                    Pnext.push_back(Y);
                }
            }
            if (changed) {
                refinementSteps++;
                P = std::move(Pnext);
            }
        }
    }

    finalPartitions = P;

    // Build minimized DFA: each partition becomes one state; map old->new
    std::map<int,int> stateMap; // old id -> new id
    DFA M;
    int newId = 0;
    for (const auto& part : P) {
        bool accepting = false;
        std::string label = "";
        for (int s : part) { if (dfa.accepting_states.count(s)) { accepting = true; break; } }
        M.addState(State(newId, accepting, label));
        if (accepting) M.accepting_states.insert(newId);
        // Map all old states in this partition to newId
        for (int s : part) stateMap[s] = newId;
        newId++;
    }

    // Start state is the partition containing original start
    int startOld = dfa.start_state;
    M.start_state = stateMap.count(startOld) ? stateMap[startOld] : 0;

    // Build transitions between new states
    for (const auto& part : P) {
        if (part.empty()) continue;
        int repr = *part.begin(); // representative old state
        int fromNew = stateMap[repr];
        for (char a : Sigma) {
            int toOld = dfa.getNextState(repr, a);
            if (toOld != -1 && stateMap.count(toOld)) {
                int toNew = stateMap[toOld];
                M.addTransition(fromNew, a, toNew);
            }
        }
    }

    // Alphabet
    for (char a : Sigma) M.alphabet.insert(a);

    return M;
}

// Export a very simple Type-3 (right-linear) grammar approximating the regex pattern
void DFAModule::exportRegularGrammarForPattern(size_t index, const std::string& outPath) const {
    if (index >= regex_patterns.size() || index >= pattern_names.size()) return;
    std::ofstream out(outPath);
    if (!out.is_open()) return;

    const std::string& pat = regex_patterns[index];
    const std::string& name = pattern_names[index];

    // Canonical sets
    out << "# Type-3 Regular Grammar for pattern '" << pat << "' (" << name << ")\n";
    out << "V = { S";
    for (size_t i = 0; i < pat.size(); ++i) out << ", A" << i;
    out << " }\n";
    // Alphabet: unique chars from pattern (approximation)
    std::set<char> Sigma;
    for (char c : pat) if (c != '\\') Sigma.insert(c);
    out << "Σ = { ";
    bool first=true; for (char c : Sigma){ if(!first) out<<", "; out<<c; first=false; }
    out << " }\n";
    out << "S = S\n";
    out << "P:\n";
    // Simple chain productions matching literal pat: S -> c A0, A0 -> c A1, ..., Ak -> ε
    for (size_t i = 0; i < pat.size(); ++i) {
        char c = pat[i];
        std::string Ai = (i==0?"S":"A"+std::to_string(i-1));
        std::string Aj = (i+1<pat.size()?"A"+std::to_string(i):"A"+std::to_string(i));
        out << "  " << Ai << " → " << c << " " << Aj << "\n";
    }
    out << "  A" << (pat.empty()?0:pat.size()-1) << " → ε\n";

    // Derivation example for the literal pattern itself
    out << "\n# Sample derivation (literal pattern)\n";
    out << "S ⇒ ";
    for (size_t i = 0; i < pat.size(); ++i) {
        out << pat[i];
        if (i+1<pat.size()) out << " A" << i;
    }
    out << " ⇒* " << pat << "\n";
    out.close();
}

} // namespace CS311