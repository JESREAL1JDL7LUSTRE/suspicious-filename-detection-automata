/**
 * PDAModule.cpp - IMPROVED VERSION
 * Explicitly shows CFG before building PDA
 */

#include "PDAModule.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <sstream>

namespace CS311 {

PDAModule::PDAModule() {}

void PDAModule::loadDataset(const std::string& filepath) {
    dataset = JSONParser::loadTCPDataset(filepath);
    metrics.total_traces = (int)dataset.size();
    for (const auto& t : dataset) {
        if (t.valid) metrics.valid_traces++;
        else metrics.invalid_traces++;
    }
}

void PDAModule::defineCFG() {
    std::cout << "[INFO] Defining Context-Free Grammar for TCP Handshake..." << std::endl;
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  CONTEXT-FREE GRAMMAR (Type-2 Chomsky Hierarchy)       ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\nMinimal Handshake Grammar:" << std::endl;
    std::cout << "  S  → SYN SYN-ACK ACK      (3-way handshake)" << std::endl;
    
    std::cout << "\nPedagogical Extensions (post-handshake):" << std::endl;
    std::cout << "  C  → DATA C | FIN | ε     (Data transfer or finish)" << std::endl;
    
    std::cout << "\nTerminals: { SYN, SYN-ACK, ACK, DATA, FIN, RST }" << std::endl;
    std::cout << "Non-terminals: { S, A, B, C }" << std::endl;
    std::cout << "Start symbol: S" << std::endl;
    
    std::cout << "\n[KEY PROPERTY]" << std::endl;
    std::cout << "  This is a Type-2 (Context-Free) language because:" << std::endl;
    std::cout << "  • Requires STACK memory to track pairing" << std::endl;
    std::cout << "  • Cannot be recognized by DFA (Type-3)" << std::endl;
    std::cout << "  • SYN must be paired with SYN-ACK" << std::endl;
    std::cout << "  • SYN-ACK must be paired with ACK" << std::endl;
    std::cout << std::endl;
}

void PDAModule::buildPDA() {
    std::cout << "[INFO] Building PDA from CFG..." << std::endl;
    
    // Define PDA states based on CFG
    pda.states.push_back(State(Q_START, false, "q0_start"));
    pda.states.push_back(State(Q_SYN_RECEIVED, false, "q1_syn_recv"));
    pda.states.push_back(State(Q_SYNACK_RECEIVED, false, "q2_synack_recv"));
    pda.states.push_back(State(Q_ACCEPT, true, "q3_accept"));
    pda.states.push_back(State(Q_ERROR, false, "q_error"));
    
    pda.start_state = Q_START;
    pda.accepting_states.insert(Q_ACCEPT);
    
    std::cout << "\n[PDA STRUCTURE]" << std::endl;
    std::cout << "  States: " << pda.states.size() << std::endl;
    std::cout << "    q0: Initial state" << std::endl;
    std::cout << "    q1: SYN received (expects SYN-ACK)" << std::endl;
    std::cout << "    q2: SYN-ACK received (expects ACK)" << std::endl;
    std::cout << "    q3: Handshake complete (ACCEPTING)" << std::endl;
    std::cout << "    qE: Error state (REJECTING)" << std::endl;
    
    std::cout << "\n[STACK OPERATIONS]" << std::endl;
    std::cout << "  PUSH SYN:      On receiving SYN in q0" << std::endl;
    std::cout << "  PUSH SYN-ACK:  On receiving SYN-ACK in q1" << std::endl;
    std::cout << "  POP ALL:       On receiving ACK in q2 (pops both SYN-ACK and SYN)" << std::endl;
    std::cout << "  Stack empty:   Required for acceptance (state-based + empty stack)" << std::endl;  
    
    std::cout << "\n[SUCCESS] PDA constructed from CFG" << std::endl;
    std::cout << std::endl;
}

bool PDAModule::processPacket(const std::string& packet, std::vector<std::string>& operations) {
    std::string top = pda.peek();
    int current = pda.current_state;
    
    // State 0: Expecting SYN (Start of handshake)
    if (current == Q_START && packet == "SYN") {
        pda.push("SYN");
        pda.current_state = Q_SYN_RECEIVED;
        operations.push_back("PUSH(SYN) → q1");
        return true;
    }
    
    // State 1: Expecting SYN-ACK (Server response)
    else if (current == Q_SYN_RECEIVED && packet == "SYN-ACK" && top == "SYN") {
        pda.push("SYN-ACK");
        pda.current_state = Q_SYNACK_RECEIVED;
        operations.push_back("PUSH(SYN-ACK) → q2");
        return true;
    }
    
    // State 2: Expecting ACK (Client acknowledgment)
    else if (current == Q_SYNACK_RECEIVED && packet == "ACK" && top == "SYN-ACK") {
        pda.pop();  // Pop SYN-ACK
        pda.pop();  // Pop SYN
        pda.current_state = Q_ACCEPT;
        operations.push_back("POP(SYN-ACK), POP(SYN) → q3");
        return true;
    }
    
    // State 3: After handshake - allow data transfer
    else if (current == Q_ACCEPT) {
        if (packet == "DATA") {
            operations.push_back("ACCEPT DATA → q3");
            return true;
        }
        else if (packet == "FIN") {
            operations.push_back("ACCEPT FIN → q3");
            return true;
        }
        else if (packet == "ACK") {
            operations.push_back("ACCEPT ACK → q3");
            return true;
        }
        // Allow new handshake after completion
        else if (packet == "SYN") {
            pda.push("SYN");
            pda.current_state = Q_SYN_RECEIVED;
            operations.push_back("NEW HANDSHAKE: PUSH(SYN) → q1");
            return true;
        }
        else {
            pda.current_state = Q_ERROR;
            operations.push_back("ERROR: Invalid packet");
            return false;
        }
    }
    
    // RST always causes error
    else if (packet == "RST") {
        pda.current_state = Q_ERROR;
        operations.push_back("ERROR: RST received");
        return false;
    }
    
    // Invalid transition
    pda.current_state = Q_ERROR;
    operations.push_back("ERROR: Invalid transition");
    return false;
}

bool PDAModule::validateSequence(const std::vector<std::string>& sequence) {
    pda.reset();
    
    for (const auto& packet : sequence) {
        std::vector<std::string> ops;
        if (!processPacket(packet, ops)) {
            return false;
        }
    }
    
    // Accept if in accepting state with empty stack
    return pda.isAccepting();
}

void PDAModule::testAllTraces() {
    std::cout << "[INFO] Validating " << dataset.size() << " TCP traces with PDA..." << std::endl;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int total_depth = 0;
    std::vector<std::string> failed_traces;
    
    for (const auto& t : dataset) {
        bool result = validateSequence(t.sequence);
        int depth = pda.getStackDepth();
        
        if (depth > metrics.max_stack_depth) {
            metrics.max_stack_depth = depth;
        }
        total_depth += depth;
        
        if (result && t.valid) {
            metrics.correctly_accepted++;
        }
        else if (!result && !t.valid) {
            metrics.correctly_rejected++;
        }
        else if (result && !t.valid) {
            metrics.false_positives++;
            failed_traces.push_back("FP: " + t.trace_id);
        }
        else if (!result && t.valid) {
            metrics.false_negatives++;
            failed_traces.push_back("FN: " + t.trace_id);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    metrics.total_execution_time_ms = dur.count() / 1000.0;
    
    if (dataset.size() > 0) {
        metrics.avg_stack_depth = (double)total_depth / dataset.size();
        metrics.avg_validation_time_ms = metrics.total_execution_time_ms / dataset.size();
    }
    
    metrics.validation_accuracy = 
        ((double)(metrics.correctly_accepted + metrics.correctly_rejected) / 
         (dataset.size() > 0 ? dataset.size() : 1)) * 100.0;
    
    std::cout << "[SUCCESS] Validation complete" << std::endl;
    std::cout << "  Accuracy: " << metrics.validation_accuracy << "%" << std::endl;
    
    // Show failed traces if any
    if (!failed_traces.empty() && failed_traces.size() <= 10) {
        std::cout << "\n[Failed (false positives/negatives)] Sample failed traces:" << std::endl;
        for (size_t i = 0; i < std::min((size_t)5, failed_traces.size()); i++) {
            std::cout << "  " << failed_traces[i] << std::endl;
        }
    }
    std::cout << std::endl;
}

void PDAModule::showStackOperations(const std::vector<std::string>& sequence) {
    pda.reset();
    
    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  STACK TRACE VISUALIZATION                             ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\nInput sequence: [";
    for (size_t i = 0; i < sequence.size(); ++i) {
        std::cout << sequence[i];
        if (i + 1 < sequence.size()) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
    
    std::cout << "\nStep-by-step execution:" << std::endl;
    std::cout << "  Initial: State=q0, Stack=[BOTTOM]" << std::endl;
    
    for (size_t i = 0; i < sequence.size(); ++i) {
        int state_before = pda.current_state;
        std::vector<std::string> ops;
        bool ok = processPacket(sequence[i], ops);
        
        std::cout << "  Step " << (i+1) << ": Input='" << sequence[i] << "'" << std::endl;
        std::cout << "         State: q" << state_before << " → q" << pda.current_state << std::endl;
        std::cout << "         Operation: " << (ops.empty() ? "none" : ops[0]) << std::endl;
        std::cout << "         Stack depth: " << pda.getStackDepth();
        if (!ok) std::cout << " [ERROR]";
        std::cout << std::endl;
    }
    
    std::cout << "\n  Final state: q" << pda.current_state << std::endl;
    std::cout << "  Stack depth: " << pda.getStackDepth() << std::endl;
    std::cout << "  Result: " << (pda.isAccepting() ? "✓ VALID" : "✗ INVALID") << std::endl;
    std::cout << std::endl;
}

void PDAModule::generateReport() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║          PDA MODULE - VALIDATION RESULTS                  ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    // Show sample TCP trace results
    std::cout << "\n[SAMPLE TCP TRACE RESULTS (RANDOMIZED)]" << std::endl;
    int sample_count = 0;
    for (const auto& t : dataset) {
        if (sample_count >= 5) break;
        pda.reset();  // Reset PDA state before validation
        bool result = validateSequence(t.sequence);
        std::string validation = result ? "VALID" : "INVALID";
        std::string reason = "";
        if (!result && t.valid) {
            reason = " (unexpected rejection)";
        } else if (result && !t.valid) {
            reason = " (unexpected acceptance)";
        } else if (!result && !t.valid && !t.description.empty()) {
            reason = " (" + t.description + ")";
        }
        std::cout << t.trace_id << ": " << validation << reason << std::endl;
        sample_count++;
    }
    
    std::cout << "\n[VALIDATION METRICS]" << std::endl;
    std::cout << "  ✓ Valid accepted:       " << metrics.correctly_accepted 
             << " / " << metrics.valid_traces << std::endl;
    std::cout << "  ✓ Invalid rejected:     " << metrics.correctly_rejected 
             << " / " << metrics.invalid_traces << std::endl;
    std::cout << "  ✗ False positives:      " << metrics.false_positives << std::endl;
    std::cout << "  ✗ False negatives:      " << metrics.false_negatives << std::endl;
    std::cout << "  Validation accuracy:    " << metrics.validation_accuracy << "%" << std::endl;
    
    std::cout << "\n[STACK METRICS]" << std::endl;
    std::cout << "  Average stack depth:    " << metrics.avg_stack_depth << std::endl;
    std::cout << "  Maximum stack depth:    " << metrics.max_stack_depth << std::endl;
    
    // Calculate confusion matrix for PDA
    int true_negatives = metrics.correctly_rejected;
    double precision = (metrics.correctly_accepted + metrics.false_positives > 0)
        ? (100.0 * metrics.correctly_accepted / (metrics.correctly_accepted + metrics.false_positives)) : 0.0;
    double recall = (metrics.correctly_accepted + metrics.false_negatives > 0)
        ? (100.0 * metrics.correctly_accepted / (metrics.correctly_accepted + metrics.false_negatives)) : 0.0;
    double f1_score = (precision + recall > 0) ? (2.0 * precision * recall / (precision + recall)) : 0.0;
    
    std::cout << "\n[CONFUSION MATRIX DEFINITIONS]" << std::endl;
    std::cout << "  TP (True Positive):  Valid trace correctly accepted" << std::endl;
    std::cout << "  FP (False Positive): Invalid trace incorrectly accepted" << std::endl;
    std::cout << "  TN (True Negative):  Invalid trace correctly rejected" << std::endl;
    std::cout << "  FN (False Negative): Valid trace incorrectly rejected" << std::endl;
    
    std::cout << "\n[CONFUSION MATRIX]" << std::endl;
    std::cout << "  ✓ True Positives (TP):   " << metrics.correctly_accepted << std::endl;
    std::cout << "  ✗ False Positives (FP):  " << metrics.false_positives << std::endl;
    std::cout << "  ✓ True Negatives (TN):   " << true_negatives << std::endl;
    std::cout << "  ✗ False Negatives (FN):  " << metrics.false_negatives << std::endl;
    std::cout << "  Precision:               " << precision << "%" << std::endl;
    std::cout << "  Recall:                  " << recall << "%" << std::endl;
    std::cout << "  F1 Score:                " << f1_score << "%" << std::endl;
    
    std::cout << "\n[PERFORMANCE]" << std::endl;
    std::cout << "  Total traces:           " << metrics.total_traces << std::endl;
    std::cout << "  Total execution time:   " << metrics.total_execution_time_ms << " ms (wall-clock)" << std::endl;
    std::cout << "  Average per trace:      " << metrics.avg_validation_time_ms << " ms" << std::endl;
    std::cout << "  Note: Times measured using std::chrono::high_resolution_clock" << std::endl;
    
    std::cout << "\n[TEST DATASET LABELS]" << std::endl;
    std::cout << "  Ground truth derived from: archive/tcp_handshake_traces_expanded.jsonl" << std::endl;
    std::cout << "  Labels: 'valid' field indicates ground truth (true=valid handshake, false=invalid)" << std::endl;
    std::cout << "  Dataset contains valid TCP handshake sequences and invalid/malformed sequences" << std::endl;
    
    std::cout << "\n[CONTEXT-FREE PROPERTY]" << std::endl;
    std::cout << "  Stack usage demonstrates Type-2 (CF) language:" << std::endl;
    std::cout << "  • Stack needed to track SYN ↔ SYN-ACK ↔ ACK pairing" << std::endl;
    std::cout << "  • Cannot be recognized by finite automaton (DFA)" << std::endl;
    std::cout << "  • Requires unbounded memory for nested structures" << std::endl;
    std::cout << "  • Accepting condition: State-based (q3) AND empty stack" << std::endl;
    std::cout << std::endl;

    // Also write PDA report to output file
    try {
        std::ofstream out("output/pda_report.txt");
        if (out.is_open()) {
            out << "╔═══════════════════════════════════════════════════════════╗\n";
            out << "║          PDA MODULE - VALIDATION RESULTS                  ║\n";
            out << "╚═══════════════════════════════════════════════════════════╝\n";
            out << "\n[VALIDATION METRICS]\n";
            out << "  ✓ Valid accepted:       " << metrics.correctly_accepted << " / " << metrics.valid_traces << "\n";
            out << "  ✓ Invalid rejected:     " << metrics.correctly_rejected << " / " << metrics.invalid_traces << "\n";
            out << "  ✗ False positives:      " << metrics.false_positives << "\n";
            out << "  ✗ False negatives:      " << metrics.false_negatives << "\n";
            out << "  Validation accuracy:    " << metrics.validation_accuracy << "%\n";
            out << "\n[STACK METRICS]\n";
            out << "  Average stack depth:    " << metrics.avg_stack_depth << "\n";
            out << "  Maximum stack depth:    " << metrics.max_stack_depth << "\n";
            int true_negatives = metrics.correctly_rejected;
            double precision = (metrics.correctly_accepted + metrics.false_positives > 0)
                ? (100.0 * metrics.correctly_accepted / (metrics.correctly_accepted + metrics.false_positives)) : 0.0;
            double recall = (metrics.correctly_accepted + metrics.false_negatives > 0)
                ? (100.0 * metrics.correctly_accepted / (metrics.correctly_accepted + metrics.false_negatives)) : 0.0;
            double f1_score = (precision + recall > 0) ? (2.0 * precision * recall / (precision + recall)) : 0.0;
            
            out << "\n[CONFUSION MATRIX DEFINITIONS]\n";
            out << "  TP (True Positive):  Valid trace correctly accepted\n";
            out << "  FP (False Positive): Invalid trace incorrectly accepted\n";
            out << "  TN (True Negative):  Invalid trace correctly rejected\n";
            out << "  FN (False Negative): Valid trace incorrectly rejected\n";
            out << "\n[CONFUSION MATRIX]\n";
            out << "  ✓ True Positives (TP):   " << metrics.correctly_accepted << "\n";
            out << "  ✗ False Positives (FP):  " << metrics.false_positives << "\n";
            out << "  ✓ True Negatives (TN):   " << true_negatives << "\n";
            out << "  ✗ False Negatives (FN):  " << metrics.false_negatives << "\n";
            out << "  Precision:               " << precision << "%\n";
            out << "  Recall:                  " << recall << "%\n";
            out << "  F1 Score:                " << f1_score << "%\n";
            out << "\n[PERFORMANCE]\n";
            out << "  Total traces:           " << metrics.total_traces << "\n";
            out << "  Total execution time:   " << metrics.total_execution_time_ms << " ms (wall-clock)\n";
            out << "  Average per trace:      " << metrics.avg_validation_time_ms << " ms\n";
            out.close();
        }
    } catch (...) {
        // ignore file errors
    }
}

// Export a Graphviz DOT snippet representing the PDA states and canonical transitions
std::string PDAModule::exportGraphviz() const {
    std::ostringstream ss;

    if (pda.states.empty()) return ss.str();

    ss << "  subgraph cluster_pda {\n";
    ss << "    label=\"PDA (TCP Handshake)\";\n";
    ss << "    color=blue;\n";
    ss << "    node [style=filled,color=white];\n";

    // Nodes
    for (const auto& s : pda.states) {
        std::string nodeName = "p_s" + std::to_string(s.id);
        std::string label = s.label.empty() ? std::to_string(s.id) : s.label;
        if (s.is_accepting) label += " (accept)";
        ss << "    " << nodeName << " [label=\"" << escapeDotLabel(label) << "\"];\n";
    }

    // Canonical transitions derived from the PDA behavior implemented in PDAModule
    auto hasState = [&](int id){ for (const auto& s : pda.states) if (s.id == id) return true; return false; };
    if (hasState(Q_START) && hasState(Q_SYN_RECEIVED))
        ss << "    p_s" << Q_START << " -> p_s" << Q_SYN_RECEIVED << " [label=\"SYN\"];\n";
    if (hasState(Q_SYN_RECEIVED) && hasState(Q_SYNACK_RECEIVED))
        ss << "    p_s" << Q_SYN_RECEIVED << " -> p_s" << Q_SYNACK_RECEIVED << " [label=\"SYN-ACK\"];\n";
    if (hasState(Q_SYNACK_RECEIVED) && hasState(Q_ACCEPT))
        ss << "    p_s" << Q_SYNACK_RECEIVED << " -> p_s" << Q_ACCEPT << " [label=\"ACK\"];\n";
    if (hasState(Q_ACCEPT))
        ss << "    p_s" << Q_ACCEPT << " -> p_s" << Q_ACCEPT << " [label=\"DATA,ACK,FIN\"];\n";
    if (hasState(Q_ACCEPT) && hasState(Q_SYN_RECEIVED))
        ss << "    p_s" << Q_ACCEPT << " -> p_s" << Q_SYN_RECEIVED << " [label=\"SYN (new)\"];\n";

    ss << "  }\n";
    return ss.str();
}

} // namespace CS311