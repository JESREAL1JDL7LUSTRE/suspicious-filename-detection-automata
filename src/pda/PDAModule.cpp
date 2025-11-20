/**
 * PDAModule.cpp - IMPROVED VERSION
 * Explicitly shows CFG before building PDA
 */

#include "PDAModule.h"
#include <iostream>
#include <chrono>

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
    
    std::cout << "\nProduction Rules:" << std::endl;
    std::cout << "  S  → SYN A                (Start with SYN)" << std::endl;
    std::cout << "  A  → SYN-ACK B            (Must respond with SYN-ACK)" << std::endl;
    std::cout << "  B  → ACK C                (Complete handshake with ACK)" << std::endl;
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
    std::cout << "  POP ALL:       On receiving ACK in q2" << std::endl;
    std::cout << "  Stack empty:   Required for acceptance" << std::endl;
    
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
        std::cout << "\n[DEBUG] Sample failed traces:" << std::endl;
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
    
    std::cout << "\n[PERFORMANCE]" << std::endl;
    std::cout << "  Total traces:           " << metrics.total_traces << std::endl;
    std::cout << "  Total execution time:   " << metrics.total_execution_time_ms << " ms" << std::endl;
    std::cout << "  Average per trace:      " << metrics.avg_validation_time_ms << " ms" << std::endl;
    
    std::cout << "\n[CONTEXT-FREE PROPERTY]" << std::endl;
    std::cout << "  Stack usage demonstrates Type-2 (CF) language:" << std::endl;
    std::cout << "  • Stack needed to track SYN ↔ SYN-ACK ↔ ACK pairing" << std::endl;
    std::cout << "  • Cannot be recognized by finite automaton (DFA)" << std::endl;
    std::cout << "  • Requires unbounded memory for nested structures" << std::endl;
    std::cout << std::endl;
}

} // namespace CS311