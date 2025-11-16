/** PDAModule.cpp **/
#include "PDAModule.h"
#include <iostream>

namespace CS311 {

PDAModule::PDAModule() {}

void PDAModule::loadDataset(const std::string& filepath) {
    dataset = JSONParser::loadTCPDataset(filepath);
    metrics.total_traces = (int)dataset.size();
    for (const auto &t: dataset) { if (t.valid) metrics.valid_traces++; else metrics.invalid_traces++; }
}

void PDAModule::buildPDA() {
    std::cout << "[INFO] Building PDA for TCP 3-way handshake..." << std::endl;
    pda.states.push_back(State(Q_START, false, "q_start"));
    pda.states.push_back(State(Q_SYN_RECEIVED, false, "q_syn_recv"));
    pda.states.push_back(State(Q_SYNACK_RECEIVED, false, "q_synack_recv"));
    pda.states.push_back(State(Q_ACCEPT, true, "q_accept"));
    pda.start_state = Q_START;
    pda.accepting_states.insert(Q_ACCEPT);
    std::cout << "[SUCCESS] PDA constructed" << std::endl;
}
bool PDAModule::processPacket(const std::string& packet, std::vector<std::string>& operations) {
    std::string top = pda.peek();
    int current = pda.current_state;
    
    // State 0: Expecting SYN
    if (current == Q_START && packet == "SYN") {
        pda.push("SYN");
        pda.current_state = Q_SYN_RECEIVED;
        operations.push_back("PUSH SYN");
        return true;
    }
    
    // State 1: Expecting SYN-ACK
    else if (current == Q_SYN_RECEIVED && packet == "SYN-ACK" && top == "SYN") {
        pda.push("SYN-ACK");
        pda.current_state = Q_SYNACK_RECEIVED;
        operations.push_back("PUSH SYN-ACK");
        return true;
    }
    
    // State 2: Expecting ACK
    else if (current == Q_SYNACK_RECEIVED && packet == "ACK" && top == "SYN-ACK") {
        pda.pop();
        pda.pop();
        pda.current_state = Q_ACCEPT;
        operations.push_back("POP ALL");
        return true;
    }
    
    // State 3: After handshake - allow DATA, FIN, ACK, or NEW HANDSHAKE
    else if (current == Q_ACCEPT) {
        if (packet == "DATA" || packet == "FIN") {
            operations.push_back("ALLOW " + packet);
            return true;
        }
        else if (packet == "ACK") {
            operations.push_back("ALLOW ACK");
            return true;
        }
        // CRITICAL FIX: Allow new SYN after completed handshake (for consecutive handshakes)
        else if (packet == "SYN") {
            pda.push("SYN");
            pda.current_state = Q_SYN_RECEIVED;
            operations.push_back("NEW HANDSHAKE - PUSH SYN");
            return true;
        }
        // Reject anything else
        else {
            pda.current_state = Q_ERROR;
            operations.push_back("ERROR: Invalid packet after handshake");
            return false;
        }
    }
    
    // RST always causes error
    else if (packet == "RST") {
        pda.current_state = Q_ERROR;
        operations.push_back("ERROR: RST");
        return false;
    }
    
    // Invalid transition
    pda.current_state = Q_ERROR;
    operations.push_back("ERROR: Invalid transition");
    return false;
}

bool PDAModule::validateSequence(const std::vector<std::string>& sequence) {
    pda.reset();
    
    for (const auto &pkt : sequence) {
        std::vector<std::string> ops;
        if (!processPacket(pkt, ops)) {
            return false;
        }
    }
    
    // Accept if in Q_ACCEPT state with empty stack (only BOTTOM)
    // OR if we completed at least one handshake
    return pda.isAccepting();
}

void PDAModule::testAllTraces() {
    std::cout << "[INFO] Validating " << dataset.size() << " TCP traces..." << std::endl;
    int total_depth = 0;
    
    // DEBUG: Track failures
    std::vector<std::string> failed_traces;
    
    for (const auto &t: dataset) {
        bool res = validateSequence(t.sequence);
        int depth = pda.getStackDepth();
        
        if (depth > metrics.max_stack_depth) metrics.max_stack_depth = depth;
        total_depth += depth;
        
        if (res && t.valid) metrics.correctly_accepted++;
        else if (!res && !t.valid) metrics.correctly_rejected++;
        else if (res && !t.valid) {
            metrics.false_positives++;
            failed_traces.push_back("FP: " + t.trace_id);  // DEBUG
        }
        else if (!res && t.valid) {
            metrics.false_negatives++;
            failed_traces.push_back("FN: " + t.trace_id);  // DEBUG
        }
    }
    
    if (dataset.size() > 0) {
        metrics.avg_stack_depth = (double)total_depth / dataset.size();
    }
    
    metrics.validation_accuracy = 
        ((double)(metrics.correctly_accepted + metrics.correctly_rejected) / 
         (dataset.size() > 0 ? dataset.size() : 1)) * 100.0;
    
    std::cout << "[SUCCESS] Validation complete" << std::endl;

    // Additional validation: Check for edge cases
for (size_t i = 0; i < dataset.size(); i++) {
    const auto& t = dataset[i];
    
    // Edge case 1: Sequences starting with non-SYN should be invalid
    if (!t.sequence.empty() && t.sequence[0] != "SYN") {
        if (t.valid) {
            // This is weird - valid trace not starting with SYN
            std::cout << "[WARNING] Trace " << t.trace_id << " marked valid but doesn't start with SYN" << std::endl;
        }
    }
    
    // Edge case 2: Very short sequences (< 3 packets) can't be complete handshakes
    if (t.sequence.size() < 3 && t.valid) {
        std::cout << "[WARNING] Trace " << t.trace_id << " marked valid but too short" << std::endl;
    }
}
    
    // DEBUG: Print failures
    if (!failed_traces.empty()) {
        std::cout << "[DEBUG] Failed traces:" << std::endl;
        for (const auto& ft : failed_traces) {
            std::cout << "  " << ft << std::endl;
        }
    }
}

void PDAModule::showStackOperations(const std::vector<std::string>& sequence) {
    pda.reset();
    std::cout << "\nSequence: [";
    for (size_t i=0;i<sequence.size();++i) { std::cout<<sequence[i]; if (i+1<sequence.size()) std::cout<<", "; }
    std::cout << "]" << std::endl;
    for (size_t i=0;i<sequence.size();++i) {
        std::string before = pda.peek(); int state_before = pda.current_state;
        std::vector<std::string> ops; bool ok = processPacket(sequence[i], ops);
        std::cout << "  Step " << (i+1) << ": " << sequence[i] << " | State: " << state_before << " -> " << pda.current_state << " | Stack depth: " << pda.getStackDepth();
        if (!ok) std::cout << " [ERROR]";
        std::cout << std::endl;
    }
    std::cout << "  Result: " << (pda.isAccepting()?"✓ VALID":"✗ INVALID") << std::endl;
}

void PDAModule::generateReport() {
    std::cout << "\n[RESULTS] PDA Validation Summary:" << std::endl;
    std::cout << "  ✓ Valid accepted: " << metrics.correctly_accepted << "/" << metrics.valid_traces << std::endl;
    std::cout << "  ✓ Invalid rejected: " << metrics.correctly_rejected << "/" << metrics.invalid_traces << std::endl;
    std::cout << "  ✗ False positives: " << metrics.false_positives << std::endl;
    std::cout << "  ✗ False negatives: " << metrics.false_negatives << std::endl;
    std::cout << "  Validation accuracy: " << metrics.validation_accuracy << "%" << std::endl;
    std::cout << "\n[PERFORMANCE] PDA Metrics:" << std::endl;
    std::cout << "  Avg stack depth: " << metrics.avg_stack_depth << std::endl;
    std::cout << "  Max stack depth: " << metrics.max_stack_depth << std::endl;
}

} // namespace CS311
