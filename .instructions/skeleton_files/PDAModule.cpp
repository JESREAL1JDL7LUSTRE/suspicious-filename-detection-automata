
/**
 * ============================================================
 * PDAModule.cpp - Implementation
 * ============================================================
 */
#include "PDAModule.h"
#include <iostream>

namespace CS311 {

PDAModule::PDAModule() {}

void PDAModule::loadDataset(const std::string& filepath) {
    dataset = JSONParser::loadTCPDataset(filepath);
    metrics.total_traces = dataset.size();
    
    for (const auto& trace : dataset) {
        if (trace.valid) metrics.valid_traces++;
        else metrics.invalid_traces++;
    }
}

void PDAModule::buildPDA() {
    std::cout << "[INFO] Building PDA for TCP 3-way handshake..." << std::endl;
    
    // Initialize PDA states
    pda.states.push_back(State(Q_START, false, "q_start"));
    pda.states.push_back(State(Q_SYN_RECEIVED, false, "q_syn_recv"));
    pda.states.push_back(State(Q_SYNACK_RECEIVED, false, "q_synack_recv"));
    pda.states.push_back(State(Q_ACCEPT, true, "q_accept"));
    
    pda.start_state = Q_START;
    pda.accepting_states.insert(Q_ACCEPT);
    
    std::cout << "[SUCCESS] PDA constructed" << std::endl;
    std::cout << "  States: {q_start, q_syn_recv, q_synack_recv, q_accept}" << std::endl;
    std::cout << "  Stack alphabet: {SYN, SYN-ACK, BOTTOM}" << std::endl;
}

bool PDAModule::validateSequence(const std::vector<std::string>& sequence) {
    pda.reset();
    
    for (const auto& packet : sequence) {
        std::vector<std::string> ops;
        if (!processPacket(packet, ops)) {
            return false;
        }
    }
    
    return pda.isAccepting();
}

bool PDAModule::processPacket(const std::string& packet, std::vector<std::string>& operations) {
    std::string stack_top = pda.peek();
    
    if (pda.current_state == Q_START && packet == "SYN") {
        pda.push("SYN");
        pda.current_state = Q_SYN_RECEIVED;
        operations.push_back("PUSH SYN");
        return true;
    }
    else if (pda.current_state == Q_SYN_RECEIVED && packet == "SYN-ACK" && stack_top == "SYN") {
        pda.push("SYN-ACK");
        pda.current_state = Q_SYNACK_RECEIVED;
        operations.push_back("PUSH SYN-ACK");
        return true;
    }
    else if (pda.current_state == Q_SYNACK_RECEIVED && packet == "ACK" && stack_top == "SYN-ACK") {
        pda.pop();  // SYN-ACK
        pda.pop();  // SYN
        pda.current_state = Q_ACCEPT;
        operations.push_back("POP ALL");
        return true;
    }
    else if (pda.current_state == Q_ACCEPT && (packet == "DATA" || packet == "FIN" || packet == "ACK")) {
        // Allow data/fin/ack after handshake
        operations.push_back("ALLOW");
        return true;
    }
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

void PDAModule::testAllTraces() {
    std::cout << "[INFO] Validating " << dataset.size() << " TCP traces..." << std::endl;
    
    int total_stack_depth = 0;
    
    for (const auto& trace : dataset) {
        bool result = validateSequence(trace.sequence);
        int depth = pda.getStackDepth();
        
        if (depth > metrics.max_stack_depth) {
            metrics.max_stack_depth = depth;
        }
        total_stack_depth += depth;
        
        if (result && trace.valid) {
            metrics.correctly_accepted++;
        }
        else if (!result && !trace.valid) {
            metrics.correctly_rejected++;
        }
        else if (result && !trace.valid) {
            metrics.false_positives++;
        }
        else if (!result && trace.valid) {
            metrics.false_negatives++;
        }
    }
    
    metrics.avg_stack_depth = (double)total_stack_depth / dataset.size();
    metrics.validation_accuracy = 
        ((double)(metrics.correctly_accepted + metrics.correctly_rejected) / dataset.size()) * 100.0;
    
    std::cout << "[SUCCESS] Validation complete" << std::endl;
    std::cout << "  Accuracy: " << metrics.validation_accuracy << "%" << std::endl;
}

void PDAModule::showStackOperations(const std::vector<std::string>& sequence) {
    pda.reset();
    
    std::cout << "\nSequence: [";
    for (size_t i = 0; i < sequence.size(); i++) {
        std::cout << sequence[i];
        if (i < sequence.size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
    
    for (size_t i = 0; i < sequence.size(); i++) {
        std::string stack_before = pda.peek();
        int state_before = pda.current_state;
        
        std::vector<std::string> ops;
        bool success = processPacket(sequence[i], ops);
        
        std::cout << "  Step " << (i+1) << ": " << sequence[i] 
                  << " | State: " << state_before << " -> " << pda.current_state
                  << " | Stack depth: " << pda.getStackDepth();
        
        if (!success) {
            std::cout << " [ERROR]";
        }
        std::cout << std::endl;
    }
    
    std::cout << "  Result: " << (pda.isAccepting() ? "✓ VALID" : "✗ INVALID") << std::endl;
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
