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
    if (pda.current_state == Q_START && packet == "SYN") {
        pda.push("SYN"); pda.current_state = Q_SYN_RECEIVED; operations.push_back("PUSH SYN"); return true;
    } else if (pda.current_state == Q_SYN_RECEIVED && packet == "SYN-ACK" && top == "SYN") {
        pda.push("SYN-ACK"); pda.current_state = Q_SYNACK_RECEIVED; operations.push_back("PUSH SYN-ACK"); return true;
    } else if (pda.current_state == Q_SYNACK_RECEIVED && packet == "ACK" && top == "SYN-ACK") {
        pda.pop(); pda.pop(); pda.current_state = Q_ACCEPT; operations.push_back("POP ALL"); return true;
    } else if (pda.current_state == Q_ACCEPT && (packet == "DATA" || packet == "FIN" || packet == "ACK")) {
        operations.push_back(std::string("ALLOW ")+packet); return true;
    } else if (packet == "RST") { pda.current_state = Q_ERROR; operations.push_back("ERROR: RST"); return false; }
    pda.current_state = Q_ERROR; operations.push_back("ERROR: Invalid transition"); return false;
}

bool PDAModule::validateSequence(const std::vector<std::string>& sequence) {
    pda.reset();
    for (const auto &pkt : sequence) {
        std::vector<std::string> ops; if (!processPacket(pkt, ops)) return false;
    }
    return pda.isAccepting();
}

void PDAModule::testAllTraces() {
    std::cout << "[INFO] Validating " << dataset.size() << " TCP traces..." << std::endl;
    int total_depth = 0;
    for (const auto &t: dataset) {
        bool res = validateSequence(t.sequence);
        int depth = pda.getStackDepth(); if (depth > metrics.max_stack_depth) metrics.max_stack_depth = depth; total_depth += depth;
        if (res && t.valid) metrics.correctly_accepted++; else if (!res && !t.valid) metrics.correctly_rejected++; else if (res && !t.valid) metrics.false_positives++; else if (!res && t.valid) metrics.false_negatives++;
    }
    if (dataset.size()>0) metrics.avg_stack_depth = (double)total_depth / dataset.size();
    metrics.validation_accuracy = ((double)(metrics.correctly_accepted + metrics.correctly_rejected) / (dataset.size()>0?dataset.size():1)) * 100.0;
    std::cout << "[SUCCESS] Validation complete" << std::endl;
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
