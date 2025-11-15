/**
 * main.cpp - Main Program
 */
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#endif
#include "Utils.h"
#include "DFAModule.h"
#include "PDAModule.h"

using namespace CS311;

int main() {
#ifdef _WIN32
    // Ensure Windows console uses UTF-8 so box-drawing/Unicode prints correctly
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    std::cout << "=======================================================" << std::endl;
    std::cout << "   CS311 Chomsky Hierarchy Security Simulator" << std::endl;
    std::cout << "   Filename Detection & TCP Protocol Validation" << std::endl;
    std::cout << "=======================================================" << std::endl;
    printHeader("MODULE 1: Filename Pattern Detection (DFA)");
    DFAModule dfaModule;
    try {
        dfaModule.loadDataset("archive/Malicious_file_trick_detection.jsonl");
        dfaModule.definePatterns();
        dfaModule.buildNFAs();
        dfaModule.convertToDFAs();
        dfaModule.minimizeDFAs();
        dfaModule.applyIGA();
        dfaModule.testPatterns();
        dfaModule.generateReport();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] DFA Module failed: " << e.what() << std::endl;
    }
    printHeader("MODULE 2: TCP Protocol Validation (PDA)");
    PDAModule pdaModule;
    try {
        pdaModule.loadDataset("archive/tcp_handshake_traces_expanded.jsonl");
        pdaModule.buildPDA();
        pdaModule.testAllTraces();
        std::cout << "\n[SAMPLE STACK OPERATIONS]" << std::endl;
        std::vector<std::string> sample1 = {"SYN","SYN-ACK","ACK"};
        pdaModule.showStackOperations(sample1);
        std::vector<std::string> sample2 = {"SYN","ACK"};
        pdaModule.showStackOperations(sample2);
        pdaModule.generateReport();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] PDA Module failed: " << e.what() << std::endl;
    }
    printHeader("CHOMSKY HIERARCHY DEMONSTRATION");
    std::cout << "┌─────────────────────┬──────────────────┬──────────────────┐" << std::endl;
    std::cout << "│ Aspect              │ DFA (Regular)    │ PDA (Context-Free)│" << std::endl;
    std::cout << "├─────────────────────┼──────────────────┼──────────────────┤" << std::endl;
    std::cout << "│ Memory              │ None (stateless) │ Stack            │" << std::endl;
    std::cout << "│ Chomsky Level       │ Type 3           │ Type 2           │" << std::endl;
    std::cout << "│ Can match patterns  │ ✓ Yes            │ ✓ Yes            │" << std::endl;
    std::cout << "│ Can count/pair      │ ✗ No             │ ✓ Yes            │" << std::endl;
    std::cout << "│ Example             │ *.exe detection  │ SYN-ACK pairing  │" << std::endl;
    std::cout << "└─────────────────────┴──────────────────┴──────────────────┘" << std::endl;
    std::cout << "\n[EXECUTION COMPLETE]" << std::endl;
    std::cout << "Results saved to: output/" << std::endl;
    return 0;
}
