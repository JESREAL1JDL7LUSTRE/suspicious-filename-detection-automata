/**
 * main.cpp - IMPROVED VERSION
 * Main Program - Now follows the architecture properly
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

    std::cout << "╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   CS311 CHOMSKY HIERARCHY SECURITY SIMULATOR              ║" << std::endl;
    std::cout << "║   Filename Detection & TCP Protocol Validation            ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;
    
    // ========================================================================
    // MODULE 1: DFA-based Filename Pattern Detection (Type-3 Regular)
    // ========================================================================
    printHeader("MODULE 1: Filename Pattern Detection (DFA)");
    std::cout << "[CHOMSKY TYPE-3: REGULAR LANGUAGE]" << std::endl;
    std::cout << "Using Deterministic Finite Automaton (DFA)" << std::endl;
    std::cout << "Memory: None (stateless)" << std::endl;
    std::cout << "Capability: Pattern matching" << std::endl;
    std::cout << std::endl;
    
    DFAModule dfaModule;
    try {
        dfaModule.loadDataset("archive/Malicious_file_trick_detection.jsonl");
        dfaModule.definePatterns();
        dfaModule.buildNFAs();          // Regex → NFA (Thompson's Construction)
        dfaModule.convertToDFAs();       // NFA → DFA (Subset Construction)
        dfaModule.minimizeDFAs();        // DFA minimization (Hopcroft's)
        dfaModule.applyIGA();            // Improved Grouping Algorithm
        dfaModule.testPatterns();        // Test using actual DFAs
        dfaModule.generateReport();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] DFA Module failed: " << e.what() << std::endl;
    }
    
    // ========================================================================
    // MODULE 2: PDA-based TCP Protocol Validation (Type-2 Context-Free)
    // ========================================================================
    printHeader("MODULE 2: TCP Protocol Validation (PDA)");
    std::cout << "[CHOMSKY TYPE-2: CONTEXT-FREE LANGUAGE]" << std::endl;
    std::cout << "Using Pushdown Automaton (PDA)" << std::endl;
    std::cout << "Memory: Stack (unbounded)" << std::endl;
    std::cout << "Capability: Counting, pairing, nested structures" << std::endl;
    std::cout << std::endl;
    
    PDAModule pdaModule;
    try {
        pdaModule.loadDataset("archive/tcp_handshake_traces_expanded.jsonl");
        pdaModule.defineCFG();          // NEW: Show the Context-Free Grammar
        pdaModule.buildPDA();           // Build PDA from CFG
        pdaModule.testAllTraces();      // Validate all traces
        
        // Show sample stack operations
        std::cout << "\n[SAMPLE STACK OPERATIONS]" << std::endl;
        std::vector<std::string> sample1 = {"SYN", "SYN-ACK", "ACK"};
        pdaModule.showStackOperations(sample1);
        
        std::vector<std::string> sample2 = {"SYN", "ACK"};
        pdaModule.showStackOperations(sample2);
        
        pdaModule.generateReport();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] PDA Module failed: " << e.what() << std::endl;
    }
    
    // ========================================================================
    // CHOMSKY HIERARCHY COMPARISON
    // ========================================================================
    printHeader("CHOMSKY HIERARCHY DEMONSTRATION");
    
    std::cout << "┌─────────────────────┬──────────────────┬──────────────────┐" << std::endl;
    std::cout << "│ Aspect              │ DFA (Regular)    │ PDA (Context-Free)│" << std::endl;
    std::cout << "├─────────────────────┼──────────────────┼──────────────────┤" << std::endl;
    std::cout << "│ Chomsky Type        │ Type 3           │ Type 2           │" << std::endl;
    std::cout << "│ Memory              │ None (stateless) │ Stack (unbounded)│" << std::endl;
    std::cout << "│ Can match patterns  │ ✓ Yes            │ ✓ Yes            │" << std::endl;
    std::cout << "│ Can count/pair      │ ✗ No             │ ✓ Yes            │" << std::endl;
    std::cout << "│ Grammar             │ Regular (a→αB)   │ CFG (A→α)        │" << std::endl;
    std::cout << "│ Example task        │ *.exe detection  │ SYN-ACK pairing  │" << std::endl;
    std::cout << "│ Complexity          │ O(n)             │ O(n)             │" << std::endl;
    std::cout << "└─────────────────────┴──────────────────┴──────────────────┘" << std::endl;
    
    std::cout << "\n[KEY INSIGHT]" << std::endl;
    std::cout << "The Chomsky Hierarchy demonstrates computational power:" << std::endl;
    std::cout << "  • Type 3 (Regular): Fast pattern matching, no memory" << std::endl;
    std::cout << "  • Type 2 (CF): Can handle nested/paired structures" << std::endl;
    std::cout << "  • Security systems need BOTH for comprehensive detection" << std::endl;
    
    std::cout << "\n[EXECUTION COMPLETE]" << std::endl;
    std::cout << "Results saved to: output/" << std::endl;
    
    return 0;
}