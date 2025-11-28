/**
 * main.cpp - IMPROVED VERSION
 * Main Program - Now follows the architecture properly
 */
#include <iostream>
#ifdef _WIN32
#include <windows.h>
#endif
#include <filesystem>
#include "Utils.h"
#include "DFAModule.h"
#include "PDAModule.h"
#include "AutomataJSON.h"

#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>

using namespace CS311;

int main() {
#ifdef _WIN32
    // Ensure Windows console uses UTF-8 so box-drawing/Unicode prints correctly
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    // Create module instances and ensure output directory exists
    
    
    std::filesystem::create_directories("output");

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
        // Ensure output directory exists
        std::filesystem::create_directories("output");
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

    // After modules have been built and reports generated, write separate DOT files
    try {
        // Write one DOT file per DFA
        size_t dfaCount = dfaModule.getDfaCount();
        for (size_t i = 0; i < dfaCount; ++i) {
            std::ostringstream dot;
            dot << "digraph G {\n";
            dot << "  rankdir=LR;\n";
            dot << dfaModule.exportGraphvizFor(i) << "\n";
            dot << "  start [shape=Mdiamond];\n";
            dot << "  end [shape=Msquare];\n";
            dot << "  start -> d" << i << "_s0;\n";
            dot << "}\n";

            std::string path = "output/dfa_" + std::to_string(i) + ".dot";
            std::ofstream out(path);
            if (out.is_open()) {
                out << dot.str();
                out.close();
                std::cout << "[OK] Wrote DFA DOT: " << path << std::endl;
            } else {
                std::cerr << "[WARN] Could not open " << path << std::endl;
            }
        }

        // Write PDA DOT
        {
            std::ostringstream dot;
            dot << "digraph G {\n";
            dot << "  rankdir=LR;\n";
            dot << pdaModule.exportGraphviz() << "\n";
            dot << "  start [shape=Mdiamond];\n";
            dot << "  end [shape=Msquare];\n";
            dot << "  start -> p_s0;\n";
            dot << "}\n";

            std::string path = "output/pda.dot";
            std::ofstream out(path);
            if (out.is_open()) {
                out << dot.str();
                out.close();
                std::cout << "[OK] Wrote PDA DOT: " << path << std::endl;
            } else {
                std::cerr << "[WARN] Could not open " << path << std::endl;
            }
        }

        // Also keep the combined file for convenience
        {
            std::ostringstream dot;
            dot << "digraph G {\n";
            dot << "  rankdir=LR;\n";
            dot << dfaModule.exportGraphvizAll() << "\n";
            dot << pdaModule.exportGraphviz() << "\n";
            dot << "  start [shape=Mdiamond];\n";
            dot << "  end [shape=Msquare];\n";
            dot << "  start -> d0_s0;\n";
            dot << "  start -> p_s0;\n";
            dot << "}\n";

            std::string path = "output/graph_from_run.dot";
            std::ofstream out(path);
            if (out.is_open()) {
                out << dot.str();
                out.close();
                std::cout << "[OK] Wrote combined DOT: " << path << std::endl;
            } else {
                std::cerr << "[WARN] Could not open " << path << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed writing DOT files: " << e.what() << std::endl;
    }

    // Emit JSON per automaton, mirroring the DOT outputs but structured
    try {
        std::filesystem::create_directories("output");

        auto trim = [](std::string s){
            size_t a = s.find_first_not_of(" \t");
            size_t b = s.find_last_not_of(" \t");
            if (a==std::string::npos) return std::string();
            return s.substr(a, b-a+1);
        };

        auto parseGraphvizToJson = [&](const std::string& gv, const std::string& type, const std::string& outPath){
            std::vector<NodeOut> nodes;
            std::vector<EdgeOut> edges;
            std::vector<std::string> accept; // TODO: populate from modules when available
            std::string start;

            std::istringstream iss(gv);
            std::string line;
            while (std::getline(iss, line)) {
                if (line.empty()) continue;
                auto arrowPos = line.find("->");
                if (arrowPos != std::string::npos) {
                    std::string left = trim(line.substr(0, arrowPos));
                    std::string right = trim(line.substr(arrowPos+2));
                    std::string target;
                    size_t bracket = right.find('[');
                    if (bracket != std::string::npos) {
                        target = trim(right.substr(0, bracket));
                    } else {
                        size_t semi = right.find(';');
                        target = trim(semi==std::string::npos ? right : right.substr(0, semi));
                    }
                    std::string label;
                    size_t labStart = right.find("label=");
                    if (labStart != std::string::npos) {
                        size_t q1 = right.find('"', labStart);
                        size_t q2 = (q1!=std::string::npos) ? right.find('"', q1+1) : std::string::npos;
                        if (q1!=std::string::npos && q2!=std::string::npos && q2>q1) {
                            label = right.substr(q1+1, q2-q1-1);
                        }
                    }
                    if (!left.empty() && !target.empty()) {
                        edges.push_back({left, target, label});
                        nodes.push_back({left, left});
                        nodes.push_back({target, target});
                    }
                }
            }
            std::sort(nodes.begin(), nodes.end(), [](const NodeOut& a, const NodeOut& b){return a.id < b.id;});
            nodes.erase(std::unique(nodes.begin(), nodes.end(), [](const NodeOut& a, const NodeOut& b){return a.id==b.id;}), nodes.end());

            start = nodes.empty()? std::string("S0") : nodes.front().id;
            for (const auto& n : nodes) { if (n.id.find("_s0")!=std::string::npos) { start = n.id; break; } }

            bool ok = writeAutomataJson(type, start, accept, nodes, edges, outPath);
            if (ok) std::cout << "[OK] Wrote " << outPath << std::endl; else std::cerr << "[WARN] Could not write " << outPath << std::endl;
        };

        // Per-DFA JSONs
        size_t dfaCount = dfaModule.getDfaCount();
        for (size_t i = 0; i < dfaCount; ++i) {
            parseGraphvizToJson(dfaModule.exportGraphvizFor(i), "DFA", "output/dfa_" + std::to_string(i) + ".json");
        }
        // PDA JSON
        parseGraphvizToJson(pdaModule.exportGraphviz(), "PDA", "output/pda.json");
        // Combined JSON (optional)
        parseGraphvizToJson(dfaModule.exportGraphvizAll() + "\n" + pdaModule.exportGraphviz(), "COMBINED", "output/automata.json");
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed writing JSON files: " << e.what() << std::endl;
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