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

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Ensure Windows console uses UTF-8 so box-drawing/Unicode prints correctly
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

    // Create module instances and ensure output directory exists
    std::filesystem::create_directories("output");

    // Check if we're in scan mode (file paths provided as arguments)
    bool scanMode = false;
    bool dfaVerbose = false;
    bool strictHandshake = false;
    std::vector<std::string> filePaths;
    // Carry DFA-suspicious filenames across to PDA
    std::vector<std::string> suspiciousGlobal;
    // Parse arguments: files imply scanMode; flag --dfa-verbose enables verbose DFA
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dfa-verbose") {
            dfaVerbose = true;
        } else if (arg == "--strict-handshake") {
            strictHandshake = true;
        } else {
            scanMode = true;
            filePaths.push_back(arg);
        }
    }

    std::cout << "Starting simulator..." << std::endl;
    std::cout << "╔══════════════════════════════════════════════════════════════╗" << std::endl;
    if (scanMode) {
        std::cout << "║      FILE SCAN MODULE - SUSPICIOUS FILENAME DETECTION       ║" << std::endl;
    } else {
        std::cout << "║      CS311 CHOMSKY HIERARCHY SECURITY SIMULATOR             ║" << std::endl;
        std::cout << "║      Filename Detection (DFA) & TCP Validation (PDA)         ║" << std::endl;
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    // ========================================================================
    // MODULE 1: DFA-based Filename Pattern Detection (Type-3 Regular)
    // ========================================================================
    // MODULE 1 header (box style)
    std::cout << "\n╔═══════════════════════════════════╗" << std::endl;
    std::cout << "MODULE 1 — Filename Detection (DFA)" << std::endl;
    std::cout << "╚═══════════════════════════════════╝" << std::endl;
    std::cout << "Chomsky Type-3: Regular Language" << std::endl;
    std::cout << "\nUses Deterministic Finite Automaton (DFA)" << std::endl;
    std::cout << "• Memory: finite-state" << std::endl;
    std::cout << "• Function: pattern matching" << std::endl;
    std::cout << std::endl;
    
    DFAModule dfaModule;
    try {
        // Ensure output directory exists
        std::filesystem::create_directories("output");
        
        if (scanMode) {
            // SCAN MODE: Scan provided file paths
            // Build DFAs silently, then show file-by-file processing
            dfaModule.definePatterns();
            dfaModule.buildNFAs();          // Regex → NFA (Thompson's Construction)
            dfaModule.convertToDFAs();       // NFA → DFA (Subset Construction)
            dfaModule.minimizeDFAs();        // DFA minimization (Hopcroft's)
            
            // Scan the provided files (this will show file-by-file details)
            if (dfaVerbose) {
                dfaModule.scanFiles(filePaths); // uses verbose DFA in module
            } else {
                // non-verbose scan: similar path but without transition prints
                std::vector<bool> detected;
                std::vector<std::string> matched;
                std::cout << "\n[INFO] Total files to scan: " << filePaths.size() << std::endl;
                for (size_t i=0;i<filePaths.size();++i){
                    std::string fileName = filePaths[i];
                    size_t lastSlash = fileName.find_last_of("/\\");
                    if (lastSlash != std::string::npos) fileName = fileName.substr(lastSlash+1);
                    std::cout << "\n[" << (i+1) << "/" << filePaths.size() << "] Analyzing: " << fileName << std::endl;
                    std::string m; bool d = dfaModule.testFilenameWithDFA(fileName, m);
                    detected.push_back(d); matched.push_back(m);
                    std::cout << "  ✓ Result: " << (d?"SUSPICIOUS ("+m+")":"SAFE") << std::endl;
                }
                dfaModule.generateScanReport(filePaths, detected, matched);
            }
        } else {
            // NORMAL MODE: Use dataset files with structured steps
            // 1. Dataset Loading
            std::cout << "1. Dataset Loading" << std::endl;
            std::cout << "[INFO] Reading unified dataset: archive/unified_dataset.jsonl" << std::endl;
            dfaModule.loadDataset("archive/unified_dataset.jsonl");
            std::cout << "✓ SUCCESS — Single-source unified dataset loaded" << std::endl;
            std::cout << "✓ SUCCESS — Total filenames staged: " << dfaModule.getMetrics().filenames_tested << std::endl;
            std::cout << std::endl;

            // 2. Regex Pattern Definition
            std::cout << "2. Regex Pattern Definition" << std::endl;
            dfaModule.definePatterns();

            // 3. Regex → NFA (Thompson’s Construction)
            std::cout << "3. Regex → NFA (Thompson’s Construction)" << std::endl;
            dfaModule.buildNFAs();
            std::cout << "✓ SUCCESS — Total NFA states: " << dfaModule.getMetrics().total_nfa_states << std::endl;
            std::cout << std::endl;

            // 4. NFA → DFA (Subset Construction)
            std::cout << "4. NFA → DFA (Subset Construction)" << std::endl;
            dfaModule.convertToDFAs();
            std::cout << "✓ SUCCESS — Total DFA states: " << dfaModule.getMetrics().total_dfa_states_before_min << std::endl;
            std::cout << std::endl;

            // 5. DFA Minimization (Hopcroft)
            std::cout << "5. DFA Minimization (Hopcroft)" << std::endl;
            dfaModule.minimizeDFAs();        
                // Export regular grammars for each pattern
                for (size_t i = 0; i < dfaModule.getDfaCount(); ++i) {
                    std::string path = "output/grammar_" + std::to_string(i) + ".txt";
                    dfaModule.exportRegularGrammarForPattern(i, path);
                    std::cout << "[OK] Wrote Regular Grammar: " << path << std::endl;
                }
                // Export regular grammars for each pattern
                for (size_t i = 0; i < dfaModule.getDfaCount(); ++i) {
                    std::string path = "output/grammar_" + std::to_string(i) + ".txt";
                    dfaModule.exportRegularGrammarForPattern(i, path);
                    std::cout << "[OK] Wrote Regular Grammar: " << path << std::endl;
                }

            // 6. Sample Filename Detection (Randomized)
            std::cout << "6. Sample Filename Detection (Randomized)" << std::endl;
            dfaModule.testPatterns();

            // 6b. DFA→PDA: Classify dataset and collect suspicious filenames
            std::cout << "6b. DFA Classification → Collect suspicious filenames" << std::endl;
            suspiciousGlobal = dfaModule.classifyDatasetAndReturnDetected();
            std::cout << "  [INFO] DFA flagged " << suspiciousGlobal.size() << " entries as suspicious" << std::endl;

            // 7. DFA Summary
            std::cout << "7. DFA Summary" << std::endl;
            const auto& dfaM = dfaModule.getMetrics();
            std::cout << "True Positives:   " << dfaM.true_positives << std::endl;
            std::cout << "False Negatives:   " << dfaM.false_negatives << std::endl;
            std::cout << "Accuracy:      " << dfaM.detection_accuracy << "%" << std::endl;
            std::cout << "\nExecution Time:" << std::endl;
            std::cout << "  Total:        " << dfaM.total_execution_time_ms << " ms" << std::endl;
            std::cout << "  Per file:     " << dfaM.avg_matching_time_ms << " ms" << std::endl;
            std::cout << std::endl;

            // Detailed report remains available
            dfaModule.generateReport();
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] DFA Module failed: " << e.what() << std::endl;
        return 1;
    }
    
    // ========================================================================
    // MODULE 2: PDA-based TCP Protocol Validation (Type-2 Context-Free)
    // Skip PDA module in scan mode
    // ========================================================================
    if (scanMode) {
        std::cout << "\n[INFO] Scan complete. PDA module skipped in scan mode." << std::endl;
        return 0;
    }
    
    // MODULE 2 header (box style)
    std::cout << "\n╔═══════════════════════════════════╗" << std::endl;
    std::cout << "MODULE 2 — TCP Protocol Validation (PDA)" << std::endl;
    std::cout << "╚═══════════════════════════════════╝" << std::endl;
    std::cout << "Chomsky Type-2: Context-Free Language" << std::endl;
    std::cout << "\nUses Pushdown Automaton (PDA)" << std::endl;
    std::cout << "• Memory: stack" << std::endl;
    std::cout << "• Function: sequence validation" << std::endl;
    std::cout << std::endl;
    
    PDAModule pdaModule;
    try {
        // 1. Loading TCP Trace Dataset (augmented from other archives)
        std::cout << "1. Loading TCP Trace Dataset" << std::endl;
        std::cout << "[INFO] Reading: archive/unified_dataset.jsonl" << std::endl;
        pdaModule.loadDataset("archive/unified_dataset.jsonl");
        // Filter PDA dataset to only those flagged by DFA (trace_id equals filename)
        {
            std::set<std::string> suspiciousSet(suspiciousGlobal.begin(), suspiciousGlobal.end());
            pdaModule.filterDatasetByTraceIds(suspiciousSet);
        }
        if (strictHandshake) {
            std::cout << "[INFO] Strict handshake-only CFG enabled" << std::endl;
            pdaModule.setStrictHandshake(true);
        }
        const auto& pdaM1 = pdaModule.getMetrics();
        std::cout << "✓ SUCCESS — Loaded " << pdaM1.total_traces << " traces" << std::endl;
        std::cout << "Valid:   " << pdaM1.valid_traces << std::endl;
        std::cout << "Invalid: " << pdaM1.invalid_traces << std::endl;
        std::cout << std::endl;

        // 2. CFG for TCP 3-Way Handshake
        std::cout << "2. CFG for TCP 3-Way Handshake" << std::endl;
        pdaModule.defineCFG();          // Show the Context-Free Grammar
            pdaModule.printCFG();           // Canonical sets notation

        // 3. PDA Structure
        std::cout << "3. PDA Structure" << std::endl;
        pdaModule.buildPDA();           // Build PDA from CFG
            pdaModule.exportPDAConstruction("output/pda_construction.txt");
            std::cout << "[OK] Wrote PDA construction log: output/pda_construction.txt" << std::endl;

        // 4. PDA Validation — Sample Randomized Results
        std::cout << "4. PDA Validation — Sample Randomized Results" << std::endl;
        pdaModule.testAllTraces();      // Validate all traces
        
        // 5. Stack Trace Examples
        std::cout << "5. Stack Trace Examples" << std::endl;
        std::vector<std::string> sample1 = {"SYN", "SYN-ACK", "ACK"};
        pdaModule.showStackOperations(sample1);
        
        std::vector<std::string> sample2 = {"SYN", "ACK"};
        pdaModule.showStackOperations(sample2);

        // 6. PDA Summary
        std::cout << "6. PDA Summary" << std::endl;
        pdaModule.generateReport();
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] PDA Module failed: " << e.what() << std::endl;
    }

    // After modules have been built and reports generated, write separate DOT files
    try {
        // Write one DOT file per minimized DFA with proper naming
        size_t dfaCount = dfaModule.getDfaCount();
        const auto& patternNames = dfaModule.getPatternNames();
        const auto& regexPatterns = dfaModule.getRegexPatterns();
        
        for (size_t i = 0; i < dfaCount; ++i) {
            std::ostringstream dot;
            
            // ARTIFACT NAMING: Include pattern name and alphabet in headers
            std::string patternName = (i < patternNames.size()) ? patternNames[i] : ("pattern_" + std::to_string(i));
            std::string regexPattern = (i < regexPatterns.size()) ? regexPatterns[i] : "";
            
            dot << "// Minimized DFA for pattern: " << patternName << "\n";
            dot << "// Regex: " << regexPattern << "\n";
            dot << "// Alphabet: Printable ASCII (32-126) - per-character tokenization\n";
            dot << "// Tokenization: Per-character (not per-lexeme)\n";
            dot << "digraph G {\n";
            dot << "  rankdir=LR;\n";
            dot << "  label=\"DFA for " << patternName << " (regex: " << regexPattern << ")\";\n";
            dot << dfaModule.exportGraphvizFor(i) << "\n";
            dot << "  start [shape=Mdiamond];\n";
            dot << "  end [shape=Msquare];\n";
            dot << "  start -> d" << i << "_s0;\n";
            dot << "}\n";

            // ARTIFACT NAMING: Save as dfa_min_i.dot
            std::string path = "output/dfa_min_" + std::to_string(i) + ".dot";
            std::ofstream out(path);
            if (out.is_open()) {
                out << dot.str();
                out.close();
                std::cout << "[OK] Wrote minimized DFA DOT: " << path << " (pattern: " << patternName << ")" << std::endl;
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

        // Per-DFA JSONs with proper naming (dfa_min_i.json)
        size_t dfaCount = dfaModule.getDfaCount();
        for (size_t i = 0; i < dfaCount; ++i) {
            parseGraphvizToJson(dfaModule.exportGraphvizFor(i), "DFA", "output/dfa_min_" + std::to_string(i) + ".json");
        }
        // PDA JSON
        parseGraphvizToJson(pdaModule.exportGraphviz(), "PDA", "output/pda.json");
        // Combined JSON (optional)
        parseGraphvizToJson(dfaModule.exportGraphvizAll() + "\n" + pdaModule.exportGraphviz(), "COMBINED", "output/automata.json");
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Failed writing JSON files: " << e.what() << std::endl;
    }
    
    // ========================================================================
    // CHOMSKY HIERARCHY COMPARISON (skip in scan mode)
    // ========================================================================
    if (scanMode) {
        return 0;
    }
    
    printHeader("CHOMSKY HIERARCHY DEMONSTRATION");
    
    std::cout << "┌─────────────────────┬──────────────────┬──────────────────┐" << std::endl;
    std::cout << "│ Aspect              │ DFA (Regular)    │ PDA (Context-Free)│" << std::endl;
    std::cout << "├─────────────────────┼──────────────────┼──────────────────┤" << std::endl;
    std::cout << "│ Chomsky Type        │ Type 3           │ Type 2           │" << std::endl;
    std::cout << "│ Memory              │ Finite-state     │ Stack (unbounded)│" << std::endl;
    std::cout << "│ Can match patterns  │ ✓ Yes            │ ✓ Yes            │" << std::endl;
    std::cout << "│ Can count/pair      │ ✗ No             │ ✓ Yes            │" << std::endl;
    std::cout << "│ Grammar             │ Regular (a→αB)   │ CFG (A→α)        │" << std::endl;
    std::cout << "│ Example task        │ *.exe detection  │ SYN-ACK pairing  │" << std::endl;
    std::cout << "│ Complexity          │ O(n)             │ O(n)             │" << std::endl;
    std::cout << "└─────────────────────┴──────────────────┴──────────────────┘" << std::endl;
    
    std::cout << "\nHAHAHHA" << std::endl;
    std::cout << "\nAll automata saved to /output/." << std::endl;
    
    return 0;
}