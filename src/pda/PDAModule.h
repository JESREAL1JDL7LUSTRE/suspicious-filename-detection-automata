/**
 * PDAModule.h - IMPROVED VERSION
 * Header for PDA-based protocol validation module
 */

#ifndef PDAMODULE_H
#define PDAMODULE_H

#include "Utils.h"
#include "JSONParser.h"
#include <vector>
#include <string>

namespace CS311 {

// PDA States for TCP handshake
enum PDAStates {
    Q_START = 0,
    Q_SYN_RECEIVED = 1,
    Q_SYNACK_RECEIVED = 2,
    Q_ACCEPT = 3,
    Q_ERROR = 4
};

class PDAModule {
private:
    std::vector<TCPTrace> dataset;
    PDA pda;
    PDAMetrics metrics;
    bool strictHandshakeOnly = false;
    
    // Process a single packet
    bool processPacket(const std::string& packet, std::vector<std::string>& operations);
    
    // Validate a sequence of packets
    bool validateSequence(const std::vector<std::string>& sequence);

public:
    PDAModule();
    void setStrictHandshake(bool strict) { strictHandshakeOnly = strict; }
    
    // Module pipeline
    void loadDataset(const std::string& filepath);
    void defineCFG();          // NEW: Explicitly show the CFG
    void buildPDA();           // Build PDA from CFG
    void printCFG();           // Canonical sets (V, Σ, P, S)
    void exportPDAConstruction(const std::string& outPath); // Log rule-driven push/pop
    void testAllTraces();      // Test all traces
    void showStackOperations(const std::vector<std::string>& sequence);
    void generateReport();
    // Export Graphviz DOT representing the PDA structure
    std::string exportGraphviz() const;
    // Filter loaded dataset by a set of trace_ids (e.g., filenames)
    void filterDatasetByTraceIds(const std::set<std::string>& ids);
    
    // Getters
    const PDAMetrics& getMetrics() const { return metrics; }
};

} // namespace CS311

#endif // PDAMODULE_H