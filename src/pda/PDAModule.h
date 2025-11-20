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
    
    // Process a single packet
    bool processPacket(const std::string& packet, std::vector<std::string>& operations);
    
    // Validate a sequence of packets
    bool validateSequence(const std::vector<std::string>& sequence);

public:
    PDAModule();
    
    // Module pipeline
    void loadDataset(const std::string& filepath);
    void defineCFG();          // NEW: Explicitly show the CFG
    void buildPDA();           // Build PDA from CFG
    void testAllTraces();      // Test all traces
    void showStackOperations(const std::vector<std::string>& sequence);
    void generateReport();
    
    // Getters
    const PDAMetrics& getMetrics() const { return metrics; }
};

} // namespace CS311

#endif // PDAMODULE_H