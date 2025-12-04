/**
 * DFAModule.h - IMPROVED VERSION
 * Header for DFA-based pattern detection module
 */

#ifndef DFAMODULE_H
#define DFAMODULE_H

#include "Utils.h"
#include "JSONParser.h"
#include "RegexParser.h"
#include <vector>
#include <string>
#include <set>

namespace CS311 {

class DFAModule {
private:
    std::vector<FilenameEntry> dataset;
    std::vector<std::string> regex_patterns;
    std::vector<std::string> pattern_names;
    std::vector<NFA> nfas;
    std::vector<DFA> dfas;
    std::vector<DFA> minimized_dfas;
    std::vector<DFA> grouped_dfas;
    DFAMetrics metrics;
    
    // NEW: Helper methods for NFA to DFA conversion
    DFA subsetConstruction(const NFA& nfa);
    std::set<int> epsilonClosure(const NFA& nfa, const std::set<int>& states);
    std::set<int> move(const NFA& nfa, const std::set<int>& states, char symbol);
    
    // NEW: Actually use DFAs for testing
    bool testFilenameWithDFA(const std::string& filename, std::string& matched_pattern);
    bool runDFA(const DFA& dfa, const std::string& input);
    bool checkAdditionalPatterns(const std::string& filename, std::string& matched_pattern);

public:
    DFAModule();
    
    // Module pipeline
    void loadDataset(const std::string& filepath);
    void definePatterns();
    void buildNFAs();
    void convertToDFAs();
    void minimizeDFAs();
    void applyIGA();
    void testPatterns();
    void generateReport();
    // Scan custom file paths using DFA modules
    void scanFiles(const std::vector<std::string>& filePaths);
    void generateScanReport(const std::vector<std::string>& filePaths, 
                           const std::vector<bool>& detected, 
                           const std::vector<std::string>& matched_patterns);
    // Export Graphviz DOT for the built DFAs (after convertToDFAs / applyIGA)
    std::string exportGraphvizAll() const;
    // Export single DFA cluster by index (useful to write separate files)
    std::string exportGraphvizFor(size_t index) const;
    
    // Getters
    size_t getDfaCount() const;
    const DFAMetrics& getMetrics() const { return metrics; }
    const std::vector<std::string>& getPatternNames() const { return pattern_names; }
    const std::vector<std::string>& getRegexPatterns() const { return regex_patterns; }
};

} // namespace CS311

#endif // DFAMODULE_H