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
    // NEW: Content patterns (regex → NFA → DFA → minimized DFA)
    std::vector<std::string> content_regex_patterns;
    std::vector<std::string> content_pattern_names;
    std::vector<NFA> content_nfas;
    std::vector<DFA> content_dfas;
    std::vector<DFA> content_minimized_dfas;
    DFAMetrics metrics;
    bool combineAll = false; // when true, build a single combined DFA for all patterns
    // Per-pattern evaluation metrics
    struct PatternMetrics { int tp=0; int fp=0; int fn=0; int tn=0; double precision=0; double recall=0; double f1=0; };
    std::map<std::string, PatternMetrics> perPattern;
    unsigned int rngSeed = 311U; // reproducible sampling seed
    
    // NEW: Helper methods for NFA to DFA conversion
    DFA subsetConstruction(const NFA& nfa);
    std::set<int> epsilonClosure(const NFA& nfa, const std::set<int>& states);
    std::set<int> move(const NFA& nfa, const std::set<int>& states, char symbol);
    
    // NEW: Actually use DFAs for testing (non-verbose helpers kept private; public wrappers below)
    bool testFilenameWithDFAVerbose(const std::string& filename, std::string& matched_pattern);
    bool runDFAVerbose(const DFA& dfa, const std::string& input);
    bool checkAdditionalPatterns(const std::string& filename, std::string& matched_pattern);
    // Tokenization discipline: current DFA is per-character; helper to expose alphabet
    std::set<char> getAlphabetUnion() const;
    void setSeed(unsigned int seed) { rngSeed = seed; }

public:
    DFAModule();
    void setCombineAllPatterns(bool on) { combineAll = on; }
    // Clear current staged filename dataset and reset basic metrics
    void clearDataset();
    
    // Module pipeline
    void loadDataset(const std::string& filepath);
    // NEW: Stage filename entries derived from TCP trace datasets
    void loadFilenamesFromTCPJsonl(const std::string& filepath);
    void loadFilenamesFromCSVTraces(const std::string& filepath);
    void definePatterns();
    void buildNFAs();
    void convertToDFAs();
    void minimizeDFAs();
    // Hopcroft's DFA minimization (actual implementation)
    DFA hopcroftMinimize(const DFA& dfa, int& refinementSteps, std::vector<std::set<int>>& finalPartitions);

    // NEW: Content DFA pipeline
    void defineContentPatterns();
    void buildContentNFAs();
    void convertContentToDFAs();
    void minimizeContentDFAs();
    
    // Export Type-3 Regular Grammar for a pattern (V, Σ, P, S)
    void exportRegularGrammarForPattern(size_t index, const std::string& outPath) const;
    void testPatterns();
    void generateReport();
    // Scan custom file paths using DFA modules
    void scanFiles(const std::vector<std::string>& filePaths);
    void generateScanReport(const std::vector<std::string>& filePaths, 
                           const std::vector<bool>& detected, 
                           const std::vector<std::string>& matched_patterns);
    // Public non-verbose DFA run/classification
    bool runDFA(const DFA& dfa, const std::string& input);
    bool testFilenameWithDFA(const std::string& filename, std::string& matched_pattern);
    // NEW: Return all matched filename patterns (indices) for detailed reporting
    std::vector<size_t> testFilenameMatchesAll(const std::string& filename);
    // NEW: DFA content scan (simple regex-derived checks). Returns true if content looks malicious.
    bool scanContent(const std::string& content);
    bool testContentWithDFA(const std::string& content, std::string& matched_pattern);
    // Integrate evaluation CSVs: combined_random (type column) and malware
    // Synthesizes filenames from hashes and routes by label:
    // - combined_random.csv: type=1 -> benign, type=0 -> malicious
    // - malware.csv: all rows treated as malicious
    void integrateCombinedAndMalwareCSVs(const std::string& combinedCsvPath,
                                         const std::string& malwareCsvPath);
    // Export Graphviz DOT for the built DFAs (after convertToDFAs / applyIGA)
    std::string exportGraphvizAll() const;
    // Export single DFA cluster by index (useful to write separate files)
    std::string exportGraphvizFor(size_t index) const;
    // NEW: Content DFA Graphviz export
    std::string exportGraphvizAllContent() const;
    std::string exportGraphvizForContent(size_t index) const;
    
    // Getters
    size_t getDfaCount() const;
    const DFAMetrics& getMetrics() const { return metrics; }
    const std::vector<std::string>& getPatternNames() const { return pattern_names; }
    const std::vector<std::string>& getRegexPatterns() const { return regex_patterns; }
    const std::vector<std::string>& getContentPatternNames() const { return content_pattern_names; }
    const std::vector<std::string>& getContentRegexPatterns() const { return content_regex_patterns; }
    size_t getContentDfaCount() const;

    // NEW: Classify all loaded dataset filenames and return those flagged by DFA
    std::vector<std::string> classifyDatasetAndReturnDetected();
    // NEW: Export Type-3 grammar for content pattern
    void exportRegularGrammarForContentPattern(size_t index, const std::string& outPath) const;
    // NEW: Content scan report module output
    void generateContentScanReport();
};

} // namespace CS311

#endif // DFAMODULE_H