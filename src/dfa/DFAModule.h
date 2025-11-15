/**
 * DFAModule.h
 */
#ifndef DFAMODULE_H
#define DFAMODULE_H

#include "Utils.h"
#include "JSONParser.h"
#include "RegexParser.h"
#include <vector>
#include <string>
#include <chrono>

namespace CS311 {

class DFAModule {
public:
    DFAModule();
    void loadDataset(const std::string& filepath);
    void definePatterns();
    void buildNFAs();
    void convertToDFAs();
    void minimizeDFAs();
    void applyIGA();
    void testPatterns();
    void generateReport();
    const DFAMetrics& getMetrics() const { return metrics; }
private:
    std::vector<FilenameEntry> dataset;
    std::vector<std::string> regex_patterns;
    std::vector<std::string> pattern_names;
    std::vector<NFA> nfas;
    std::vector<DFA> dfas;
    std::vector<DFA> minimized_dfas;
    std::vector<DFA> grouped_dfas;
    DFAMetrics metrics;
    bool testFilename(const std::string& filename, std::string& matched_pattern);
};

} // namespace CS311

#endif // DFAMODULE_H
