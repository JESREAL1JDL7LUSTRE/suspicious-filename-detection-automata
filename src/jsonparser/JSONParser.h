/**
 * JSONParser.h
 * Simple JSONL parser for loading datasets
 */

#ifndef JSONPARSER_H
#define JSONPARSER_H

#include "Utils.h"
#include <string>
#include <vector>
#include <fstream>

namespace CS311 {

class JSONParser {
private:
    // Helper to extract string value from JSON
    static std::string extractString(const std::string& src, const std::string& key);
    
    // Parse individual entries
    static FilenameEntry parseFilenameEntrySimple(const std::string& line);
    static TCPTrace parseTCPTraceSimple(const std::string& line);

public:
    // Load datasets from JSONL files
    static std::vector<FilenameEntry> loadFilenameDataset(const std::string& filepath);
    static std::vector<TCPTrace> loadTCPDataset(const std::string& filepath);
    // Load TCP traces from CSV (trace_id,sequence,valid,description,category)
    static std::vector<TCPTrace> loadTCPDatasetCSV(const std::string& filepath);
};

} // namespace CS311

#endif // JSONPARSER_H