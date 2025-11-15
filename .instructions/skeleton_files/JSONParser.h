/**
 * File: JSONParser.h
 * Purpose: Parse JSONL datasets for filenames and TCP traces
 */

#ifndef JSONPARSER_H
#define JSONPARSER_H

#include "Utils.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

namespace CS311 {

class JSONParser {
public:
    /**
     * Load malicious filename dataset from JSONL file
     * @param filepath Path to Malicious_file_trick_detection.jsonl
     * @return Vector of FilenameEntry objects
     */
    static std::vector<FilenameEntry> loadFilenameDataset(const std::string& filepath);
    
    /**
     * Load TCP handshake trace dataset from JSONL file
     * @param filepath Path to tcp_handshake_traces_expanded.jsonl
     * @return Vector of TCPTrace objects
     */
    static std::vector<TCPTrace> loadTCPDataset(const std::string& filepath);
    
private:
    /**
     * Parse a single JSON line into FilenameEntry
     */
    static FilenameEntry parseFilenameEntry(const nlohmann::json& j);
    
    /**
     * Parse a single JSON line into TCPTrace
     */
    static TCPTrace parseTCPTrace(const nlohmann::json& j);
};

} // namespace CS311

#endif // JSONPARSER_H
