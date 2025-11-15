/**
 * File: JSONParser.h
 * Purpose: Parse JSONL datasets for filenames and TCP traces (simple parser)
 */

#ifndef JSONPARSER_H
#define JSONPARSER_H

#include "Utils.h"
#include <fstream>
#include <iostream>
#include <sstream>

namespace CS311 {

class JSONParser {
public:
    static std::vector<FilenameEntry> loadFilenameDataset(const std::string& filepath);
    static std::vector<TCPTrace> loadTCPDataset(const std::string& filepath);
private:
    static FilenameEntry parseFilenameEntrySimple(const std::string& line);
    static TCPTrace parseTCPTraceSimple(const std::string& line);
    // helper
    static std::string extractString(const std::string& src, const std::string& key);
};

} // namespace CS311

#endif // JSONPARSER_H
