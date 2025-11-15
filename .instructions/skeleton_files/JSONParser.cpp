
// ============================================================
// JSONParser.cpp
// ============================================================

#include "JSONParser.h"

using json = nlohmann::json;

namespace CS311 {

std::vector<FilenameEntry> JSONParser::loadFilenameDataset(const std::string& filepath) {
    std::vector<FilenameEntry> dataset;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        std::cerr << "[ERROR] Could not open file: " << filepath << std::endl;
        return dataset;
    }
    
    std::cout << "[INFO] Loading filename dataset: " << filepath << std::endl;
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        if (line.empty()) continue;
        
        try {
            json j = json::parse(line);
            FilenameEntry entry = parseFilenameEntry(j);
            dataset.push_back(entry);
        }
        catch (const json::parse_error& e) {
            std::cerr << "[WARNING] JSON parse error at line " << line_number 
                     << ": " << e.what() << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "[WARNING] Error at line " << line_number 
                     << ": " << e.what() << std::endl;
        }
    }
    
    file.close();
    std::cout << "[SUCCESS] Loaded " << dataset.size() << " filename entries" << std::endl;
    
    return dataset;
}

std::vector<TCPTrace> JSONParser::loadTCPDataset(const std::string& filepath) {
    std::vector<TCPTrace> dataset;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        std::cerr << "[ERROR] Could not open file: " << filepath << std::endl;
        return dataset;
    }
    
    std::cout << "[INFO] Loading TCP trace dataset: " << filepath << std::endl;
    
    std::string line;
    int line_number = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        if (line.empty()) continue;
        
        try {
            json j = json::parse(line);
            TCPTrace trace = parseTCPTrace(j);
            dataset.push_back(trace);
        }
        catch (const json::parse_error& e) {
            std::cerr << "[WARNING] JSON parse error at line " << line_number 
                     << ": " << e.what() << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "[WARNING] Error at line " << line_number 
                     << ": " << e.what() << std::endl;
        }
    }
    
    file.close();
    
    int valid_count = 0;
    for (const auto& trace : dataset) {
        if (trace.valid) valid_count++;
    }
    
    std::cout << "[SUCCESS] Loaded " << dataset.size() << " TCP traces" << std::endl;
    std::cout << "  Valid sequences: " << valid_count << std::endl;
    std::cout << "  Invalid sequences: " << (dataset.size() - valid_count) << std::endl;
    
    return dataset;
}

FilenameEntry JSONParser::parseFilenameEntry(const nlohmann::json& j) {
    FilenameEntry entry;
    
    // Required fields
    if (j.contains("filename")) {
        entry.filename = j["filename"].get<std::string>();
    }
    
    // Optional fields with defaults
    entry.technique = j.value("technique", "Unknown");
    entry.category = j.value("category", "Unknown");
    entry.detected_by = j.value("detected_by", "Unknown");
    entry.is_malicious = true;  // All entries in dataset are malicious
    
    return entry;
}

TCPTrace JSONParser::parseTCPTrace(const nlohmann::json& j) {
    TCPTrace trace;
    
    // Required fields
    if (j.contains("trace_id")) {
        trace.trace_id = j["trace_id"].get<std::string>();
    }
    
    if (j.contains("sequence") && j["sequence"].is_array()) {
        for (const auto& packet : j["sequence"]) {
            trace.sequence.push_back(packet.get<std::string>());
        }
    }
    
    if (j.contains("valid")) {
        trace.valid = j["valid"].get<bool>();
    }
    
    // Optional fields
    trace.description = j.value("description", "");
    trace.category = j.value("category", "Unknown");
    
    return trace;
}

} // namespace CS311