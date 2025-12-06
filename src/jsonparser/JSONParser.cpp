// Simple JSONL parser implementation (lightweight, tolerant)
#include "JSONParser.h"
#include <set>
#include <algorithm>
#include <sstream>
#include <cctype>

namespace CS311 {

std::string JSONParser::extractString(const std::string& src, const std::string& key) {
    size_t pos = src.find('"' + key + '"');
    if (pos == std::string::npos) return "";
    size_t colon = src.find(':', pos);
    if (colon == std::string::npos) return "";
    size_t first_quote = src.find('"', colon);
    if (first_quote == std::string::npos) return "";
    size_t second_quote = src.find('"', first_quote + 1);
    if (second_quote == std::string::npos) return "";
    return src.substr(first_quote + 1, second_quote - first_quote - 1);
}

FilenameEntry JSONParser::parseFilenameEntrySimple(const std::string& line) {
    FilenameEntry entry;
    entry.filename = extractString(line, "filename");
    entry.technique = extractString(line, "technique");
    entry.category = extractString(line, "category");
    entry.detected_by = extractString(line, "detected_by");
    
    // DATASET FIELD VALIDATION: Explicitly validate is_malicious from source
    size_t posMalicious = line.find("\"is_malicious\"");
    if (posMalicious != std::string::npos) {
        size_t colon = line.find(':', posMalicious);
        if (colon != std::string::npos) {
            size_t start = line.find_first_not_of(" \t", colon + 1);
            if (start != std::string::npos) {
                if (line.compare(start, 4, "true") == 0) {
                    entry.is_malicious = true;
                } else if (line.compare(start, 5, "false") == 0) {
                    entry.is_malicious = false;
                } else {
                    // Default to true if value is malformed
                    entry.is_malicious = true;
                }
            } else {
                entry.is_malicious = true; // default
            }
        } else {
            entry.is_malicious = true; // default
        }
    } else {
        // Field not found, default to true
        entry.is_malicious = true;
    }
    
    return entry;
}

TCPTrace JSONParser::parseTCPTraceSimple(const std::string& line) {
    TCPTrace trace;
    trace.trace_id = extractString(line, "trace_id");
    // extract sequence array "sequence": ["SYN","SYN-ACK",...]
    size_t pos = line.find("\"sequence\"");
    if (pos != std::string::npos) {
        size_t lbr = line.find('[', pos);
        size_t rbr = line.find(']', lbr == std::string::npos ? pos : lbr);
        if (lbr != std::string::npos && rbr != std::string::npos && rbr > lbr) {
            std::string array = line.substr(lbr + 1, rbr - lbr - 1);
            // split on '"'
            size_t i = 0;
            while (i < array.size()) {
                size_t q1 = array.find('"', i);
                if (q1 == std::string::npos) break;
                size_t q2 = array.find('"', q1 + 1);
                if (q2 == std::string::npos) break;
                std::string pkt = array.substr(q1 + 1, q2 - q1 - 1);
                trace.sequence.push_back(pkt);
                i = q2 + 1;
            }
        }
    }
    // valid boolean
    size_t posValid = line.find("\"valid\"");
    if (posValid != std::string::npos) {
        size_t colon = line.find(':', posValid);
        if (colon != std::string::npos) {
            size_t start = line.find_first_not_of(" \t", colon + 1);
            if (start != std::string::npos) {
                if (line.compare(start, 4, "true") == 0) trace.valid = true;
                else trace.valid = false;
            }
        }
    }
    trace.description = extractString(line, "description");
    trace.category = extractString(line, "category");
    trace.content = extractString(line, "content");
    return trace;
}

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
    int malicious_count = 0;
    int benign_count = 0;
    std::set<std::string> extensions;
    
    while (std::getline(file, line)) {
        line_number++;
        if (line.empty()) continue;
        try {
            FilenameEntry entry = parseFilenameEntrySimple(line);
            if (!entry.filename.empty()) {
                dataset.push_back(entry);
                if (entry.is_malicious) malicious_count++;
                else benign_count++;
                
                // Extract extension for coverage analysis
                size_t dot_pos = entry.filename.find_last_of('.');
                if (dot_pos != std::string::npos && dot_pos < entry.filename.length() - 1) {
                    std::string ext = entry.filename.substr(dot_pos + 1);
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    extensions.insert(ext);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Error at line " << line_number << ": " << e.what() << std::endl;
        }
    }
    file.close();
    
    // SANITY CHECKS: Filename distribution and extension coverage
    std::cout << "[SUCCESS] Loaded " << dataset.size() << " filename entries" << std::endl;
    std::cout << "  Malicious: " << malicious_count << ", Benign: " << benign_count << std::endl;
    std::cout << "  Unique extensions: " << extensions.size() << std::endl;
    if (extensions.size() > 0 && extensions.size() <= 20) {
        std::cout << "  Extensions: ";
        bool first = true;
        for (const auto& ext : extensions) {
            if (!first) std::cout << ", ";
            std::cout << ext;
            first = false;
        }
        std::cout << std::endl;
    }
    
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
            TCPTrace trace = parseTCPTraceSimple(line);
            if (!trace.trace_id.empty() || !trace.sequence.empty()) dataset.push_back(trace);
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Error at line " << line_number << ": " << e.what() << std::endl;
        }
    }
    file.close();
    int valid_count = 0;
    for (const auto& t : dataset) if (t.valid) valid_count++;
    std::cout << "[SUCCESS] Loaded " << dataset.size() << " TCP traces" << std::endl;
    std::cout << "  Valid sequences: " << valid_count << std::endl;
    std::cout << "  Invalid sequences: " << (dataset.size() - valid_count) << std::endl;
    return dataset;
}

std::vector<TCPTrace> JSONParser::loadTCPDatasetCSV(const std::string& filepath) {
    std::vector<TCPTrace> dataset;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Could not open file: " << filepath << std::endl;
        return dataset;
    }
    std::cout << "[INFO] Loading TCP trace dataset (CSV): " << filepath << std::endl;
    std::string line;
    // Read header
    if (!std::getline(file, line)) {
        file.close();
        return dataset;
    }
    // Expected header: trace_id,sequence,valid,description,category[,content]
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);
        std::string trace_id, sequence, valid, description, category, content;
        if (!std::getline(ss, trace_id, ',')) continue;
        if (!std::getline(ss, sequence, ',')) continue;
        if (!std::getline(ss, valid, ',')) valid = "false";
        if (!std::getline(ss, description, ',')) description = "";
        if (!std::getline(ss, category, ',')) category = "";
        // Optional content column
        if (std::getline(ss, content, ',')) {
            // content may include commas originally; dataset keeps it simple
        } else {
            content = "";
        }
        // Parse sequence: pipe-delimited tokens
        TCPTrace t;
        t.trace_id = trace_id;
        size_t start = 0;
        while (start <= sequence.size()) {
            size_t sep = sequence.find('|', start);
            std::string token = sequence.substr(start, sep == std::string::npos ? std::string::npos : sep - start);
            if (!token.empty()) t.sequence.push_back(token);
            if (sep == std::string::npos) break;
            start = sep + 1;
        }
        // valid flag
        std::string v = valid;
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        t.valid = (v == "true" || v == "1");
        t.description = description;
        t.category = category;
        t.content = content;
        dataset.push_back(std::move(t));
    }
    file.close();
    int valid_count = 0; for (const auto& t : dataset) if (t.valid) valid_count++;
    std::cout << "[SUCCESS] Loaded " << dataset.size() << " TCP traces (CSV)" << std::endl;
    std::cout << "  Valid sequences: " << valid_count << std::endl;
    std::cout << "  Invalid sequences: " << (dataset.size() - valid_count) << std::endl;
    return dataset;
}

} // namespace CS311
