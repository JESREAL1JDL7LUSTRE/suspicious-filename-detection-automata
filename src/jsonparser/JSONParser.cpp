// Simple JSONL parser implementation (lightweight, tolerant)
#include "JSONParser.h"

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
    // Parse explicit ground truth label: is_malicious (true/false)
    // Default to false if field is present and set to false, otherwise true only if explicitly true
    // This keeps academic metrics (TP/FP/FN) meaningful.
    size_t posMal = line.find("\"is_malicious\"");
    if (posMal != std::string::npos) {
        size_t colon = line.find(':', posMal);
        if (colon != std::string::npos) {
            size_t start = line.find_first_not_of(" \t", colon + 1);
            if (start != std::string::npos) {
                if (line.compare(start, 4, "true") == 0) entry.is_malicious = true;
                else entry.is_malicious = false;
            }
        }
    } else {
        // If label absent, conservatively treat as benign to avoid inflating TP
        entry.is_malicious = false;
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
    while (std::getline(file, line)) {
        line_number++;
        if (line.empty()) continue;
        try {
            FilenameEntry entry = parseFilenameEntrySimple(line);
            if (!entry.filename.empty()) dataset.push_back(entry);
        } catch (const std::exception& e) {
            std::cerr << "[WARNING] Error at line " << line_number << ": " << e.what() << std::endl;
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

} // namespace CS311
