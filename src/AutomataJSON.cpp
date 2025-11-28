#include "AutomataJSON.h"
#include <fstream>

static std::string escapeJson(const std::string& s) {
    std::string o; o.reserve(s.size()+8);
    for (char c: s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default: o += c; break;
        }
    }
    return o;
}

bool writeAutomataJson(
    const std::string& type,
    const std::string& start,
    const std::vector<std::string>& accept,
    const std::vector<NodeOut>& nodes,
    const std::vector<EdgeOut>& edges,
    const std::string& outPath) {
    std::ofstream f(outPath, std::ios::out | std::ios::trunc);
    if (!f.is_open()) return false;

    f << "{";
    f << "\"type\":\"" << escapeJson(type) << "\",";
    f << "\"start\":\"" << escapeJson(start) << "\",";
    f << "\"accept\":[";
    for (size_t i=0;i<accept.size();++i) {
        if (i) f << ",";
        f << "\"" << escapeJson(accept[i]) << "\"";
    }
    f << "],";

    f << "\"nodes\":[";
    for (size_t i=0;i<nodes.size();++i) {
        if (i) f << ",";
        f << "{\"id\":\"" << escapeJson(nodes[i].id) << "\"";
        if (!nodes[i].label.empty()) {
            f << ",\"label\":\"" << escapeJson(nodes[i].label) << "\"";
        }
        f << "}";
    }
    f << "],";

    f << "\"edges\":[";
    for (size_t i=0;i<edges.size();++i) {
        if (i) f << ",";
        f << "{\"source\":\"" << escapeJson(edges[i].source) << "\",";
        f << "\"target\":\"" << escapeJson(edges[i].target) << "\"";
        if (!edges[i].label.empty()) {
            f << ",\"label\":\"" << escapeJson(edges[i].label) << "\"";
        }
        f << "}";
    }
    f << "]";

    f << "}";
    return true;
}
