#pragma once
#include <string>
#include <vector>

struct EdgeOut { std::string source, target, label; };
struct NodeOut { std::string id, label; };

// Writes frontend-friendly JSON to `outPath` (e.g., output/automata.json)
// Schema:
// {
//   "type": "DFA|PDA|NFA",
//   "start": "stateId",
//   "accept": ["stateId", ...],
//   "nodes": [{"id":"S0","label":"S0"}, ...],
//   "edges": [{"source":"S0","target":"S1","label":"a"}, ...]
// }
bool writeAutomataJson(
    const std::string& type,
    const std::string& start,
    const std::vector<std::string>& accept,
    const std::vector<NodeOut>& nodes,
    const std::vector<EdgeOut>& edges,
    const std::string& outPath);
