/**
 * RegexParser.h - IMPROVED VERSION
 * Actually implements regex to NFA conversion
 */

#ifndef REGEXPARSER_H
#define REGEXPARSER_H

#include "Utils.h"
#include <string>
#include <stack>

namespace CS311 {

class RegexParser {
private:
    static int state_counter;
    
    // Helper functions for regex parsing
    static std::string addConcatOperator(const std::string& regex);
    static std::string infixToPostfix(const std::string& regex);
    static NFA buildNFAFromPostfix(const std::string& postfix);
    
    // NFA construction primitives
    static NFA createCharNFA(char c);
    static NFA createWildcardNFA();  // NEW: for . (any char)
    static NFA createCharClassNFA(const std::string& chars);  // NEW: for [abc]
    static NFA concatenateNFA(const NFA& nfa1, const NFA& nfa2);
    static NFA alternateNFA(const NFA& nfa1, const NFA& nfa2);
    static NFA kleeneStarNFA(const NFA& nfa);
    static NFA plusNFA(const NFA& nfa);  // NEW: for + (one or more)
    static NFA optionalNFA(const NFA& nfa);  // NEW: for ? (zero or one)
    
    // Helper functions
    static int getPrecedence(char op);
    static bool isOperator(char c);
    static bool isMetachar(char c);

public:
    /**
     * Convert a regex pattern to NFA
     * Supports: literals, ., *, +, ?, |, (), []
     * Example patterns:
     *   ".*\\.exe$"        -> matches .exe files
     *   ".*\\.(exe|scr)$"  -> matches .exe or .scr files
     *   "[a-z]+"           -> one or more lowercase letters
     */
    static NFA regexToNFA(const std::string& regex);
    
    /**
     * Simplified pattern matcher (for basic patterns)
     * Use this for simple substring/extension matching
     */
    static NFA createSimplePattern(const std::string& pattern);
};

} // namespace CS311

#endif // REGEXPARSER_H