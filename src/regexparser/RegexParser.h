/**
 * File: RegexParser.h
 * Purpose: Convert regular expressions to NFA using Thompson's Construction
 */

#ifndef REGEXPARSER_H
#define REGEXPARSER_H

#include "Utils.h"
#include <string>
#include <stack>
#include <queue>

namespace CS311 {

class RegexParser {
public:
    static NFA regexToNFA(const std::string& regex);
private:
    static std::string infixToPostfix(const std::string& regex);
    static NFA buildNFAFromPostfix(const std::string& postfix);
    static NFA createCharNFA(char c);
    static NFA concatenateNFA(const NFA& nfa1, const NFA& nfa2);
    static NFA alternateNFA(const NFA& nfa1, const NFA& nfa2);
    static NFA kleeneStarNFA(const NFA& nfa);
    static int getPrecedence(char op);
    static bool isOperator(char c);
    static std::string addConcatOperator(const std::string& regex);
    static int state_counter;
};

} // namespace CS311

#endif // REGEXPARSER_H
