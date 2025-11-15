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
    /**
     * Convert regex pattern to NFA using Thompson's Construction
     * @param regex Regular expression pattern
     * @return NFA that recognizes the pattern
     */
    static NFA regexToNFA(const std::string& regex);
    
private:
    /**
     * Convert infix regex to postfix notation (Shunting Yard algorithm)
     */
    static std::string infixToPostfix(const std::string& regex);
    
    /**
     * Build NFA from postfix expression
     */
    static NFA buildNFAFromPostfix(const std::string& postfix);
    
    /**
     * Create NFA fragment for single character
     */
    static NFA createCharNFA(char c);
    
    /**
     * Create NFA fragment for concatenation (AB)
     */
    static NFA concatenateNFA(const NFA& nfa1, const NFA& nfa2);
    
    /**
     * Create NFA fragment for alternation (A|B)
     */
    static NFA alternateNFA(const NFA& nfa1, const NFA& nfa2);
    
    /**
     * Create NFA fragment for Kleene star (A*)
     */
    static NFA kleeneStarNFA(const NFA& nfa);
    
    /**
     * Get operator precedence
     */
    static int getPrecedence(char op);
    
    /**
     * Check if character is operator
     */
    static bool isOperator(char c);
    
    /**
     * Add explicit concatenation operators
     */
    static std::string addConcatOperator(const std::string& regex);
    
    // State counter for unique state IDs
    static int state_counter;
};

} // namespace CS311

#endif // REGEXPARSER_H