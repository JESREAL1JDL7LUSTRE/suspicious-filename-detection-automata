
/** PDAModule.h **/
#ifndef PDAMODULE_H
#define PDAMODULE_H

#include "Utils.h"
#include "JSONParser.h"
#include <vector>
#include <string>

namespace CS311 {

class PDAModule {
public:
    PDAModule();
    void loadDataset(const std::string& filepath);
    void buildPDA();
    bool validateSequence(const std::vector<std::string>& sequence);
    void testAllTraces();
    void showStackOperations(const std::vector<std::string>& sequence);
    void generateReport();
    const PDAMetrics& getMetrics() const { return metrics; }
private:
    std::vector<TCPTrace> dataset;
    PDA pda;
    PDAMetrics metrics;
    enum TCPState { Q_START = 0, Q_SYN_RECEIVED = 1, Q_SYNACK_RECEIVED = 2, Q_ACCEPT = 3, Q_ERROR = -1 };
    bool processPacket(const std::string& packet, std::vector<std::string>& operations);
};

} // namespace CS311

#endif // PDAMODULE_H
