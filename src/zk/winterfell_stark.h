#ifndef WINTERFELL_STARK_H
#define WINTERFELL_STARK_H

#include <string>
#include <ctime>  // Required for time_t

class WinterfellStark {
public:
    // ✅ Generate zk-STARK Proof for a block using blockHash + previousHash + txRoot
    static std::string generateProof(const std::string& blockHash,
                                     const std::string& prevHash,
                                     const std::string& txRoot);

    // ✅ Verify zk-STARK Proof for a block
    static bool verifyProof(const std::string& proof,
                            const std::string& blockHash,
                            const std::string& prevHash,
                            const std::string& txRoot);

    // ✅ Generate zk-STARK Proof for a transaction
    static std::string generateTransactionProof(const std::string& sender,
                                                const std::string& recipient,
                                                double amount,
                                                time_t timestamp);

    // ✅ Verify zk-STARK Proof for a transaction
    static bool verifyTransactionProof(const std::string& zkProof,
                                       const std::string& sender,
                                       const std::string& recipient,
                                       double amount,
                                       time_t timestamp);
};

#endif // WINTERFELL_STARK_H
