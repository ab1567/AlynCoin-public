#include "nft.h"
#include "nft_zk.h"
#include "../zk/winterfell_stark.h"  // Provides WinterfellStark class
#include <iostream>
#include <vector>
#include <cstdint>

bool NFTZK::verifyProof(const std::vector<uint8_t>& proofData, const std::string& expectedHash) {
    if (proofData.empty()) {
        std::cerr << "❌ [ZK] Proof data is empty.\n";
        return false;
    }

    try {
        // Convert proofData to a string (assuming ASCII-safe)
        std::string proofStr(reinterpret_cast<const char*>(proofData.data()), proofData.size());

        // You can pass dummy values for prevHash and txRoot for now
        const std::string dummyPrevHash = "";
        const std::string dummyTxRoot = "";

        bool isValid = WinterfellStark::verifyProof(proofStr, expectedHash, dummyPrevHash, dummyTxRoot);
        if (!isValid) {
            std::cerr << "❌ [ZK] zk-STARK proof verification failed!\n";
        } else {
            std::cout << "✅ [ZK] zk-STARK proof verified successfully.\n";
        }
        return isValid;
    } catch (const std::exception& e) {
        std::cerr << "❌ [ZK] Exception during verification: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "❌ [ZK] Unknown error during zk verification.\n";
        return false;
    }
}

// Optional: Integrate proof generation later
bool NFTZK::generateProof(const std::string& input, std::vector<uint8_t>& outProof) {
    std::cerr << "⚠️ [ZK] Proof generation not implemented yet. Integrate with zk prover here.\n";
    return false;
}
