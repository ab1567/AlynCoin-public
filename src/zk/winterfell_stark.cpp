#include "winterfell_stark.h"
#include "rust_bindings.h"
#include "crypto_utils.h"
#include "blockchain.h"
#include "transaction.h"
#include <cstring>
#include <iostream>
#include <sstream>

// ✅ Exportable BLAKE3-256 hash for Rust FFI
extern "C" void hash_blake3_256(const uint8_t* input, size_t len, uint8_t out[32]) {
    std::string input_str(reinterpret_cast<const char*>(input), len);
    std::string hash = Crypto::blake3(input_str); // hex string
    std::vector<unsigned char> raw = Crypto::fromHex(hash);
    if (raw.size() >= 32) {
        memcpy(out, raw.data(), 32);
    } else {
        memset(out, 0, 32);
    }
}

// ✅ Block zk-STARK Proof Generation
std::string WinterfellStark::generateProof(const std::string& blockHash,
                                           const std::string& prevHash,
                                           const std::string& txRoot) {
    std::string seed = Crypto::blake3(blockHash) + Crypto::blake3(prevHash) + txRoot;
    std::cout << "[zkSTARK] Generating proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate zk-STARK proof.\n";
        return "";
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}

// ✅ Block zk-STARK Proof Verification
bool WinterfellStark::verifyProof(const std::string& proof,
                                  const std::string& blockHash,
                                  const std::string& prevHash,
                                  const std::string& txRoot) {
    if (proof.empty() || blockHash.empty() || prevHash.empty() || txRoot.empty()) {
        std::cerr << "[zkSTARK] ❌ Invalid input for block zk-STARK proof verification.\n";
        return false;
    }

    // ✅ Canonical seed computation — must exactly match proof generator
    std::string seed = Crypto::blake3(blockHash) + Crypto::blake3(prevHash) + txRoot;

    std::cout << "[zkSTARK] Verifying proof with seed: " << seed << "\n";

    bool result = verify_proof(proof.c_str(), seed.c_str(), blockHash.c_str());
    std::cout << "[zkSTARK] 🔍 Block Proof Verification Result: " << (result ? "✅ Passed" : "❌ Failed") << "\n";
    return result;
}

// ✅ Transaction zk-STARK Proof Verification
bool WinterfellStark::verifyTransactionProof(const std::string& zkProof, const std::string& sender, const std::string& recipient, double amount, time_t timestamp) {
    if (zkProof.empty() || sender.empty() || recipient.empty()) {
        std::cerr << "[zkSTARK] ❌ Invalid input for transaction zk-STARK proof verification.\n";
        return false;
    }

    std::ostringstream oss;
    oss << sender << recipient << amount << timestamp;
    std::string seed = oss.str();

    bool result = verify_proof(zkProof.c_str(), seed.c_str(), sender.c_str());

    std::cout << "[zkSTARK] 🔍 Transaction Proof Verification Result: " << (result ? "✅ Passed" : "❌ Failed") << "\n";
    return result;
}

// ✅ Transaction zk-STARK Proof Generation
std::string WinterfellStark::generateTransactionProof(const std::string& sender,
                                                      const std::string& recipient,
                                                      double amount,
                                                      time_t timestamp) {
    std::ostringstream oss;
    oss << sender << recipient << amount << timestamp;
    std::string seed = oss.str();

    std::cout << "[zkSTARK] Generating transaction proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate transaction zk-STARK proof.\n";
        return "";
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ Transaction zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}

// ✅ Identity zk-STARK Proof Generation
std::optional<std::string> WinterfellStark::generateIdentityProof(const std::string& uuid,
                                                                   const std::string& name,
                                                                   const std::string& metadataHash) {
    std::string seed = uuid + name + metadataHash;

    std::cout << "[zkSTARK] Generating identity proof with seed: " << seed << "\n";

    char* proof_cstr = generate_proof_bytes(seed.c_str(), seed.size());
    if (!proof_cstr) {
        std::cerr << "[zkSTARK] ❌ Failed to generate identity zk-STARK proof.\n";
        return std::nullopt;
    }

    std::string proof(proof_cstr);
    free(proof_cstr);

    std::cout << "[zkSTARK] ✅ Identity zk-STARK proof generated. Size: " << proof.size() << " bytes\n";
    return proof;
}

// ✅ Recursive zk-STARK Proof Composition
std::string WinterfellStark::generateRecursiveProof(const std::string& address, size_t txCount) {
    std::vector<Transaction> allTxs = Transaction::loadAllFromDB();
    std::vector<unsigned char> combined;

    size_t count = 0;
    for (auto it = allTxs.rbegin(); it != allTxs.rend(); ++it) {
        if (count >= txCount) break;
        if (it->getSender() != address && it->getRecipient() != address) continue;

        std::vector<unsigned char> txData;

        // Add transaction hash
        std::vector<unsigned char> hashBytes = Crypto::fromHex(it->getHash());
        txData.insert(txData.end(), hashBytes.begin(), hashBytes.end());

        // Add sender and recipient hashed with BLAKE3
        std::vector<unsigned char> senderHash = Crypto::fromHex(Crypto::blake3(it->getSender()));
        std::vector<unsigned char> recipientHash = Crypto::fromHex(Crypto::blake3(it->getRecipient()));
        txData.insert(txData.end(), senderHash.begin(), senderHash.end());
        txData.insert(txData.end(), recipientHash.begin(), recipientHash.end());

        // Add amount (scaled to avoid float precision loss)
        uint64_t amt = static_cast<uint64_t>(it->getAmount() * 1'000'000);
        for (int i = 0; i < 8; ++i) {
            txData.push_back((amt >> (i * 8)) & 0xFF);
        }

        // Add timestamp
        uint64_t ts = static_cast<uint64_t>(it->getTimestamp());
        for (int i = 0; i < 8; ++i) {
            txData.push_back((ts >> (i * 8)) & 0xFF);
        }

        combined.insert(combined.end(), txData.begin(), txData.end());
        count++;
    }

    std::cout << "[zkSTARK] 🔢 Combined input size: " << combined.size() << " bytes\n";
    std::cout << "[zkSTARK] 🧪 First 32 bytes: ";
    for (size_t i = 0; i < std::min(combined.size(), size_t(32)); ++i) {
        printf("%02x", combined[i]);
    }
    std::cout << "\n";

    if (combined.empty()) {
        std::cerr << "[zkSTARK] ❌ No matching transactions found for recursive proof.\n";
        return "";
    }

    // Compute address hash (used in public inputs)
    std::string hashHex = Crypto::blake3(address);
    std::vector<unsigned char> hashBytes = Crypto::fromHex(hashHex);

    const uint8_t* innerData = combined.data();
    const uint8_t* hashPtr = hashBytes.data();

    RecursiveProofResult result = compose_recursive_proof(innerData, combined.size(), hashPtr);

    if (!result.data || result.len == 0) {
        std::cerr << "[zkSTARK] ❌ Recursive proof generation failed.\n";
        return "";
    }

    std::string recursiveProof(reinterpret_cast<char*>(result.data), result.len);
    free(result.data);
    std::cout << "[zkSTARK] ✅ Recursive proof composed. Size: " << recursiveProof.size() << " bytes\n";
    return recursiveProof;
}
