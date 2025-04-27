#include "recursive_proof_helper.h"
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <cstdint>
#include <cstring>
#include "blake3.h"

// FFI-compatible struct from Rust
extern "C" {
    typedef struct {
        uint8_t* data;
        size_t len;
    } RecursiveProofResult;

    RecursiveProofResult compose_recursive_proof(
        const uint8_t* proof,
        size_t len,
        const uint8_t* hash
    );
}

// Converts raw bytes into a hex string
static std::string toHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Converts hex string → raw binary bytes
static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string generateRecursiveProofToFile(
    const std::vector<std::string>& hashes,
    const std::string& address,
    int txCount,
    const std::string& customOutFile
) {
    // 👇 Convert all hex hashes into raw bytes
    std::vector<uint8_t> combinedBytes;
    for (const std::string& h : hashes) {
        std::vector<uint8_t> raw = hexToBytes(h);
        combinedBytes.insert(combinedBytes.end(), raw.begin(), raw.end());
    }

    // 🔐 Compute BLAKE3(address) as 32-byte hash
    uint8_t addressHash[32];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, address.data(), address.size());
    blake3_hasher_finalize(&hasher, addressHash, 32);

    // 🔄 Call FFI to compose recursive proof
    RecursiveProofResult result = compose_recursive_proof(
        combinedBytes.data(),
        combinedBytes.size(),
        addressHash
    );

    if (!result.data || result.len == 0) {
        return "❌ Recursive proof generation failed.";
    }

    std::string proofDataHex = toHex(result.data, result.len);

    std::string filename = customOutFile.empty()
        ? "/root/.alyncoin/recursive_proof_" + address + "_last" + std::to_string(txCount) + ".json"
        : customOutFile;

    std::ofstream out(filename);
    if (!out.is_open()) {
        return "❌ Failed to write proof file: " + filename;
    }

    auto now = std::time(nullptr);
    out << "{\n";
    out << "  \"address\": \"" << address << "\",\n";
    out << "  \"tx_count\": " << txCount << ",\n";
    out << "  \"timestamp\": \"" << std::put_time(std::gmtime(&now), "%FT%TZ") << "\",\n";
    out << "  \"proof_data\": \"" << proofDataHex << "\"\n";
    out << "}\n";
    out.close();

    return "✅ Recursive zk-STARK Proof saved to:\n" + filename;
}
