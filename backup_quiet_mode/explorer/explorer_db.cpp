#include "explorer_db.h"
#include "explorer_utils.h"
#include "../generated/block_protos.pb.h"
#include "../generated/transaction_protos.pb.h"
#include "../block.h"
#include "../transaction.h"
#include <iostream>
#include <sstream>

ExplorerDB::ExplorerDB(const std::string& db_path) : dbPath(db_path), db(nullptr) {
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::OpenForReadOnly(options, dbPath, &db);
    if (!status.ok()) {
quietPrint( "❌ [ExplorerDB] Failed to open RocksDB: " << status.ToString() << "\n");
        db = nullptr;
    } else {
quietPrint( "✅ [ExplorerDB] RocksDB opened successfully.\n");
    }
}

ExplorerDB::~ExplorerDB() {
    if (db) delete db;
}

// ============ Get Block by Hash ============
Json::Value ExplorerDB::getBlockByHash(const std::string& blockHash) {
    Json::Value blockJson;
    if (!db) return blockJson;

    std::string blockKey = "block_" + blockHash;
    std::string blockData;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), blockKey, &blockData);

    if (!status.ok()) {
        std::cerr << "❌ [ExplorerDB] Block not found for hash: " << blockHash << "\n";
        return blockJson;
    }

    alyncoin::BlockProto protoBlock;
    if (!protoBlock.ParseFromString(blockData)) {
quietPrint( "❌ [ExplorerDB] BlockProto parse failed!\n");
        return blockJson;
    }

    Block block = Block::fromProto(protoBlock);
    blockJson = block.toJSON();
    std::string zkStr(block.getZkProof().begin(), block.getZkProof().end());
    blockJson["zkProof"] = zkStr;
    return blockJson;
}

// ============ Get Transaction by Hash ============
Json::Value ExplorerDB::getTransactionByHash(const std::string& txHash) {
    Json::Value txJson;
    if (!db) {
        txJson["error"] = "Database not initialized";
        return txJson;
    }

    std::string txKey = "tx_" + txHash;
    std::string txData;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), txKey, &txData);

    if (!status.ok()) {
        std::cerr << "❌ [ExplorerDB] Transaction not found: " << txHash << "\n";
        txJson["error"] = "Transaction not found";
        return txJson;
    }

    alyncoin::TransactionProto protoTx;
    if (!protoTx.ParseFromString(txData)) {
        std::cerr << "❌ [ExplorerDB] TransactionProto parse failed!\n";
        txJson["error"] = "Failed to parse transaction data";
        return txJson;
    }

    Transaction tx = Transaction::fromProto(protoTx);
    txJson = tx.toJSON();
    return txJson;
}

// ============ Get Transactions by Address ============
Json::Value ExplorerDB::getTransactionsByAddress(const std::string& address) {
    Json::Value txArray(Json::arrayValue);
    if (!db) return txArray;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("tx_") != 0) continue;  // Skip non-tx entries

        alyncoin::TransactionProto protoTx;
        if (!protoTx.ParseFromString(it->value().ToString())) continue;

        if (protoTx.sender() == address || protoTx.recipient() == address) {
            Transaction tx = Transaction::fromProto(protoTx);
            txArray.append(tx.toJSON());
        }
    }
    delete it;
    return txArray;
}

// ============ Get Blockchain Stats ============
Json::Value ExplorerDB::getBlockchainStats() {
    Json::Value stats;
    if (!db) return stats;

    int blockCount = 0;
    int txCount = 0;
    double totalSupply = 0;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("block_") == 0) blockCount++;
        if (key.find("tx_") == 0) txCount++;
    }
    delete it;

    // Total supply = Block count × block reward (simple logic, can adjust for actual reward schedule)
    totalSupply = blockCount * 10;  // Base reward as per your code

    stats["blockHeight"] = blockCount;
    stats["transactionCount"] = txCount;
    stats["totalSupply"] = totalSupply;

    return stats;
}

// ============ Get Balance ============
double ExplorerDB::getBalance(const std::string& address) {
    if (!db) return 0;

    double balance = 0.0;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("tx_") != 0) continue;

        alyncoin::TransactionProto protoTx;
        if (!protoTx.ParseFromString(it->value().ToString())) continue;

        // System or reward transactions
        if (protoTx.sender() == "System" && protoTx.recipient() == address) {
            balance += protoTx.amount();
        }
        // Normal incoming tx
        else if (protoTx.recipient() == address) {
            balance += protoTx.amount();
        }
        // Outgoing tx
        else if (protoTx.sender() == address) {
            balance -= protoTx.amount();
        }
    }

    delete it;
    return balance;
}

// ====== Get Block by Height ======
Json::Value ExplorerDB::getBlockByHeight(int height) {
    Json::Value blockJson;
    if (!db) return blockJson;

    std::string blockKey = "block_height_" + std::to_string(height); // Assuming you store by height
    std::string blockData;
    rocksdb::Status status = db->Get(rocksdb::ReadOptions(), blockKey, &blockData);

    if (!status.ok()) {
quietPrint( "❌ [ExplorerDB] Block not found for height: " << height << "\n");
        return blockJson;
    }

    alyncoin::BlockProto protoBlock;
    if (!protoBlock.ParseFromString(blockData)) {
quietPrint( "❌ [ExplorerDB] BlockProto parse failed!\n");
        return blockJson;
    }

    Block block = Block::fromProto(protoBlock);
    blockJson = block.toJSON();
    return blockJson;
}

// ====== Get Latest Block ======
Json::Value ExplorerDB::getLatestBlock() {
    Json::Value blockJson;
    if (!db) return blockJson;

    int maxHeight = 0;
    std::string latestBlockData;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("block_height_") != 0) continue;

        int height = std::stoi(key.substr(13)); // After "block_height_"
        if (height > maxHeight) {
            maxHeight = height;
            latestBlockData = it->value().ToString();
        }
    }
    delete it;

    if (latestBlockData.empty()) return blockJson;

    alyncoin::BlockProto protoBlock;
    if (!protoBlock.ParseFromString(latestBlockData)) return blockJson;

    Block block = Block::fromProto(protoBlock);
    blockJson = block.toJSON();
    return blockJson;
}
