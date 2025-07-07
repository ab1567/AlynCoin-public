#ifndef BLOCK_H
#define BLOCK_H

#include <generated/block_protos.pb.h>
#include <generated/blockchain_protos.pb.h>
#include <generated/transaction_protos.pb.h>
#include "crypto_utils.h"
#include "crypto_protos.pb.h"
#include "transaction.h"
#include "zk/winterfell_stark.h"
#include <cstddef>
#include <ctime>
#include <json/json.h>
#include <string>
#include <vector>
#include "constants.h"
#include <boost/multiprecision/cpp_int.hpp>

class Block {
private:
  int index;
  std::string previousHash;
  std::vector<Transaction> transactions;
  std::string hash;
  std::string minerAddress;
  int nonce;
  time_t timestamp;
  mutable std::string transactionsHash;
  mutable std::string cachedRoot;
  std::string blockSignature;
  std::vector<unsigned char> dilithiumSignature;
  std::vector<unsigned char> falconSignature;
  std::vector<unsigned char> publicKeyDilithium;
  std::vector<unsigned char> publicKeyFalcon;
  std::vector<uint8_t> zkProof;
  std::string merkleRoot;
  double reward = 0.0;
  std::vector<Transaction> l2Transactions;
  std::string epochRoot;
  std::vector<uint8_t> epochProof;
  boost::multiprecision::cpp_int accumulatedWork;
  std::string transactionsToString() const;

public:
  friend void ensureRootConsistency(const Block& b, int idx);
  std::string keccakHash;
  int difficulty;

  static constexpr double INITIAL_REWARD = 100.0;
  static constexpr double DECAY_RATE = 0.00005;

  // --- Constructors ---
  Block();
  Block(int index, const std::string &previousHash,
        const std::vector<Transaction> &transactions,
        const std::string &minerAddress, int difficulty,
        uint64_t timestamp, uint64_t nonce);
  Block(const Block &other) = default;
  Block &operator=(const Block &other) = default;

  // --- Getters ---
  int getIndex() const { return index; }
  std::string getPreviousHash() const { return previousHash; }
  const std::vector<Transaction> &getTransactions() const { return transactions; }
  std::string getHash() const { return hash; }
  std::string getMinerAddress() const { return minerAddress; }
  int getNonce() const { return nonce; }
  time_t getTimestamp() const { return timestamp; }
  std::string getBlockSignature() const { return blockSignature; }
  std::string getMerkleRoot() const { return merkleRoot; }
  std::string getTxRoot() const { return getTransactionsHash(); }
  std::vector<uint8_t> getZkProof() const { return zkProof; }
  const std::string& getEpochRoot() const { return epochRoot; }
  const std::vector<uint8_t>& getEpochProof() const { return epochProof; }

  const std::vector<unsigned char>& getDilithiumSignature() const { return dilithiumSignature; }
  const std::vector<unsigned char>& getFalconSignature() const    { return falconSignature; }
  std::vector<unsigned char> getPublicKeyDilithium() const { return publicKeyDilithium; }
  std::vector<unsigned char> getPublicKeyFalcon() const { return publicKeyFalcon; }
  double getReward() const;
  int getDifficulty() const { return difficulty; }
  const boost::multiprecision::cpp_int& getAccumulatedWork() const { return accumulatedWork; }
  void setAccumulatedWork(const boost::multiprecision::cpp_int& w) { accumulatedWork = w; }
  // --- Setters ---
  void setIndex(int idx) { index = idx; }
  void setPreviousHash(const std::string &prev) { previousHash = Crypto::normaliseHash(prev); }
  void setTransactions(const std::vector<Transaction> &txs) {
    transactions = txs;
    cachedRoot.clear();
  }
  void setHash(const std::string &value)        { hash         = Crypto::normaliseHash(value); }
  void setMinerAddress(const std::string &addr) { minerAddress = addr; }
  void setNonce(int value) { nonce = value; }
  void setSignature(const std::string &signature) { blockSignature = signature; }
  void setTimestamp(time_t ts) { timestamp = ts; }
  void setKeccakHash(const std::string &khash) { keccakHash = khash; }
  void setDifficulty(int diff) { difficulty = diff; }
  void setDilithiumSignature(const std::vector<unsigned char> &sig) { dilithiumSignature = sig; }
  void setFalconSignature(const std::vector<unsigned char> &sig)    { falconSignature = sig; }
  void setPublicKeyDilithium(const std::vector<unsigned char> &pk) { publicKeyDilithium = pk; }
  void setPublicKeyFalcon(const std::vector<unsigned char> &pk) { publicKeyFalcon = pk; }
  void setZkProof(const std::vector<uint8_t> &proof) { zkProof = proof; }
  void setEpochRoot(const std::string& root) { epochRoot = root; }
  void setEpochProof(const std::vector<uint8_t>& proof) { epochProof = proof; }
  //void setMerkleRoot(const std::string &merkle) { merkleRoot = merkle; }
  void setReward(double r);

  void setMerkleRoot(const std::string &root);
  void setTransactionsHash(const std::string &hash);
  // --- Other Functions ---
  bool isGenesisBlock() const {
    return index == 0 && previousHash == GENESIS_PARENT_HASH;
  }

  void incrementNonce() { nonce++; }
  std::string getTransactionsHash() const;
  std::string computeTransactionsHash() const;
  std::string calculateHash() const;
  bool mineBlock(int difficulty);
  void signBlock(const std::string &minerPrivateKeyPath);
  bool hasValidProofOfWork() const;
  void computeKeccakHash();
  bool isValid(const std::string &prevHash, int expectedDifficulty) const;
  bool containsTransaction(const Transaction &tx) const;
  std::vector<unsigned char> getSignatureMessage() const;
  std::string getHashInput() const {
    return previousHash + std::to_string(timestamp) + std::to_string(nonce);
  }

  std::string generateRollupProof(const std::vector<Transaction> &offChainTxs);
  const std::vector<Transaction>& getL2Transactions() const { return l2Transactions; }

  void setL2Transactions(const std::vector<Transaction>& txs) { l2Transactions = txs; }


  // --- Serialization / Deserialization ---
  static Block fromProto(const alyncoin::BlockProto &proto, bool allowPartial = false);
  alyncoin::BlockProto toProtobuf() const;
  Json::Value toJSON() const;
  static Block fromJSON(const Json::Value &blockJson);
};

#endif // BLOCK_H
