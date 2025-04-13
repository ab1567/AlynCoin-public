#ifndef NETWORK_H
#define NETWORK_H

#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "block.h"
#include "blockchain.h"
#include "transaction.h"
#include <atomic>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "network/peer_manager.h"

using boost::asio::ip::tcp;

class Network {
public:
inline static Network &getInstance(unsigned short port,
                                   Blockchain *blockchain = nullptr,
                                   PeerBlacklist *blacklistPtr = nullptr) {
  static std::map<unsigned short, std::unique_ptr<Network>> instances;
  static std::mutex mutex;

  std::lock_guard<std::mutex> lock(mutex);

  // If already initialized, return the existing one
  if (instances.find(port) != instances.end()) {
    return *instances[port];
  }

  try {
    auto instance = std::make_unique<Network>(port, blockchain, blacklistPtr);
    instancePtr = instance.get();                  // Update global reference
    instances[port] = std::move(instance);         // Store in map
    return *instances[port];
  } catch (const std::exception &ex) {
    std::cerr << "❌ Failed to bind Network on port " << port << ": " << ex.what() << "\n";
    throw;
  }
}


  explicit Network(unsigned short port, Blockchain *blockchain,
                   PeerBlacklist *blacklistPtr = nullptr);
  ~Network();

  Blockchain& getBlockchain() {
    return *blockchain;
  }

  void start();
  void startListening();
  void syncWithPeers();
  void connectToPeer(const std::string &host, short port);
  void broadcastTransaction(const Transaction &tx);
  void broadcastMessage(const std::string &message);
  void broadcastBlock(const Block &block);
  PeerManager* getPeerManager();
  std::vector<std::string> discoverPeers();
  void connectToDiscoveredPeers();
  std::string requestBlockchainSync(const std::string &peer);
  std::string receiveData(const std::string &peer);
  void requestPeerList();
  void scanForPeers();
  void processReceivedData(const std::string &senderIP,
                           const std::string &data);
  void startServer();
  void handleIncomingData(const std::string &senderIP, std::string data);
  void sendLatestBlock(const std::string &peerIP);
  void sendLatestBlockIndex(const std::string &peerIP);
  void handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex);
  void sendFullChain(const std::string &peerIP);
  void loadPeers();
  void savePeers();
  void addPeer(const std::string &peer);
  void acceptConnections();
  void sendMessageToPeer(const std::string &peer, const std::string &message);
  void sendMessage(std::shared_ptr<tcp::socket> socket,
                   const std::string &message);
  std::vector<std::string> getPeers();
  bool sendData(const std::string &peer, const std::string &data);
  void receiveTransaction(const Transaction &tx);
  void broadcastPeerList();
  void run();
  bool isSyncing() const;
  bool connectToNode(const std::string &ip, int port);
  void receiveFullChain(const std::string &sender,
                        const std::string &serializedData);
  void autoMineBlock();
  void periodicSync();
  void broadcastRollupBlock(const RollupBlock &rollupBlock);
  void handleNewRollupBlock(const RollupBlock &newRollupBlock);
  void receiveRollupBlock(const std::string &data);
  void listenForConnections();
  bool validatePeer(const std::string &peer);
  void handleNewBlock(const Block &newBlock);
  void blacklistPeer(const std::string &peer);
  bool isBlacklisted(const std::string &peer);
  void cleanupPeers();

  inline static bool isUninitialized() {
    return instancePtr == nullptr;
  }

  inline static Network* getExistingInstance() {
    return instancePtr;
  }

private:
  unsigned short port;
  Blockchain *blockchain;

  std::atomic<bool> isRunning;
  std::atomic<bool> syncing;
  std::mutex peersMutex;
  std::mutex fileIOMutex;

  boost::asio::io_context ioContext;
  boost::asio::ip::tcp::acceptor acceptor;
  std::thread listenerThread;
  std::thread serverThread;
  PeerManager* peerManager = nullptr;

  std::unordered_map<std::string, std::shared_ptr<tcp::socket>> peerSockets;
  std::unordered_set<std::string> bannedPeers;
  PeerBlacklist *blacklist;
  std::unordered_set<std::string> seenTxHashes;
  static Network* instancePtr;

  void handlePeer(std::shared_ptr<tcp::socket> socket);
  bool validateBlockSignatures(const Block &blk);
};

#endif // NETWORK_H
