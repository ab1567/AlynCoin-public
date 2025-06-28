#ifndef NETWORK_H
#define NETWORK_H

#include "block.h"
#include "blockchain.h"
#include "constants.h"
#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "network/peer_manager.h"
#include "transaction.h"
#include "transport/peer_globals.h" // <<--- ONLY include, don't redeclare!
#include "transport/transport.h"
#include <atomic>
#include <boost/asio.hpp>
#include <fstream>
#include <generated/net_frame.pb.h>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using boost::asio::ip::tcp;

class Network {
public:
  // Singleton initialization
  inline static Network &getInstance(unsigned short port,
                                     Blockchain *blockchain = nullptr,
                                     PeerBlacklist *blacklistPtr = nullptr) {
    static std::map<unsigned short, std::unique_ptr<Network>> instances;
    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex);

    if (instances.find(port) != instances.end()) {
      return *instances[port];
    }

    try {
      auto instance = std::make_unique<Network>(port, blockchain, blacklistPtr);
      instancePtr = instance.get();
      instances[port] = std::move(instance);
      return *instances[port];
    } catch (const std::exception &ex) {
      std::cerr << "❌ Failed to bind Network on port " << port << ": "
                << ex.what() << "\n";
      throw;
    }
  }

  inline static Network &getInstance() {
    if (!instancePtr) {
      throw std::runtime_error(
          "❌ Network::getInstance() called before initialization.");
    }
    return *instancePtr;
  }

  explicit Network(unsigned short port, Blockchain *blockchain,
                   PeerBlacklist *blacklistPtr = nullptr);
  ~Network();

  Blockchain &getBlockchain() { return *blockchain; }
  void setPublicPeerId(const std::string &peerId);
  void start();
  void syncWithPeers();
  void connectToPeer(const std::string &host, short port);
  void broadcastTransaction(const Transaction &tx);
  void broadcastTransactionToAllExcept(const Transaction &tx,
                                       const std::string &excludePeer);
  void broadcastBlock(const Block &block, bool force = false);
  void broadcastBlocks(const std::vector<Block> &blocks);
  void sendBlockToPeer(const std::string &peer, const Block &blk);
  void sendInventory(const std::string &peer);
  PeerManager *getPeerManager();
  std::vector<std::string> discoverPeers();
  void connectToDiscoveredPeers();
  std::string requestBlockchainSync(const std::string &peer);
  std::string receiveData(const std::string &peer);
  void requestPeerList();
  void scanForPeers();
  void startServer();
  void sendLatestBlock(const std::string &peerIP);
  void handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex);
  void loadPeers();
  void savePeers();
  void addPeer(const std::string &peer);
  void intelligentSync();
  std::vector<std::string> getPeers();
  bool sendData(std::shared_ptr<Transport> transport, const std::string &data);
  void receiveTransaction(const Transaction &tx);
  void broadcastPeerList();
  void run();
  bool isSyncing() const;
  bool connectToNode(const std::string &ip, int port);
  void autoMineBlock();
  void periodicSync();
  void broadcastRollupBlock(const RollupBlock &rollupBlock);
  void broadcastEpochProof(int epochIdx, const std::string &rootHash,
                           const std::vector<uint8_t> &proof);
  void requestEpochHeaders(const std::string &peerId);
  void handleNewRollupBlock(const RollupBlock &newRollupBlock);
  void receiveRollupBlock(const std::string &data);
  void listenForConnections();
  void handleNewBlock(const Block &newBlock);
  void blacklistPeer(const std::string &peer);
  bool isBlacklisted(const std::string &peer);
  void cleanupPeers();
  bool peerSupportsAggProof(const std::string &peerId) const;
  bool isSelfPeer(const std::string &peer) const;
  std::string getSelfAddressAndPort() const;
  inline static bool isUninitialized() { return instancePtr == nullptr; }
  inline static Network *getExistingInstance() { return instancePtr; }
  void autoSyncIfBehind();
  const auto &getPeerTable() const { return peerTransports; }
  void waitForInitialSync(int timeoutSeconds = 10);
  void handleGetData(const std::string &peer,
                     const std::vector<std::string> &hashes);
  void sendStateProof(std::shared_ptr<Transport> tr);
  bool peerSupportsSnapshot(const std::string &peerId) const;
  void requestSnapshotSync(const std::string &peer);
  void requestTailBlocks(const std::string &peer, int fromHeight);
  void sendForkRecoveryRequest(const std::string &peer, const std::string &tip);
  void sendSnapshot(std::shared_ptr<Transport> tr, int upToHeight = -1);
  void sendTailBlocks(std::shared_ptr<Transport> tr, int fromHeight);
  void handleSnapshotMeta(const std::string &peer,
                          const alyncoin::net::SnapshotMeta &meta);
  void handleSnapshotChunk(const std::string &peer, const std::string &b64);
  void handleSnapshotAck(const std::string &peer, uint32_t seq);
  void handleSnapshotEnd(const std::string &peer);
  void handleTailRequest(const std::string &peer, int fromHeight);
  void handleTailBlocks(const std::string &peer, const std::string &b64);
  void handleBlockchainSyncRequest(const std::string &peer,
                                   const alyncoin::BlockchainSyncProto &req);
  static unsigned short findAvailablePort(unsigned short startPort,
                                          int maxTries = 10);
  bool sendFrame(std::shared_ptr<Transport> tr,
                 const google::protobuf::Message &m);
  void broadcastFrame(const google::protobuf::Message &m);
  void sendHeight(const std::string &peer);
  void sendTipHash(const std::string &peer);
  void sendPeerList(const std::string &peer);

  // Mark a peer offline and close its transport
  void markPeerOffline(const std::string &peerId);

private:
  unsigned short port;
  Blockchain *blockchain;

  std::atomic<bool> isRunning;
  std::atomic<bool> syncing;
  std::mutex fileIOMutex;

  boost::asio::io_context ioContext;
  boost::asio::ip::tcp::acceptor acceptor;
  std::thread listenerThread;
  std::thread serverThread;
  std::unique_ptr<PeerManager> peerManager;
  std::string publicPeerId;
  std::unordered_set<std::string> bannedPeers;
  std::unordered_set<std::string> knownPeers;
  PeerBlacklist *blacklist;
  std::unordered_set<std::string> seenTxHashes;
  static Network *instancePtr;
  std::vector<std::thread> threads_;

  // Helpers reused by handlePeer & connectToNode
  void startBinaryReadLoop(const std::string &peerId,
                           std::shared_ptr<Transport> transport);
  void dispatch(const alyncoin::net::Frame &f, const std::string &peerId);
  void sendInitialRequests(const std::string &peerId);
  void handlePeer(std::shared_ptr<Transport> transport);
  bool validateBlockSignatures(const Block &blk);
};
#endif // NETWORK_H
