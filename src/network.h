#ifndef NETWORK_H
#define NETWORK_H

#include "block.h"
#include "blockchain.h"
#include "constants.h"
#include <generated/block_protos.pb.h>
#include <generated/transaction_protos.pb.h>
#include "network/peer_manager.h"
#include "transaction.h"
#include "transport/peer_globals.h" // <<--- ONLY include, don't redeclare!
#include "transport/transport.h"
#include "self_healing/self_healing_node.h"
#include "config.h"
#include "syncing/headers_sync.h"
#include <boost/asio/ssl.hpp>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <chrono>
#include <deque>
#include <fstream>
#include <generated/net_frame.pb.h>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <optional>

using boost::asio::ip::tcp;

static_assert(alyncoin::net::Frame::kBlockBatch == 7,
              "If you resurrect block_batch, you MUST chunk it first!");

class Network {
public:
  friend class HeadersSync;
  // Singleton initialization
  inline static bool autoMineEnabled = true;
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
  void setConfiguredExternalAddress(const std::string &address);
  void start();
  void connectToPeer(const std::string &host, short port);
  void broadcastTransaction(const Transaction &tx);
  void broadcastTransactionToAllExcept(const Transaction &tx,
                                       const std::string &excludePeer);
  void broadcastBlock(const Block &block, bool force = false,
                      const std::string &excludePeer = "");
  void broadcastBlocks(const std::vector<Block> &blocks);
  void broadcastINV(const std::vector<std::string> &hashes);
  void broadcastHeight(uint32_t height);
  void broadcastHandshake();
  void sendBlockToPeer(const std::string &peer, const Block &blk);
  void sendInventory(const std::string &peer);
  PeerManager *getPeerManager();
  size_t getConnectedPeerCount() const;
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
  void broadcastPeerList(const std::string &excludePeer = "");
  void run();
  bool isSyncing() const;
  bool isSnapshotActive() const;
  bool connectToNode(const std::string &ip, int remotePort);
  bool finishOutboundHandshake(std::shared_ptr<Transport> tx,
                               std::array<uint8_t, 32> &privOut);
  void autoMineBlock();
  void periodicSync();
  void broadcastRollupBlock(const RollupBlock &rollupBlock);
  void broadcastEpochProof(int epochIdx, const std::string &rootHash,
                           const std::vector<uint8_t> &proof);
  void requestEpochHeaders(const std::string &peerId);
  void handleNewRollupBlock(const RollupBlock &newRollupBlock);
  void receiveRollupBlock(const std::string &data);
  void listenForConnections();
  // Handle a new block received from a peer or mined locally.
  // The optional sender argument is the peer ID that relayed the block.
  // When provided we will update our cached height for that peer.
  void handleNewBlock(const Block &newBlock, const std::string &sender = "");
  void blacklistPeer(const std::string &peer);
  bool isBlacklisted(const std::string &peer);
  void cleanupPeers();
  bool peerSupportsAggProof(const std::string &peerId) const;
  bool isSelfPeer(const std::string &peer) const;
  bool isSelfEndpoint(const std::string &host, int port) const;
  std::string getSelfAddressAndPort() const;
  inline static bool isUninitialized() { return instancePtr == nullptr; }
  inline static Network *getExistingInstance() { return instancePtr; }
  void autoSyncIfBehind();
  const auto &getPeerTable() const { return peerTransports; }
  struct PeerSnapshot {
    std::shared_ptr<Transport> transport;
    std::shared_ptr<PeerState> state;
  };
  PeerSnapshot getPeerSnapshot(const std::string &peer) const;
  void waitForInitialSync(int timeoutSeconds = 10);
  void handleGetData(const std::string &peer,
                     const std::vector<std::string> &hashes);
  void sendStateProof(std::shared_ptr<Transport> tr);
  bool peerSupportsSnapshot(const std::string &peerId) const;
  bool peerSupportsWhisper(const std::string &peerId) const;
  bool peerSupportsTls(const std::string &peerId) const;
  void requestSnapshotSync(const std::string &peer);
  void requestTailBlocks(const std::string &peer, int fromHeight,
                         const std::string &anchorHash);
  void requestBlockByHash(const std::string &peer, const std::string &hash);
  void sendForkRecoveryRequest(const std::string &peer, const std::string &tip);
  void sendSnapshot(const std::string &peerId, std::shared_ptr<Transport> tr,
                    int upToHeight = -1, size_t preferredChunk = 0);
  void sendTailBlocks(std::shared_ptr<Transport> tr, int fromHeight,
                      const std::string &peerId);
  void handleSnapshotMeta(const std::string &peer,
                          const alyncoin::net::SnapshotMeta &meta);
  void handleSnapshotChunk(const std::string &peer,
                           const alyncoin::net::SnapshotChunk &chunk);
  void handleSnapshotAck(const std::string &peer,
                         const alyncoin::net::SnapshotAck &ack);
  void handleSnapshotEnd(const std::string &peer,
                         const alyncoin::net::SnapshotEnd &end);
  void handleTailRequest(const std::string &peer, int fromHeight);
  void handleTailBlocks(const std::string &peer, const std::string &b64);
  void handleHeaderBatch(const std::string &peer,
                         const alyncoin::net::Headers &headers);
  void handleBlockBatch(const std::string &peer,
                        const alyncoin::net::BlockBatch &batch);
  void handleBlockchainSyncRequest(const std::string &peer,
                                   const alyncoin::BlockchainSyncProto &req);
  static unsigned short findAvailablePort(unsigned short startPort,
                                          int maxTries = 10);
  bool sendFrame(std::shared_ptr<Transport> tr,
                 const google::protobuf::Message &m,
                 bool immediate = false);
  inline bool sendFrameImmediate(std::shared_ptr<Transport> tr,
                                 const google::protobuf::Message &m) {
    const size_t sz = m.ByteSizeLong();
    if (sz > MAX_WIRE_PAYLOAD) {
      std::cerr << "[sendFrameImmediate] \xE2\x9D\x8C Payload too large: " << sz
                << " bytes (limit " << MAX_WIRE_PAYLOAD << ")" << '\n';
      return false;
    }
    return sendFrame(std::move(tr), m, true);
  }
  void broadcastFrame(const google::protobuf::Message &m);
  void sendPrivate(const std::string &peer,
                   const google::protobuf::Message &m);
  void sendHeight(const std::string &peer);
  void sendHeightProbe(std::shared_ptr<Transport> tr);
  void sendTipHash(const std::string &peer);
  void sendPeerList(const std::string &peer);
  size_t getTrackedEndpointCount() const;
  bool noteShareableEndpoint(const std::string &host, int port,
                             bool triggerBroadcast = true,
                             bool markVerified = false,
                             const std::string &originPeer = "");
  void startDiscoveryLoops();
  void stopDiscoveryLoops();

  // Expose frame processing for worker threads
  void processFrame(const alyncoin::net::Frame &f, const std::string &peer);

  // Mark a peer offline and close its transport
  void markPeerOffline(const std::string &peerId);

private:
  // Construct a Handshake populated with the current chain height
  // and supported feature list.
  alyncoin::net::Handshake buildHandshake() const;
  void configureNatTraversal();

  unsigned short port;
  Blockchain *blockchain;

  std::atomic<bool> isRunning;
  std::mutex fileIOMutex;

  boost::asio::io_context ioContext;
  std::unique_ptr<boost::asio::ssl::context> tlsContext;
  boost::asio::ip::tcp::acceptor acceptor;
  std::thread listenerThread;
  std::thread serverThread;
  std::unique_ptr<PeerManager> peerManager;
  std::unique_ptr<SelfHealingNode> selfHealer;
  std::string publicPeerId;
  std::string configuredExternalAddress;
  bool configuredExternalExplicit{false};
  std::atomic<bool> hairpinCheckAttempted{false};
  std::string nodeId; // stable identifier for this node
  uint64_t localHandshakeNonce{0};
  struct ActiveSnapshotSession {
    std::string peer;
    std::string sessionId;
  };
  mutable std::mutex snapshotSessionMutex;
  std::optional<ActiveSnapshotSession> activeSnapshotSession;

  bool beginSnapshotSession(const std::string &peer,
                            const std::string &sessionId);
  void releaseSnapshotSession(const std::string &peer,
                              const std::string &sessionId);
  void releaseSnapshotSessionForPeer(const std::string &peer);
  bool isSnapshotInProgress() const;
  bool isSnapshotOwnedBy(const std::string &peer) const;
  bool snapshotSessionMatches(const std::string &peer,
                              const std::string &sessionId) const;
  struct BanEntry {
    uint64_t until{0};
    int strikes{0};
  };
  std::unordered_map<std::string, BanEntry> bannedPeers;
  struct EndpointRecord {
    std::string host;
    int port{0};
    bool verified{false};
    int successCount{0};
    int failureCount{0};
    std::chrono::steady_clock::time_point lastSeen{};
    std::chrono::steady_clock::time_point lastSuccess{};
    std::chrono::steady_clock::time_point nextDialAllowed{};
    std::string lastOrigin;
  };

  std::unordered_set<std::string> knownPeers;
  std::unordered_set<std::string> anchorPeers;
  std::unordered_map<std::string, EndpointRecord> knownPeerEndpoints;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point>
      peerListLastSent;
  std::atomic<int> activeOutboundDials{0};
  mutable std::mutex gossipMutex;
  mutable std::mutex peerBroadcastMutex;
  std::chrono::steady_clock::time_point lastPeerRebroadcast{};
  std::atomic<bool> peerFileLoaded{false};
  PeerBlacklist *blacklist;
  std::unordered_set<std::string> seenTxHashes;
  static Network *instancePtr;
  std::vector<std::thread> threads_;
  mutable std::mutex selfFilterMutex;
  std::unordered_set<std::string> localInterfaceAddrs;
  std::unordered_set<std::string> selfObservedAddrs;
  std::unordered_set<std::string> selfObservedEndpoints;

  // Helpers reused by handlePeer & connectToNode
  void startBinaryReadLoop(const std::string &peerId,
                           std::shared_ptr<Transport> transport);
  void dispatch(const alyncoin::net::Frame &f, const std::string &peerId);
  void sendInitialRequests(const std::string &peerId);
  void handlePeer(std::shared_ptr<Transport> transport);
  bool validateBlockSignatures(const Block &blk);
  void penalizePeer(const std::string &peer, int points);
  bool ensureEndpointCapacityLocked(bool incomingVerified);
  std::pair<std::string, unsigned short> determineAnnounceEndpoint() const;
  void recordExternalAddress(const std::string &ip, unsigned short port);
  void runHairpinCheck();
  void rememberPeerEndpoint(const std::string &ip, int port);
  void recordEndpointFailure(const std::string &host, int port);
  void recordSelfEndpoint(const std::string &host, int port);
  void refreshLocalInterfaceCache();
  bool shouldServeHeavyData(const std::string &peerId,
                            int remoteHeightHint = -1,
                            bool forSnapshot = false);
  void beginHeaderBridge(const std::string &peer);
  void handleHeaderResponse(
      const std::string &peer,
      const std::vector<HeadersSync::HeaderRecord> &headers);
  struct PeerSyncProgress {
    enum class Mode { Idle, Headers, Blocks, Snapshot };
    Mode mode{Mode::Idle};
    std::deque<std::string> blockQueue;
    std::unordered_set<std::string> requestedBlocks;
    std::vector<HeadersSync::HeaderRecord> headers;
    boost::multiprecision::cpp_int remoteWork{0};
    std::string remoteTip;
    std::chrono::steady_clock::time_point lastHeaderRequest{};
    int headerFailures{0};
  };
  mutable std::mutex syncStateMutex;
  std::unordered_map<std::string, PeerSyncProgress> peerSyncStates;
  void resetPeerSyncState(const std::string &peer);
  void setPeerSyncMode(const std::string &peer, PeerSyncProgress::Mode mode);
  void applySyncModeToPeerState(const std::string &peer,
                                PeerSyncProgress::Mode mode);
  bool noteHeaderFailure(const std::string &peer, const std::string &reason);
  void startHeaderSync(const std::string &peer);
  void requestQueuedBlocks(const std::string &peer);
  void onBlockAccepted(const std::string &hash);
  void bootstrapLoop();
  void pexLoop();
  std::thread bootstrapThread_;
  std::thread pexThread_;
  std::atomic<bool> loopsRunning_{false};
};
#endif // NETWORK_H
