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
#include "transport/transport.h"
#include "transport/peer_globals.h"  // <<--- ONLY include, don't redeclare!

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
            std::cerr << "❌ Failed to bind Network on port " << port << ": " << ex.what() << "\n";
            throw;
        }
    }

    inline static Network &getInstance() {
        if (!instancePtr) {
            throw std::runtime_error("❌ Network::getInstance() called before initialization.");
        }
        return *instancePtr;
    }

    explicit Network(unsigned short port, Blockchain *blockchain, PeerBlacklist *blacklistPtr = nullptr);
    ~Network();

    std::unordered_multimap<std::string, Block> orphanBlocks;
    void tryAttachOrphans(const std::string& newParentHash);

    Blockchain &getBlockchain() { return *blockchain; }
    void setPublicPeerId(const std::string& peerId);
    void start();
    void startListening();
    void syncWithPeers();
    void connectToPeer(const std::string &host, short port);
    void broadcastTransaction(const Transaction &tx);
    void broadcastTransactionToAllExcept(const Transaction &tx, const std::string &excludePeer);
    void broadcastMessage(const std::string &message);
    void broadcastBlock(const Block &block, bool force = false);
    void broadcastBlocks(const std::vector<Block>& blocks);
    void sendBlockToPeer(const std::string& peer, const Block& blk);
    void sendInventory(const std::string& peer);
    PeerManager *getPeerManager();
    std::vector<std::string> discoverPeers();
    void connectToDiscoveredPeers();
    std::string requestBlockchainSync(const std::string &peer);
    std::string receiveData(const std::string &peer);
    void requestPeerList();
    void scanForPeers();
    void processReceivedData(const std::string &senderIP, const std::string &data);
    void startServer();
    void handleIncomingData(const std::string &senderIP, std::string data, std::shared_ptr<Transport> transport);
    void sendLatestBlock(const std::string &peerIP);
    void sendLatestBlockIndex(const std::string &peerIP);
    void handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex);
    void sendFullChain(const std::string &peerIP);
    void sendFullChain(std::shared_ptr<Transport> transport);
    void loadPeers();
    void savePeers();
    void addPeer(const std::string &peer);
    void acceptConnections();
    void intelligentSync();
    void sendMessageToPeer(const std::string &peer, const std::string &message);
    void sendMessage(std::shared_ptr<Transport> transport, const std::string &message);
    std::vector<std::string> getPeers();
    bool sendData(const std::string &peer, const std::string &data);
    bool sendData(std::shared_ptr<Transport> transport, const std::string &data);
    void receiveTransaction(const Transaction &tx);
    void broadcastPeerList();
    void run();
    bool isSyncing() const;
    bool connectToNode(const std::string &ip, int port);
    void receiveFullChain(const std::string &sender, const std::string &serializedData);
    void autoMineBlock();
    void periodicSync();
    void broadcastRollupBlock(const RollupBlock &rollupBlock);
    void broadcastEpochProof(int epochIdx, const std::string &rootHash,
                             const std::vector<uint8_t> &proof);
    void requestEpochHeaders(const std::string &peerId);
    void handleNewRollupBlock(const RollupBlock &newRollupBlock);
    void receiveRollupBlock(const std::string &data);
    void listenForConnections();
    bool validatePeer(const std::string &peer);
    void handleNewBlock(const Block &newBlock);
    void blacklistPeer(const std::string &peer);
    bool isBlacklisted(const std::string &peer);
    void cleanupPeers();
    bool peerSupportsAggProof(const std::string& peerId) const;
    bool isSelfPeer(const std::string& peer) const;
    std::string getSelfAddressAndPort() const;
    inline static bool isUninitialized() { return instancePtr == nullptr; }
    inline static Network *getExistingInstance() { return instancePtr; }
    void autoSyncIfBehind();
    const auto& getPeerTable() const { return peerTransports; }
    void waitForInitialSync(int timeoutSeconds = 10);
    void handleBase64Proto(const std::string &peer, const std::string &prefix,
                                const std::string &b64, std::shared_ptr<Transport> transport);
    void handleGetData(const std::string& peer, const std::vector<std::string>& hashes);
    static unsigned short findAvailablePort(unsigned short startPort, int maxTries = 10);
    void sendStateProof(std::shared_ptr<Transport> tr);
    void broadcastRaw(const std::string& msg);
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
    PeerManager *peerManager = nullptr;
    std::string publicPeerId;
    std::unordered_set<std::string> bannedPeers;
    PeerBlacklist *blacklist;
    std::unordered_set<std::string> seenTxHashes;
    static Network *instancePtr;

    // Helpers reused by handlePeer & connectToNode
    void startReadLoop(const std::string& peerId, std::shared_ptr<Transport> transport);
    void sendInitialRequests(const std::string& peerId);
    void handlePeer(std::shared_ptr<Transport> transport);
    bool validateBlockSignatures(const Block &blk);
};
#endif // NETWORK_H
