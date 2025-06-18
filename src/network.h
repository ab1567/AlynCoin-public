#ifndef NETWORK_H
#define NETWORK_H

#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "generated/sync_protos.pb.h"
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
#include "transport/peer_globals.h"

using boost::asio::ip::tcp;

/* ------------------------------------------------------------------ */
/* Augment PeerState (declared in peer_manager.h) with a flag we need */
/* ------------------------------------------------------------------ */
struct PeerState {
    std::string ip;
    int         port        = 0;
    bool        alive       = true;
    bool        supportsSnapshot = false;   // <-- NEW
};

class Network {
public:
    /* ───────────── Singleton helpers ───────────── */
    static Network& getInstance(unsigned short port,
                                Blockchain*   bc = nullptr,
                                PeerBlacklist* bl = nullptr) {
        static std::map<unsigned short, std::unique_ptr<Network>> instances;
        static std::mutex mx;
        std::lock_guard<std::mutex> lk(mx);

        if (instances.count(port)) return *instances.at(port);

        auto obj      = std::make_unique<Network>(port, bc, bl);
        instancePtr   = obj.get();
        instances[port] = std::move(obj);
        return *instancePtr;
    }
    static Network& getInstance() {
        if (!instancePtr)
            throw std::runtime_error("Network::getInstance() called too early");
        return *instancePtr;
    }

    /* quick JSON sender */
    static void sendJsonToPeer(std::shared_ptr<Transport> t, const Json::Value& j) {
        Json::StreamWriterBuilder w; w["indentation"] = "";
        t->queueWrite("ALYN|" + Json::writeString(w, j) + "\n");
    }

    explicit Network(unsigned short port, Blockchain* bc,
                     PeerBlacklist* bl = nullptr);
    ~Network();

    /* ------------- public API (unchanged) ------------- */
    void start();
    void startListening();
    void syncWithPeers();
    void connectToPeer(const std::string& host, short port);
    /* … (all your existing public methods stay as-is) … */

    /* === Legacy helpers STILL referenced in blockchain.cpp / peer_manager.cpp === */
    std::string requestBlockchainSync(const std::string& peer);   // impl lives in network.cpp
    std::string receiveData         (const std::string& peer);    // impl lives in network.cpp

    /* === Snapshot-sync helpers (already used in .cpp) === */
    bool  peerSupportsSnapshot(const std::string& peerId) const;
    void  requestSnapshotSync(const std::string& peer);
    void  requestTailBlocks   (const std::string& peer, int fromHeight);
    void  sendSnapshot(std::shared_ptr<Transport> tr, int upToHeight = -1);
    void  sendTailBlocks(std::shared_ptr<Transport> tr, int fromHeight);
    void  handleSnapshotChunk(const std::string& peer, const std::string& b64);
    void  handleSnapshotEnd  (const std::string& peer);
    void  handleTailRequest  (const std::string& peer, int fromHeight);
    void  handleTailBlocks   (const std::string& peer, const std::string& b64);

private:
    /* core state */
    unsigned short                 port;
    Blockchain*                    blockchain;
    PeerManager*                   peerManager = nullptr;
    PeerBlacklist*                 blacklist   = nullptr;
    boost::asio::io_context        ioCtx;
    boost::asio::ip::tcp::acceptor acceptor;
    std::thread                    listenerTh;
    std::thread                    serverTh;
    std::atomic<bool>              running{false};
    std::atomic<bool>              syncing{false};

    /* snapshot download per peer */
    struct PeerSyncState {
        bool        snapshotActive = false;
        int         snapshotHeight = 0;
        std::string snapshotB64;
    };

    /* misc */
    std::unordered_map<std::string, std::shared_ptr<Transport>> peerTransports;
    std::unordered_set<std::string> bannedPeers;
    std::unordered_set<std::string> seenTxHashes;
    std::string publicPeerId;
    static Network* instancePtr;

    /* internal helpers */
    void startReadLoop(const std::string& peerId, std::shared_ptr<Transport> tr);
    void handlePeer    (std::shared_ptr<Transport> tr);
    void sendInitialRequests(const std::string& peerId);
    bool validateBlockSignatures(const Block& blk);
};

#endif /* NETWORK_H */
