#include "generated/block_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "generated/sync_protos.pb.h"
#include "network.h"
#include "blockchain.h"
#include "generated/net_frame.pb.h"
#include "wire/varint.h"
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>
#include "rollup/proofs/proof_verifier.h"
#include "rollup/rollup_block.h"
#include "syncing.h"
#include "transaction.h"
#include "zk/winterfell_stark.h"
#include <array>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include "crypto_utils.h"
#include <filesystem>
#include <iostream>
#include <set>
#include <algorithm>
#include <unordered_map>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include <cctype>
#include <memory>
#include "proto_utils.h"
#include <cstdlib>
#include <cstdio>
#include <sys/wait.h>
#ifdef HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif
#ifdef HAVE_LIBNATPMP
#include <natpmp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#endif
#include "transport/tcp_transport.h"
#include "transport/pubsub_router.h"

using namespace alyncoin;

// ==== [Globals, Statics] ====
static std::unordered_map<std::string, std::vector<Block>> incomingChains;
// Buffers for in-progress FULL_CHAIN syncs
// Per-peer sync buffers are now stored in PeerState via peerTransports
struct ScopedLockTracer {
    std::string name;
    ScopedLockTracer(const std::string &n) : name(n) {
        std::cerr << "[TRACE] Lock entered: " << name << std::endl;
    }
    ~ScopedLockTracer() {
        std::cerr << "[TRACE] Lock exited: " << name << std::endl;
    }
};
static std::unordered_set<std::string> seenTxHashes;
static std::mutex seenTxMutex;
static std::unordered_set<std::string> seenBlockHashes;
static std::mutex seenBlockMutex;

struct EpochProofEntry {
    std::string root;
    std::vector<uint8_t> proof;
};
static std::unordered_map<int, EpochProofEntry> receivedEpochProofs;
static std::mutex epochProofMutex;
static std::map<uint64_t, Block> futureBlockBuffer;
PubSubRouter g_pubsub;
namespace fs = std::filesystem;
Network* Network::instancePtr = nullptr;

static bool isPortAvailable(unsigned short port) {
    boost::asio::io_context io;
    boost::asio::ip::tcp::acceptor acceptor(io);
    boost::system::error_code ec;
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    if (ec) return false;
    acceptor.bind({boost::asio::ip::tcp::v4(), port}, ec);
    if (ec) return false;
    acceptor.close();
    return true;
}

unsigned short Network::findAvailablePort(unsigned short startPort, int maxTries) {
    for (int i = 0; i < maxTries; ++i) {
        unsigned short p = startPort + i;
        if (isPortAvailable(p)) return p;
    }
    return 0;
}
//

void Network::sendFrame(std::shared_ptr<Transport> tr, const google::protobuf::Message& m)
{
    if (!tr || !tr->isOpen()) return;
    const alyncoin::net::Frame* fr = dynamic_cast<const alyncoin::net::Frame*>(&m);
    if (fr) {
        std::string tag = fr->has_block_broadcast() ? "BLOCK"
                        : fr->has_snapshot_chunk() ? "SNAP_CHUNK"
                        : fr->has_snapshot_end()   ? "SNAP_END"
                        : fr->has_snapshot_req()   ? "SNAP_REQ"
                        : "OTHER";
        std::cerr << "[>>] Outgoing Frame Type=" << tag << "\n";
    }
    std::string payload = m.SerializeAsString();
    if (payload.empty()) {
        std::cerr << "[sendFrame] ❌ Attempting to send empty protobuf message!" << '\n';
        return;
    }
    uint8_t var[10];
    size_t n = encodeVarInt(payload.size(), var);
    std::string out(reinterpret_cast<char*>(var), n);
    out.append(payload);
    std::cerr << "[sendFrame] Sending frame, payload size: " << payload.size() << " bytes" << '\n';
    tr->writeBinary(out);
}

void Network::broadcastFrame(const google::protobuf::Message& m)
{
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (auto& kv : peerTransports)
    {
        auto tr = kv.second.tx;
        if (tr && tr->isOpen())
            sendFrame(tr, m);
    }
}

void Network::sendHeight(const std::string& peer) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    fr.mutable_height_res()->set_height(Blockchain::getInstance().getHeight());
    sendFrame(it->second.tx, fr);
}

void Network::sendTipHash(const std::string& peer) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    fr.mutable_tip_hash_res()->set_hash(Blockchain::getInstance().getLatestBlockHash());
    sendFrame(it->second.tx, fr);
}

void Network::sendPeerList(const std::string& peer) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    auto* pl = fr.mutable_peer_list();
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto& kv : peerTransports)
        pl->add_peers(kv.first);
    sendFrame(it->second.tx, fr);
}
// Fallback peer(s) in case DNS discovery fails
static const std::vector<std::string> DEFAULT_DNS_PEERS = {
    "49.206.56.213:15672", // Known bootstrap peer
    "35.209.49.156:15671"
};

// ==== [DNS Peer Discovery] ====
std::vector<std::string> fetchPeersFromDNS(const std::string& domain) {
    std::vector<std::string> peers;
    std::string cmd = "nslookup -type=TXT " + domain;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "❌ [DNS] Failed to run nslookup for domain: " << domain << "\n";
        return peers;
    }
    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        if (line.find("text =") != std::string::npos || line.find("\"") != std::string::npos) {
            size_t start = line.find("\"");
            size_t end = line.find_last_of("\"");
            if (start != std::string::npos && end > start) {
                std::string peer = line.substr(start + 1, end - start - 1);
                if (peer.find(":") != std::string::npos &&
                    peer.find(" ") == std::string::npos &&
                    peer.find(",") == std::string::npos) {
                    std::cout << "🌐 [DNS] Found peer TXT entry: " << peer << "\n";
                    peers.push_back(peer);
                }
            }
        }
    }
    int rc = pclose(pipe);
    if (rc != 0) {
        int code = WEXITSTATUS(rc);
        std::cerr << "⚠️ [DNS] nslookup exited with code " << code
                  << " for domain " << domain << "\n";
    }
    if (peers.empty()) {
        std::cerr << "⚠️ [DNS] No valid TXT peer records found at " << domain << "\n";
        peers = DEFAULT_DNS_PEERS; // fallback to built-in peers
        if (!peers.empty()) {
            std::cerr << "ℹ️  [DNS] Using fallback peers list." << std::endl;
        }
    }
    return peers;
}

// ==== [Network Ctor/Dtor] ====
#ifdef HAVE_MINIUPNPC
void tryUPnPPortMapping(int port) {
    struct UPnPContext {
        UPNPUrls urls{};
        IGDdatas data{};
        UPNPDev* devlist{nullptr};
        ~UPnPContext() {
            FreeUPNPUrls(&urls);
            if (devlist) freeUPNPDevlist(devlist);
        }
    } ctx;

    char lanAddr[64] = {0};
    ctx.devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, nullptr);
    if (!ctx.devlist) {
        std::cerr << "⚠️ [UPnP] upnpDiscover() failed or no devices found\n";
        return;
    }

    int igdStatus = UPNP_GetValidIGD(ctx.devlist, &ctx.urls, &ctx.data,
                                     lanAddr, sizeof(lanAddr));
    if (igdStatus != 1) {
        std::cerr << "⚠️ [UPnP] No valid IGD found\n";
        return;
    }

    char portStr[16];
    snprintf(portStr, sizeof(portStr), "%d", port);

    int ret = UPNP_AddPortMapping(ctx.urls.controlURL, ctx.data.first.servicetype,
                                  portStr, portStr, lanAddr,
                                  "AlynCoin", "TCP", nullptr, "0");

    if (ret == UPNPCOMMAND_SUCCESS) {
         std::cout << "✅ [UPnP] Port mapping added on port "
                  << std::dec << port << "\n";
    } else {
        std::cerr << "⚠️ [UPnP] Failed to add port mapping: "
                  << strupnperror(ret) << "\n";
    }
}
#endif
#ifdef HAVE_LIBNATPMP
void tryNATPMPPortMapping(int port) {
    natpmp_t natpmp;
    natpmpresp_t response;
    int r = initnatpmp(&natpmp, 0, 0);
    if (r < 0) {
        std::cerr << "⚠️ [NAT-PMP] initnatpmp failed: " << r << "\n";
        return;
    }
    r = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
    if (r < 0) {
        std::cerr << "⚠️ [NAT-PMP] send request failed: " << r << "\n";
        closenatpmp(&natpmp);
        return;
    }
    do {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(natpmp.s, &fds);
        struct timeval timeout;
        if (getnatpmprequesttimeout(&natpmp, &timeout) < 0) {
            std::cerr << "⚠️ [NAT-PMP] timeout failed\n";
            closenatpmp(&natpmp);
            return;
        }
        select(natpmp.s + 1, &fds, nullptr, nullptr, &timeout);
        r = readnatpmpresponseorretry(&natpmp, &response);
    } while (r == NATPMP_TRYAGAIN);

    if (r >= 0 && response.resultcode == 0) {
        std::cout << "✅ [NAT-PMP] Port mapping added on port "
                  << std::dec << port << "\n";
    } else {
        std::cerr << "⚠️ [NAT-PMP] Failed to add port mapping: " << r
                  << " resp=" << response.resultcode << "\n";
    }
    closenatpmp(&natpmp);
}
#endif


Network::Network(unsigned short port, Blockchain* blockchain, PeerBlacklist* blacklistPtr)
    : port(port), blockchain(blockchain), isRunning(false), syncing(true),
      ioContext(), acceptor(ioContext), blacklist(blacklistPtr) {
    if (!blacklistPtr) {
        std::cerr << "❌ [FATAL] PeerBlacklist is null! Cannot initialize network.\n";
        throw std::runtime_error("PeerBlacklist is null");
    }

    try {
        boost::asio::ip::tcp::acceptor::reuse_address reuseOpt(true);
        acceptor.open(boost::asio::ip::tcp::v4());

        boost::system::error_code ec;
        acceptor.set_option(reuseOpt, ec);
        if (ec) {
            std::cerr << "⚠️ [Network] Failed to set socket option: " << ec.message() << "\n";
        }

        // ✅ Bind to all interfaces (0.0.0.0)
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::make_address("0.0.0.0"), port);
        acceptor.bind(endpoint, ec);
        if (ec) {
            std::cerr << "❌ [Network Bind Error] bind failed on port " << port
                      << ": " << ec.message() << "\n";
            std::cerr << "❌ Failed to bind Network on port " << port
                      << " — skipping network startup.\n";
            return;
        }

        acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            std::cerr << "❌ [Network Listen Error] " << ec.message() << "\n";
            return;
        }

        std::cout << "🌐 Network listener started on port: "
                  << std::dec << port << "\n";
        peerManager = std::make_unique<PeerManager>(blacklistPtr, this);
        isRunning = true;
        listenerThread = std::thread(&Network::listenForConnections, this);
         threads_.push_back(std::move(listenerThread));

    } catch (const std::exception& ex) {
        std::cerr << "❌ [Network Exception] " << ex.what() << "\n";
    }
}

// ✅ Correct Destructor:

Network::~Network() {
    try {
	   ioContext.stop();
 	   acceptor.close();
	   for (auto& t : threads_) if (t.joinable()) t.join();
        std::cout << "✅ Network instance cleaned up safely." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "❌ Error during Network destruction: " << e.what() << std::endl;
    }
}
//
 void Network::listenForConnections() {
     std::cout << "🌐 Listening for connections on port: "
               << std::dec << port << std::endl;

     acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
         if (!ec) {
             std::cout << "🌐 [ACCEPTED] Incoming connection accepted.\n";
        auto sockPtr   = std::make_shared<tcp::socket>(std::move(socket));
        auto transport = std::make_shared<TcpTransport>(sockPtr);
        std::thread(&Network::handlePeer, this, transport).detach();
         } else {
             std::cerr << "❌ [Network] Accept error: " << ec.message() << "\n";
         }

         // 🔁 Recursive call to keep the acceptor alive
         listenForConnections();
     });
 }
//

void Network::start() {
  startServer();
  intelligentSync();
}

// ✅ **Auto-Mining Background Thread**
void Network::autoMineBlock() {
  std::thread([this]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(5));

      Blockchain &blockchain = *this->blockchain;
      if (!blockchain.getPendingTransactions().empty()) {
        std::cout << "⛏️ New transactions detected. Starting mining..." << std::endl;

        // Use default miner address
        std::string minerAddress = "miner";  // Replace with actual configured address if needed
        std::vector<unsigned char> dilithiumPriv = Crypto::loadDilithiumKeys(minerAddress).privateKey;
        std::vector<unsigned char> falconPriv    = Crypto::loadFalconKeys(minerAddress).privateKey;

        if (dilithiumPriv.empty() || falconPriv.empty()) {
          std::cerr << "❌ Miner private keys not found or invalid!" << std::endl;
          continue;
        }

        Block minedBlock = blockchain.minePendingTransactions(minerAddress, dilithiumPriv, falconPriv);

        // Validate signatures using raw block hash
        std::vector<unsigned char> msgHash = Crypto::fromHex(minedBlock.getHash());
        std::vector<unsigned char> sigDil = minedBlock.getDilithiumSignature();
        std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(minedBlock.getMinerAddress());

        std::vector<unsigned char> sigFal = minedBlock.getFalconSignature();
        std::vector<unsigned char> pubFal = Crypto::getPublicKeyFalcon(minedBlock.getMinerAddress());
        bool validSignatures =
            Crypto::verifyWithDilithium(msgHash, sigDil, pubDil) &&
            Crypto::verifyWithFalcon(msgHash, sigFal, pubFal);

        if (blockchain.isValidNewBlock(minedBlock) && validSignatures) {
          {
            std::lock_guard<std::mutex> lock(blockchainMutex);
            Blockchain::getInstance().saveToDB();
          }
          broadcastBlock(minedBlock);
          std::cout << "✅ Mined & broadcasted block: " << minedBlock.getHash() << std::endl;
        } else {
          std::cerr << "❌ Mined block failed validation or signature check!" << std::endl;
        }
      }
    }
  }).detach();
}

//
// ✅ **Getter function for syncing status**
bool Network::isSyncing() const { return syncing; }

// ✅ **Broadcast a transaction to all peers**

void Network::broadcastTransaction(const Transaction &tx) {
    alyncoin::TransactionProto proto = tx.toProto();
    alyncoin::net::Frame fr;
    *fr.mutable_tx_broadcast()->mutable_tx() = proto;
    for (const auto &peer : peerTransports) {
        auto transport = peer.second.tx;
        if (transport && transport->isOpen()) {
            try {
                sendFrame(transport, fr);
                std::cout << "📡 Transaction broadcasted to peer: " << peer.first << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "❌ [ERROR] Failed to broadcast transaction to "
                          << peer.first << ": " << e.what() << std::endl;
            }
        }
    }
}

// Broadcast transaction to all peers except sender (to prevent echo storms)
void Network::broadcastTransactionToAllExcept(const Transaction &tx, const std::string &excludePeer) {
    alyncoin::TransactionProto proto = tx.toProto();
    alyncoin::net::Frame fr;
    *fr.mutable_tx_broadcast()->mutable_tx() = proto;
    for (const auto &peer : peerTransports) {
        if (peer.first == excludePeer) continue;
        auto transport = peer.second.tx;
        if (transport && transport->isOpen()) {
            try {
                sendFrame(transport, fr);
                std::cout << "📡 [TX] Rebroadcast to peer: " << peer.first << std::endl;
            } catch (const std::exception &e) {
                std::cerr << "❌ [ERROR] Failed to broadcast tx to " << peer.first << ": " << e.what() << std::endl;
            }
        }
    }
}


// sync with peers
void Network::syncWithPeers() {
    std::cout << "🔄 [INFO] Syncing with peers..." << std::endl;
    if (peerTransports.empty()) {
        std::cerr << "⚠️ [WARNING] No peers available for sync!\n";
        return;
    }

    const size_t myHeight = Blockchain::getInstance().getHeight();

    for (const auto &[peer, entry] : peerTransports) {
        if (peer.empty()) continue;

        auto  transport  = entry.tx;
        int   peerHeight = peerManager ? peerManager->getPeerHeight(peer) : -1;

        /* ask for height if unknown */
        if (peerHeight == -1) {
            auto it2 = peerTransports.find(peer);
            if (it2 != peerTransports.end() && it2->second.tx) {
                alyncoin::net::Frame fr; fr.mutable_height_req();
                sendFrame(it2->second.tx, fr);
            }
            continue;
        }

        /* ── peer is *ahead* ── */
        if (static_cast<size_t>(peerHeight) > myHeight) {
            if      (peerSupportsSnapshot(peer))  requestSnapshotSync(peer);
            else if (peerSupportsAggProof(peer))  requestEpochHeaders(peer);
            continue;
        }

        /* ── peer is *behind* ── */
        if (static_cast<size_t>(peerHeight) < myHeight &&
            transport && transport->isOpen())
        {
            if (peerSupportsSnapshot(peer))
                sendTailBlocks(transport, peerHeight);   // push just the tail they’re missing
        }
    }
}
// ✅ New smart sync method
void Network::intelligentSync() {
    std::cout << "🔄 [Smart Sync] Starting intelligent sync process...\n";

    if (!peerManager || peerTransports.empty()) {
        std::cerr << "⚠️ [Smart Sync] No peers or no PeerManager. Skipping sync.\n";
        return;
    }

    const int localHeight   = blockchain->getHeight();
    const int networkHeight = peerManager->getMedianNetworkHeight();

    if (networkHeight <= localHeight) {
        std::cout << "✅ [Smart Sync] Local blockchain is up-to-date. No sync needed.\n";
        return;
    }

    std::cout << "📡 [Smart Sync] Local height: " << localHeight
              << ", Network height: " << networkHeight << ". Sync needed.\n";

    /* pick the first suitable peer that is ahead */
    for (const auto &[peer, entry] : peerTransports) {
        int ph = peerManager->getPeerHeight(peer);
        if (ph <= localHeight) continue;

        if      (peerSupportsSnapshot(peer))  requestSnapshotSync(peer);
        else if (peerSupportsAggProof(peer))  requestEpochHeaders(peer);
        break;  // one good peer is enough
    }
}
//
void Network::connectToPeer(const std::string &ip, short port) {
    std::string peerKey = ip + ":" + std::to_string(port);
    if (isSelfPeer(peerKey)) {
        std::cerr << "⚠️ [connectToPeer] Skipping self connect: " << peerKey << "\n";
        return;
    }
    connectToNode(ip, port);
}

// ✅ **Broadcast peer list to all connected nodes**
void Network::broadcastPeerList() {
    ScopedLockTracer tracer("broadcastPeerList");
    std::vector<std::string> peers;
    {
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        if (peerTransports.empty()) return;
        for (const auto &[peerAddr, _] : peerTransports) {
            if (peerAddr.find(":") == std::string::npos) continue;
            peers.push_back(peerAddr);
        }
    }

    for (const auto &peerAddr : peers) {
        auto it = peerTransports.find(peerAddr);
        if (it == peerTransports.end() || !it->second.tx) continue;
        alyncoin::net::Frame fr;
        auto* pl = fr.mutable_peer_list();
        for (const auto& p : peers) pl->add_peers(p);
        sendFrame(it->second.tx, fr);
    }

}

//
PeerManager* Network::getPeerManager() {
     return peerManager.get();
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
    for (const auto& [peerAddr, entry] : peerTransports) {
        if (entry.tx && entry.tx->isOpen()) {
            alyncoin::net::Frame fr; fr.mutable_peer_list_req();
            sendFrame(entry.tx, fr);
        }
    }
    std::cout << "📡 Requesting peer list from all known peers..." << std::endl;
}
// Handle Peer (Transport version)
void Network::handlePeer(std::shared_ptr<Transport> transport)
{
    std::string realPeerId, claimedPeerId;
    std::string claimedVersion, claimedNetwork;
    int  remoteHeight = 0;
    bool remoteAgg   = false;
    bool remoteSnap  = false;

    /* what *we* look like to the outside world */
    const auto selfAddr = [this]{
        return publicPeerId.empty()
             ? "127.0.0.1:" + std::to_string(port)
             : publicPeerId;
    };

    // ── 1. read + verify handshake ──────────────────────────────────────────
    try {
        std::string blob = transport->readBinaryBlocking();
        alyncoin::net::Frame fr;
        if (blob.empty() || !fr.ParseFromString(blob) || !fr.has_handshake())
            throw std::runtime_error("invalid handshake");

        const auto& hs = fr.handshake();

        const std::string senderIP = transport->getRemoteIP();
        // The Handshake proto uses proto3 semantics so there is no
        // `has_listen_port()` accessor. If the field is omitted the value will
        // be zero, which is invalid for a listening port.
        if (hs.listen_port() == 0)
            throw std::runtime_error("peer did not declare listen_port");
        const int finalPort = hs.listen_port();
        realPeerId         = senderIP + ':' + std::to_string(finalPort);

        claimedVersion = hs.version();
        claimedNetwork = hs.network_id();
        remoteHeight   = static_cast<int>(hs.height());

        bool gotBinary = false;
        for (const auto& cap : hs.capabilities()) {
            if (cap == "agg_proof_v1")  remoteAgg  = true;
            if (cap == "snapshot_v1")   remoteSnap = true;
            if (cap == "binary_v1")     gotBinary  = true;
        }
        if (!gotBinary)
            throw std::runtime_error("legacy peer – no binary_v1");
        claimedPeerId = realPeerId;

        std::string myGenesis;
        if (!Blockchain::getInstance().getChain().empty())
            myGenesis = Blockchain::getInstance().getChain().front().getHash();
        if (!hs.genesis_hash().empty() && !myGenesis.empty() &&
            hs.genesis_hash() != myGenesis) {
            std::cerr << "⚠️  [handlePeer] genesis hash mismatch – dropped." << '\n';
            return;
        }

        std::cout << "🤝 Handshake from " << realPeerId
                  << " | ver "      << claimedVersion
                  << " | net "      << claimedNetwork
                  << " | height "   << remoteHeight << '\n';

        if (claimedNetwork != "mainnet") {
            std::cerr << "⚠️  [handlePeer] peer is on another network – dropped.\n";
            return;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "❌ [handlePeer] invalid binary handshake (" << ex.what() << ")" << '\n';
        return;
    }

    // ── 2. refuse self-connects ─────────────────────────────────────────────
    if (claimedPeerId == selfAddr() || realPeerId == selfAddr()) {
        std::cout << "🛑 Self-connect ignored: " << claimedPeerId << '\n';
        return;
    }

    // ── 3. register / update transport entry ───────────────────────────────
    {
        ScopedLockTracer t("handlePeer/register");
        std::lock_guard<std::timed_mutex> lk(peersMutex);

        auto& entry = peerTransports[claimedPeerId];
        entry.tx    = transport;
        if (!entry.state) entry.state = std::make_shared<PeerState>();
        entry.state->supportsAggProof  = remoteAgg;
        entry.state->supportsSnapshot = remoteSnap;

        if (peerManager) {
            peerManager->connectToPeer(claimedPeerId);
            peerManager->setPeerHeight (claimedPeerId, remoteHeight);
        }
    }

    std::cout << "✅ Registered peer: " << claimedPeerId << '\n';

    // ── 4. push our handshake back ──────────────────────────────────────────
    {
        alyncoin::net::Handshake hs;
        Blockchain& bc = Blockchain::getInstance();
        hs.set_version("1.0.0");
        hs.set_network_id("mainnet");
        hs.set_height(bc.getHeight());
        hs.set_listen_port(this->port);
        if (!bc.getChain().empty())
            hs.set_genesis_hash(bc.getChain().front().getHash());
        hs.add_capabilities("full");
        hs.add_capabilities("miner");
        hs.add_capabilities("agg_proof_v1");
        hs.add_capabilities("snapshot_v1");
        hs.add_capabilities("binary_v1");
        alyncoin::net::Frame out;
        out.mutable_handshake()->CopyFrom(hs);
        sendFrame(transport, out);
    }

    // ── 5. arm read loop + initial requests ────────────────────────────────
    startBinaryReadLoop(claimedPeerId, transport);

    sendInitialRequests(claimedPeerId);

    // ── 6. immediate sync decision ─────────────────────────────────────────
    const size_t myHeight = Blockchain::getInstance().getHeight();
    if (remoteHeight > static_cast<int>(myHeight)) {
        if      (remoteSnap) requestSnapshotSync(claimedPeerId);
        else if (remoteAgg)  requestEpochHeaders(claimedPeerId);
    }
    else if (remoteHeight < static_cast<int>(myHeight) && remoteSnap)
        sendTailBlocks(transport, remoteHeight);

    autoSyncIfBehind();
    syncWithPeers();

    // ── 7. optional reverse connect removed for binary protocol ──
}
// ✅ **Run Network Thread**
void Network::run() {
    std::cout << "🚀 [Network] Starting network stack for port " << port << "\n";
    #ifdef HAVE_MINIUPNPC
    tryUPnPPortMapping(this->port);
    #elif defined(HAVE_LIBNATPMP)
    tryNATPMPPortMapping(this->port);
    #endif
    // Start listener and IO thread
    startServer();
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // === 1. Only DNS-based bootstrap at startup ===
    std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
    for (const std::string& peer : dnsPeers) {
        size_t colonPos = peer.find(":");
        if (colonPos == std::string::npos) continue;
        std::string ip = peer.substr(0, colonPos);
        int p = std::stoi(peer.substr(colonPos + 1));
        if ((ip == "127.0.0.1" || ip == "localhost") && p == this->port) continue;
        if (ip == "127.0.0.1" || ip == "localhost") continue;
        if (isSelfPeer(ip + ":" + std::to_string(p))) continue;
        connectToNode(ip, p);
    }

    // Initial sync/gossip setup
    requestPeerList();
    autoMineBlock();

    // Trigger a sync immediately after startup so the node isn't left waiting
    // for the periodic thread to run before catching up with peers.
    this->autoSyncIfBehind();

    // Give some additional time for peers to connect, then try again to ensure
    // we didn't miss any height updates.
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::seconds(3)); // Let connectToNode finish
        this->autoSyncIfBehind();
    }).detach();

    // Periodic tasks (sync, cleanup, gossip mesh)
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            periodicSync();
        }
    }).detach();

    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(20));
            cleanupPeers();
        }
    }).detach();

    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            this->requestPeerList();
        }
    }).detach();

    std::cout << "✅ [Network] Network loop launched successfully.\n";
}

// Call this after all initial peers are connected
void Network::autoSyncIfBehind() {
    Blockchain &bc  = Blockchain::getInstance();
    const size_t myHeight = bc.getHeight();
    const std::string myTip = bc.getLatestBlockHash();

    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &[peerAddr, entry] : peerTransports) {
        auto tr = entry.tx;
        if (!tr || !tr->isOpen()) continue;

        alyncoin::net::Frame f1; f1.mutable_height_req();
        sendFrame(tr, f1);
        alyncoin::net::Frame f2; f2.mutable_tip_hash_req();
        sendFrame(tr, f2);

        if (!peerManager) continue;
        int  peerHeight = peerManager->getPeerHeight(peerAddr);
        std::string peerTip = peerManager->getPeerTipHash(peerAddr);

        std::cout << "[autoSync] peer=" << peerAddr
                  << " height=" << peerHeight
                  << " | local=" << myHeight << '\n';

        if (peerHeight > static_cast<int>(myHeight)) {
            if (peerSupportsSnapshot(peerAddr)) {
                std::cout << "  → requesting snapshot sync\n";
                requestSnapshotSync(peerAddr);
            } else if (peerSupportsAggProof(peerAddr)) {
                std::cout << "  → requesting epoch headers\n";
                requestEpochHeaders(peerAddr);
            }
        }
        else if (peerHeight == static_cast<int>(myHeight) &&
                 !peerTip.empty() && peerTip != myTip)
        {
            if (peerSupportsSnapshot(peerAddr)) {
                std::cout << "  → tip mismatch, requesting snapshot sync\n";
                requestSnapshotSync(peerAddr);
            } else if (peerSupportsAggProof(peerAddr)) {
                std::cout << "  → tip mismatch, requesting epoch headers\n";
                requestEpochHeaders(peerAddr);
            }
        }
        else if (peerHeight < static_cast<int>(myHeight)) {
            if (peerSupportsSnapshot(peerAddr)) {
                std::cout << "  → sending tail blocks\n";
                sendTailBlocks(tr, peerHeight);
            }
        }
    }
}
void Network::waitForInitialSync(int timeoutSeconds) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        size_t localHeight = blockchain->getHeight();
        int networkHeight = peerManager ? peerManager->getMedianNetworkHeight() : 0;
        if (networkHeight > 0 && localHeight >= static_cast<size_t>(networkHeight)) {
            syncing = false;
            break;
        }
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(timeoutSeconds)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
    std::vector<std::string> peers;
    std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
    for (const auto& peer : dnsPeers) {
        if (!peer.empty()) {
            std::cout << "🌐 [DNS] Found peer: " << peer << "\n";
            peers.push_back(peer);
        }
    }
    return peers;
}

//
void Network::connectToDiscoveredPeers() {
    std::vector<std::string> peers = discoverPeers();
    for (const std::string &peer : peers) {
        size_t pos = peer.find(":");
        if (pos == std::string::npos) continue;
        std::string ip = peer.substr(0, pos);
        int port = std::stoi(peer.substr(pos + 1));
        std::string peerKey = ip + ":" + std::to_string(port);
        if (isSelfPeer(peerKey)) {
            std::cout << "⚠️ Skipping self in discovered peers: " << peerKey << "\n";
            continue;
        }
        if (ip == "127.0.0.1" || ip == "localhost") continue;
        connectToNode(ip, port);
    }
}

//
void Network::periodicSync() {
    ScopedLockTracer tracer("periodicSync");
    std::lock_guard<std::timed_mutex> lock(peersMutex);

    for (const auto &p : peerTransports) {
        const auto &peerId  = p.first;
        const auto &transport  = p.second.tx;
        if (!transport || !transport->isOpen()) continue;

        alyncoin::net::Frame f; f.mutable_height_req();
        sendFrame(transport, f);

        std::cerr << "📡 [DEBUG] Height probe sent to " << peerId << '\n';
    }
}
//
std::vector<std::string> Network::getPeers() {
    std::vector<std::string> peerList;
    for (const auto &peer : peerTransports) {
        if (peer.second.tx && peer.second.tx->isOpen()) {
            peerList.push_back(peer.first); // Only include connected peers
        }
    }
    return peerList;
}

//
void Network::sendStateProof(std::shared_ptr<Transport> tr)
{
    if (!tr || !tr->isOpen()) return;

    Blockchain& bc = Blockchain::getInstance();
    const int    h  = bc.getHeight();
    const Block& tip= bc.getLatestBlock();

    // -- ❶ compute state root (pick the one you trust) --
    std::string stateRoot = bc.getLatestBlock().getMerkleRoot(); // or bc.getStateRoot()

    // -- ❷ generate proof bytes --
    std::string proof = WinterfellStark::generateProof(
                            stateRoot,                    // blockHash
                            tip.getPreviousHash(),        // prev
                            tip.getTxRoot());             // tx_root

    alyncoin::StateProofProto proto;
    proto.set_block_height(h);
    proto.set_state_root(stateRoot);
    proto.set_zk_proof(proof);

    alyncoin::net::Frame fr;
    fr.mutable_state_proof()->mutable_proof()->CopyFrom(proto);
    sendFrame(tr, fr);
}
//

// ✅ **Handle Incoming Data with Protobuf Validation**


// ✅ **Broadcast a mined block to all peers*
void Network::broadcastBlock(const Block& block, bool /*force*/)
{
    {
        std::lock_guard<std::mutex> lk(seenBlockMutex);
        if (seenBlockHashes.count(block.getHash()))
            return;
        seenBlockHashes.insert(block.getHash());
    }
    // Serialize to protobuf and then base64
    alyncoin::BlockProto proto = block.toProtobuf();
    std::string raw;
    if (!proto.SerializeToString(&raw) || raw.empty()) {
        std::cerr << "[BUG] EMPTY proto in broadcastBlock for idx=" << block.getIndex() << " hash=" << block.getHash() << "\n";
        return;
    }
    // Pre-build binary frame
    alyncoin::net::Frame fr;
    *fr.mutable_block_broadcast()->mutable_block() = proto;

    std::unordered_map<std::string, PeerEntry> peersCopy;
    {
        ScopedLockTracer _t("broadcastBlock");
        std::unique_lock<std::timed_mutex> lk(peersMutex, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(500))) {
            std::cerr << "⚠️ [broadcastBlock] peersMutex lock timeout\n";
            return;
        }
        peersCopy = peerTransports;
    }

    std::set<std::shared_ptr<Transport>> seen;
    for (auto& [peerId, entry] : peersCopy)
    {
        auto transport = entry.tx;
        if (isSelfPeer(peerId) || !transport || !transport->isOpen()) continue;
        if (!seen.insert(transport).second) continue;

        try {
            sendFrame(transport, fr);
            std::cout << "✅ [broadcastBlock] Block " << block.getIndex() << " sent to " << peerId << '\n';
        }
        catch (const std::exception& e) {
            std::cerr << "❌ [broadcastBlock] Send to " << peerId << " failed: " << e.what() << '\n';
        }
    }
}

// Broadcast a batch of blocks
void Network::broadcastBlocks(const std::vector<Block>& blocks)
{
    if (blocks.empty()) return;
    for (const auto& b : blocks) {
        std::lock_guard<std::mutex> lk(seenBlockMutex);
        seenBlockHashes.insert(b.getHash());
    }
    alyncoin::BlockchainProto proto;
    for (const auto& b : blocks)
        *proto.add_blocks() = b.toProtobuf();
    std::string raw;
    if (!proto.SerializeToString(&raw) || raw.empty()) return;

    alyncoin::net::Frame fr;
    fr.mutable_block_batch()->mutable_chain()->CopyFrom(proto);

    for (auto& [peerId, entry] : peerTransports) {
        auto transport = entry.tx;
        if (isSelfPeer(peerId) || !transport || !transport->isOpen()) continue;
        sendFrame(transport, fr);
    }
}

void Network::sendBlockToPeer(const std::string& peer, const Block& blk)
{
    {
        std::lock_guard<std::mutex> lk(seenBlockMutex);
        if (seenBlockHashes.count(blk.getHash()))
            return;
        seenBlockHashes.insert(blk.getHash());
    }
    alyncoin::BlockProto proto = blk.toProtobuf();
    std::string raw;
    if (!proto.SerializeToString(&raw) || raw.empty()) return;
    alyncoin::net::Frame fr;
    *fr.mutable_block_broadcast()->mutable_block() = proto;
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end() && it->second.tx && it->second.tx->isOpen())
        sendFrame(it->second.tx, fr);
}
//
bool Network::isSelfPeer(const std::string& peer) const {
    std::string selfAddr = getSelfAddressAndPort();
    if (peer == selfAddr ||
        peer == "127.0.0.1:" + std::to_string(this->port) ||
        peer == "localhost:" + std::to_string(this->port))
        return true;

    if (!publicPeerId.empty()) {
        auto colon = publicPeerId.find(':');
        std::string ipSelf = publicPeerId.substr(0, colon);
        std::string peerIp = peer.substr(0, peer.find(':'));
        if (peerIp == ipSelf)
            return true;
    }
    return false;
}

std::string Network::getSelfAddressAndPort() const {
    // Prefer explicit publicPeerId if set
    if (!publicPeerId.empty())
        return publicPeerId;
    // Fallback: localhost + port
    return "127.0.0.1:" + std::to_string(this->port);
}

void Network::setPublicPeerId(const std::string& peerId) {
    publicPeerId = peerId;
}
//

void Network::handleGetData(const std::string& peer, const std::vector<std::string>& hashes)
{
    Blockchain& bc = Blockchain::getInstance();
    for (const auto& h : hashes) {
        for (const auto& blk : bc.getChain()) {
            if (blk.getHash() == h) {
                sendBlockToPeer(peer, blk);
                break;
            }
        }
    }
}



//
void Network::receiveTransaction(const Transaction &tx) {
    std::string txHash = tx.getHash();
    {
        std::lock_guard<std::mutex> lock(seenTxMutex);
        if (seenTxHashes.count(txHash) > 0)
            return;
        seenTxHashes.insert(txHash);
    }

    Blockchain::getInstance().addTransaction(tx);
    broadcastTransaction(tx);
}

// Valid peer
// Handle new block
void Network::handleNewBlock(const Block &newBlock) {
    Blockchain &blockchain = Blockchain::getInstance();
    std::cerr << "[handleNewBlock] Attempting to add block idx="
              << newBlock.getIndex() << " hash=" << newBlock.getHash() << '\n';
    const int expectedIndex = blockchain.getLatestBlock().getIndex() + 1;

    // 1) PoW and zk-STARK check
    if (!newBlock.hasValidProofOfWork()) {
        std::cerr << "❌ [ERROR] Block PoW check failed!\n";
        return;
    }

    const auto& zkVec = newBlock.getZkProof();
    if (zkVec.empty()) {
        std::cerr << "❌ [ERROR] Missing zkProof in incoming block!\n";
        return;
    }

    std::string zkProofStr(zkVec.begin(), zkVec.end());
    if (!WinterfellStark::verifyProof(
            zkProofStr,
            newBlock.getHash(),
            newBlock.getPreviousHash(),
            newBlock.getTransactionsHash())) {
        std::cerr << "❌ [ERROR] Invalid zk-STARK proof detected in new block!\n";
        return;
    }

    // 2) Fork detection
    if (!blockchain.getChain().empty()) {
        std::string localTipHash = blockchain.getLatestBlockHash();
        if (newBlock.getPreviousHash() != localTipHash) {
            std::cerr << "⚠️ [Fork Detected] Previous hash mismatch at incoming block.\n";
            std::vector<Block> forkCandidate = { newBlock };
            blockchain.saveForkView(forkCandidate);

            for (const auto& peer : peerTransports) {
                sendForkRecoveryRequest(peer.first, newBlock.getHash());
            }
            return;
        }
    }

    // 3) Index ordering
    if (newBlock.getIndex() < expectedIndex) {
        std::cerr << "⚠️ [Node] Ignoring duplicate or old block (idx=" << newBlock.getIndex() << ").\n";
        if (!blockchain.hasBlockHash(newBlock.getHash())) {
            std::cerr << "🧐 [Node] Unknown historical block. Requesting full sync.\n";
            blockchain.setPendingForkChain({newBlock});
            for (const auto &peer : peerTransports) {
                sendForkRecoveryRequest(peer.first, newBlock.getHash());
            }
        }
        return;
    }
    if (newBlock.getIndex() > expectedIndex) {
        std::cerr << "⚠️ [Node] Received future block. Buffering (idx=" << newBlock.getIndex() << ").\n";
        futureBlockBuffer[newBlock.getIndex()] = newBlock;

        if (newBlock.getIndex() > expectedIndex + 5) {
            for (const auto& peer : peerTransports) {
                sendForkRecoveryRequest(peer.first, newBlock.getHash());
            }
        }
        return;
    }

    // 4) Signature validation
    try {
        auto msgBytes = newBlock.getSignatureMessage();
        auto sigDil = newBlock.getDilithiumSignature();
        auto pubDil = newBlock.getPublicKeyDilithium();

        if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
            std::cerr << "❌ Dilithium signature verification failed!\n";
            return;
        }

        auto sigFal = newBlock.getFalconSignature();
        auto pubFal = newBlock.getPublicKeyFalcon();

        if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
            std::cerr << "❌ Falcon signature verification failed!\n";
            return;
        }

    } catch (const std::exception& e) {
        std::cerr << "❌ [Exception] Signature verification error: " << e.what() << "\n";
        return;
    }

    // 5) Add and save
    try {
        if (!blockchain.addBlock(newBlock)) {
            std::cerr << "❌ [ERROR] Failed to add new block.\n";
            return;
        }

        blockchain.saveToDB();
        std::cout << "✅ Block added successfully! Index: " << newBlock.getIndex() << "\n";

    } catch (const std::exception& ex) {
        std::cerr << "❌ [EXCEPTION] Block add/save failed: " << ex.what() << "\n";
    }

    // 6) Process any buffered future blocks
    uint64_t nextIndex = blockchain.getLatestBlock().getIndex() + 1;
    while (futureBlockBuffer.count(nextIndex)) {
        auto nextBlk = futureBlockBuffer[nextIndex];
        futureBlockBuffer.erase(nextIndex);
        std::cout << "⏩ Processing buffered block: " << nextIndex << "\n";
        handleNewBlock(nextBlk);
        ++nextIndex;
    }
}

// Black list peer
void Network::blacklistPeer(const std::string &peer) {
  peerTransports.erase(peer);
  bannedPeers.insert(peer);
}

bool Network::isBlacklisted(const std::string &peer) {
  return bannedPeers.find(peer) != bannedPeers.end();
}

// ✅ **Send Data to Peer with Error Handling**

bool Network::sendData(std::shared_ptr<Transport> transport, const std::string &data) {
    if (!transport || !transport->isOpen()) {
        std::cerr << "❌ [sendData] Transport is null or closed\n";
        return false;
    }
    try {
        std::string finalMessage = data;
        while (!finalMessage.empty() && (finalMessage.back() == '\n' || finalMessage.back() == '\r')) {
            finalMessage.pop_back();
        }
        finalMessage += '\n';

        transport->queueWrite(finalMessage, false);
        std::cout << "📡 [DEBUG] Queued message to transport: " << finalMessage.substr(0, 100) << "...\n";
        return true;
    } catch (const std::exception &e) {
        std::cerr << "❌ [sendData] Transport send failed: " << e.what() << "\n";
        return false;
    }
}

// ✅ **Request Blockchain Sync from Peers**
std::string Network::requestBlockchainSync(const std::string &peer) {
    {
        std::lock_guard<std::timed_mutex> lk(peersMutex);
        if (!peerTransports.count(peer)) {
            std::cerr << "❌ [ERROR] Peer not found: " << peer << "\n";
            return "";
        }
    }

    std::cout << "📡 Initiating catch-up sync with: " << peer << "\n";

    if      (peerSupportsSnapshot(peer))  requestSnapshotSync(peer);
    else if (peerSupportsAggProof(peer))  requestEpochHeaders(peer);
    else
        std::cerr << "⚠️  Peer " << peer
                  << " offers no modern sync capability. Skipping.\n";

    return "";
}
// ✅ **Start Listening for Incoming Connections**
void Network::startServer() {
    try {
        std::cout << "🌐 Node is now listening for connections on port: "
                  << std::dec << port << "\n";

        ioContext.restart();  // Must come before async_accept
        listenForConnections();

        std::thread ioThread([this]() {
            std::cout << "🚀 IO context thread started for port "
                      << std::dec << port << "\n";
            try {
                ioContext.run();
                std::cout << "✅ IO context exited normally for port "
                          << std::dec << port << "\n";
            } catch (const std::exception& e) {
                std::cerr << "❌ [IOContext] Exception: " << e.what() << "\n";
            }
        });

        ioThread.detach();  // Detach safely
    } catch (const std::exception &e) {
        std::cerr << "❌ [ERROR] Server failed to start: " << e.what() << "\n";
        std::cerr << "⚠️ Try using a different port or checking if another instance is running.\n";
    }
}

// ✅ **Receive Data from Peer (Blocking)**
std::string Network::receiveData(const std::string &peer) {
    try {
        std::shared_ptr<Transport> transport;
        {
            std::lock_guard<std::timed_mutex> lk(peersMutex);
            auto it = peerTransports.find(peer);
            if (it == peerTransports.end() || !it->second.tx) {
                std::cerr << "❌ [ERROR] Peer not found or transport null: " << peer << std::endl;
                return "";
            }
            transport = it->second.tx;
        }
        return transport->readLineWithTimeout(3); // Assuming Transport has this method!
    } catch (const std::exception &e) {
        std::cerr << "❌ [EXCEPTION] receiveData: " << e.what() << "\n";
        return "";
    }
}

// ✅ Add peer
void Network::addPeer(const std::string &peer) {
    if (peerTransports.find(peer) != peerTransports.end()) {
        return;
    }
    auto transport = std::make_shared<TcpTransport>(ioContext);

    peerTransports.emplace(peer, PeerEntry{transport, std::make_shared<PeerState>()});
    std::cout << "📡 Peer added: " << peer << std::endl;
    savePeers(); // ✅ Save immediately
}

// ------------------------------------------------------------------
//  Helper: send the three “kick-off” messages after a connection
// ------------------------------------------------------------------
void Network::sendInitialRequests(const std::string& peerId) {
    auto it = peerTransports.find(peerId);
    if (it == peerTransports.end() || !it->second.tx) return;

    alyncoin::net::Frame f1; f1.mutable_height_req();
    sendFrame(it->second.tx, f1);

    alyncoin::net::Frame f2; f2.mutable_tip_hash_req();
    sendFrame(it->second.tx, f2);

    alyncoin::net::Frame f3; f3.mutable_peer_list_req();
    sendFrame(it->second.tx, f3);

    if (peerSupportsSnapshot(peerId))
        requestSnapshotSync(peerId);
    else if (peerSupportsAggProof(peerId))
        requestEpochHeaders(peerId);

    sendInventory(peerId);
}
// ------------------------------------------------------------------
//  Helper: set up an endless async-read loop for a socket
// ------------------------------------------------------------------
void Network::startBinaryReadLoop(const std::string& peerId, std::shared_ptr<Transport> transport)
{
    if (!transport || !transport->isOpen()) return;
    auto cb = [this, peerId](const boost::system::error_code& ec, const std::string& blob) {
        if (ec) {
            std::cerr << "[readLoop] " << peerId << " error: " << ec.message() << '\n';
            return;
        }

        alyncoin::net::Frame f;
        if (f.ParseFromString(blob)) {
            std::cerr << "[readLoop] ✅ Parsed frame successfully from peer: " << peerId << '\n';
            dispatch(f, peerId);
        } else {
            std::cerr << "[readLoop] ❌ Failed to parse protobuf frame!" << '\n';
        }
    };
    transport->startReadBinaryLoop(cb);
    std::cout << "🔄 Binary read-loop armed for " << peerId << '\n';
}

void Network::dispatch(const alyncoin::net::Frame& f, const std::string& peer)
{
    std::string tag = f.has_block_broadcast() ? "BLOCK"
                    : f.has_snapshot_chunk() ? "SNAP_CHUNK"
                    : f.has_snapshot_end()   ? "SNAP_END"
                    : f.has_snapshot_req()   ? "SNAP_REQ"
                    : "OTHER";
    std::cerr << "[<<] Incoming Frame from " << peer << " Type=" << tag << "\n";
    switch (f.kind_case()) {
        case alyncoin::net::Frame::kBlockBroadcast: {
            Block blk = Block::fromProto(f.block_broadcast().block());
            std::cerr << "[dispatch] kBlockBroadcast frame detected. idx="
                      << blk.getIndex() << " hash=" << blk.getHash() << '\n';
            handleNewBlock(blk);
            break;
        }
        case alyncoin::net::Frame::kBlockBatch: {
            for (const auto& pb : f.block_batch().chain().blocks()) {
                Block blk = Block::fromProto(pb);
                std::cerr << "[dispatch] Batch block idx=" << blk.getIndex()
                          << " hash=" << blk.getHash() << '\n';
                handleNewBlock(blk);
            }
            break;
        }
        case alyncoin::net::Frame::kPing: {
            alyncoin::net::Frame out; out.mutable_pong();
            auto it = peerTransports.find(peer);
            if (it != peerTransports.end())
                sendFrame(it->second.tx, out);
            break;
        }
        case alyncoin::net::Frame::kHeightReq:
            sendHeight(peer);
            break;
        case alyncoin::net::Frame::kHeightRes:
            if (peerManager)
                peerManager->setPeerHeight(peer, f.height_res().height());
            break;
        case alyncoin::net::Frame::kSnapshotChunk:
            handleSnapshotChunk(peer, f.snapshot_chunk().data());
            break;
        case alyncoin::net::Frame::kSnapshotEnd:
            handleSnapshotEnd(peer);
            break;
        case alyncoin::net::Frame::kTailBlocks:
            handleTailBlocks(peer, f.tail_blocks().SerializeAsString());
            break;
        case alyncoin::net::Frame::kInv: {
            std::vector<std::string> hashes;
            for (const auto& h : f.inv().hashes()) hashes.push_back(h);
            std::vector<std::string> missing;
            Blockchain& bc = Blockchain::getInstance();
            for (const auto& h : hashes)
                if (!bc.hasBlockHash(h)) missing.push_back(h);
            if (!missing.empty()) {
                alyncoin::net::Frame req;
                auto* gd = req.mutable_get_data();
                for (const auto& h : missing) gd->add_hashes(h);
                auto it = peerTransports.find(peer);
                if (it != peerTransports.end())
                    sendFrame(it->second.tx, req);
            }
            break;
        }
        case alyncoin::net::Frame::kGetData: {
            std::vector<std::string> hashes;
            for (const auto& h : f.get_data().hashes()) hashes.push_back(h);
            handleGetData(peer, hashes);
            break;
        }
        case alyncoin::net::Frame::kTipHashReq:
            sendTipHash(peer);
            break;
        case alyncoin::net::Frame::kTipHashRes:
            if (peerManager)
                peerManager->recordTipHash(peer, f.tip_hash_res().hash());
            break;
        case alyncoin::net::Frame::kPeerListReq:
            sendPeerList(peer);
            break;
        case alyncoin::net::Frame::kPeerList: {
            for (const auto& p : f.peer_list().peers()) {
                size_t pos = p.find(':');
                if (pos == std::string::npos) continue;
                std::string ip = p.substr(0, pos);
                int port = std::stoi(p.substr(pos + 1));
                if ((ip == "127.0.0.1" || ip == "localhost") && port == this->port) continue;
                if (peerTransports.count(p)) continue;
                connectToNode(ip, port);
            }
            break;
        }
        case alyncoin::net::Frame::kRollupBlock: {
            RollupBlock rb = RollupBlock::deserialize(f.rollup_block().data());
            handleNewRollupBlock(rb);
            break;
        }
        case alyncoin::net::Frame::kAggProof: {
            const std::string& blob = f.agg_proof().data();
            if (blob.size() > sizeof(int) + 64) {
                int epoch = 0;
                std::memcpy(&epoch, blob.data(), sizeof(int));
                std::string root = blob.substr(sizeof(int), 64);
                std::vector<uint8_t> proof(blob.begin()+sizeof(int)+64, blob.end());
                {
                    std::lock_guard<std::mutex> lk(epochProofMutex);
                    receivedEpochProofs[epoch] = {root, proof};
                }
                std::cerr << "[agg_proof] stored proof for epoch " << epoch << '\n';
            }
            break;
        }
        case alyncoin::net::Frame::kTxBroadcast: {
            Transaction tx = Transaction::fromProto(f.tx_broadcast().tx());
            receiveTransaction(tx);
            break;
        }
        case alyncoin::net::Frame::kSnapshotReq:
            sendSnapshot(peerTransports[peer].tx, -1);
            break;
        case alyncoin::net::Frame::kTailReq:
            handleTailRequest(peer, f.tail_req().from_height());
            break;
        case alyncoin::net::Frame::kBlockchainSyncRequest:
            handleBlockchainSyncRequest(peer, f.blockchain_sync_request());
            break;
        default:
            std::cerr << "Unknown frame from " << peer << "\n";
    }
}
// Connect to Node

bool Network::connectToNode(const std::string& host, int port)
{
    if (peerTransports.size() >= MAX_PEERS) {
        std::cerr << "⚠️ [connectToNode] peer cap reached, skip " << host << ':' << port << '\n';
        return false;
    }

    const std::string peerKey = host + ':' + std::to_string(port);
    if (bannedPeers.count(peerKey)) {
        std::cerr << "⚠️ [connectToNode] " << peerKey << " is banned.\n";
        return false;
    }

    try {
        std::cout << "[PEER_CONNECT] → " << host << ':' << port << '\n';

        auto tx = std::make_shared<TcpTransport>(ioContext);
        if (!tx->connect(host, port)) {
            std::cerr << "❌ [connectToNode] Connection to " << host << ':' << port
                      << " failed." << '\n';
            return false;
        }

        {
            ScopedLockTracer _t("connectToNode");
            std::lock_guard<std::timed_mutex> g(peersMutex);
            if (peerTransports.count(peerKey)) {
                std::cout << "🔁 already connected to " << peerKey << '\n';
                return false;
            }
        }

        /* our handshake */
        alyncoin::net::Handshake hs;
        Blockchain& bc = Blockchain::getInstance();
        hs.set_version("1.0.0");
        hs.set_network_id("mainnet");
        hs.set_height(bc.getHeight());
        hs.set_listen_port(this->port);
        if (!bc.getChain().empty())
            hs.set_genesis_hash(bc.getChain().front().getHash());
        hs.add_capabilities("full");
        hs.add_capabilities("miner");
        hs.add_capabilities("agg_proof_v1");
        hs.add_capabilities("snapshot_v1");
        hs.add_capabilities("binary_v1");
        alyncoin::net::Frame out;
        out.mutable_handshake()->CopyFrom(hs);
        sendFrame(tx, out);

        /* read their handshake (2 s timeout) */
        std::string blob;
        if (auto tcp = std::dynamic_pointer_cast<TcpTransport>(tx)) {
            if (!tcp->waitReadable(2)) {
                std::cerr << "⚠️ [connectToNode] handshake timeout for "
                          << peerKey << '\n';
                std::lock_guard<std::timed_mutex> g(peersMutex);
                peerTransports.erase(peerKey);
                return false;
            }
            blob = tcp->readBinaryBlocking();
        } else {
            blob = tx->readBinaryBlocking();
        }

        bool theirAgg  = false;
        bool theirSnap = false;
        int  theirHeight = 0;
        alyncoin::net::Frame fr;
        if (blob.empty() || !fr.ParseFromString(blob) || !fr.has_handshake()) {
            std::cerr << "⚠️ [connectToNode] invalid handshake from " << peerKey << '\n';
            std::lock_guard<std::timed_mutex> g(peersMutex);
            peerTransports.erase(peerKey);
            return false;
        }
        const auto& rhs = fr.handshake();
        theirHeight = static_cast<int>(rhs.height());
        for (const auto& c : rhs.capabilities()) {
            if (c == "agg_proof_v1")  theirAgg  = true;
            if (c == "snapshot_v1")   theirSnap = true;
        }

        {
            ScopedLockTracer t("connectToNode/register");
            std::lock_guard<std::timed_mutex> lk(peersMutex);
            if (peerTransports.count(peerKey)) {
                std::cout << "🔁 already connected to " << peerKey << '\n';
                return false;
            }
            peerTransports[peerKey] = {tx, std::make_shared<PeerState>()};
            auto st = peerTransports[peerKey].state;
            st->supportsAggProof  = theirAgg;
            st->supportsSnapshot = theirSnap;
            if (peerManager) {
                peerManager->connectToPeer(peerKey);
                peerManager->setPeerHeight(peerKey, theirHeight);
            }
        }

        /* pick correct sync action now */
        const int localHeight = Blockchain::getInstance().getHeight();
        if (theirHeight > localHeight) {
            if      (theirSnap) requestSnapshotSync(peerKey);
            else if (theirAgg)  requestEpochHeaders(peerKey);
        }
        else if (theirHeight < localHeight && theirSnap)
            sendTailBlocks(tx, theirHeight);

        startBinaryReadLoop(peerKey, tx);
        sendInitialRequests(peerKey);

        autoSyncIfBehind();
        syncWithPeers();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "❌ [connectToNode] " << host << ':' << port
                  << " – " << e.what() << '\n';
        return false;
    }
}
//
void Network::handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex) {
    int localIndex = Blockchain::getInstance().getLatestBlock().getIndex();

    if (localIndex <= 0) { // Only genesis present
        std::cout << "⚠️ [Node] Only Genesis block found locally. Requesting snapshot from " << peerIP << "\n";
        sendForkRecoveryRequest(peerIP, "");
        return;
    }

    if (peerBlockIndex > localIndex) {
        std::cout << "📡 Peer " << peerIP
                  << " has longer chain. Requesting snapshot...\n";
        sendForkRecoveryRequest(peerIP, "");
    } else {
        std::cout << "✅ Local chain is up-to-date. No sync needed.\n";
    }
}

// ✅ **Fix Peer Saving & Loading**
void Network::loadPeers() {
    std::lock_guard<std::mutex> lock(fileIOMutex);

    std::ifstream file("peers.txt");
    if (!file.is_open()) {
        std::cerr << "⚠️ [loadPeers] peers.txt not found, skipping manual mesh restore.\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line.find(":") == std::string::npos) continue;

        std::string ip = line.substr(0, line.find(":"));
        int portVal = std::stoi(line.substr(line.find(":") + 1));
        std::string peerKey = ip + ":" + std::to_string(portVal);

        // Exclude self and local-only
        if (isSelfPeer(peerKey)) continue;
        if (ip == "127.0.0.1" || ip == "localhost") continue;

        if (connectToNode(ip, portVal)) {
            std::cout << "✅ Peer loaded & connected: " << line << "\n";
        }
    }
    file.close();
    std::cout << "✅ [loadPeers] Peer file mesh restore complete.\n";
}

//
void Network::scanForPeers() {
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    if (!peerTransports.empty()) {
        std::cout << "✅ [scanForPeers] Mesh established, skipping DNS scan.\n";
        return;
    }
    std::vector<std::string> potentialPeers = fetchPeersFromDNS("peers.alyncoin.com");
    std::cout << "🔍 [DNS] Scanning for AlynCoin nodes..." << std::endl;

    for (const auto& peer : potentialPeers) {
        std::string ip = peer.substr(0, peer.find(":"));
        int peerPort = std::stoi(peer.substr(peer.find(":") + 1));
        std::string peerKey = ip + ":" + std::to_string(peerPort);
        if (isSelfPeer(peerKey)) continue;
        if (ip == "127.0.0.1" || ip == "localhost") continue;
        connectToNode(ip, peerPort);
    }
    if (peerTransports.empty()) {
        std::cout << "⚠️ No active peers found from DNS. Will retry if needed.\n";
    }
}

// ✅ **Ensure Peers are Saved Correctly & Safely**
void Network::savePeers() {
    std::lock_guard<std::mutex> lock(fileIOMutex); // 🔒 File IO Mutex lock

    // Optional: Backup current peers.txt before overwrite
    if (fs::exists("peers.txt")) {
        try {
            fs::copy_file("peers.txt", "peers_backup.txt",
                        fs::copy_options::overwrite_existing);
            std::cout << "📋 Backup of peers.txt created (peers_backup.txt)\n";
        } catch (const std::exception &e) {
            std::cerr << "⚠️ Warning: Failed to backup peers.txt: " << e.what()
                    << "\n";
        }
    }

    std::ofstream file("peers.txt", std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "❌ Error: Unable to open peers.txt for saving!" << std::endl;
        return;
    }

    for (const auto &[peer, _] : peerTransports) {
        if (!peer.empty() && peer.find(":") != std::string::npos) {
            file << peer << std::endl;
        }
    }

    file.close();
    std::cout << "✅ Peer list saved successfully. Total peers: "
            << peerTransports.size() << std::endl;
}

// ✅ **Broadcast Latest Block Correctly (Base64 Encoded)**
void Network::sendLatestBlock(const std::string &peerIP) {
    Blockchain &blockchain = Blockchain::getInstance();
    if (blockchain.getChain().empty()) return;
    Block latestBlock = blockchain.getLatestBlock();
    sendBlockToPeer(peerIP, latestBlock);
}

void Network::sendInventory(const std::string& peer)
{
    Blockchain& bc = Blockchain::getInstance();
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    auto* inv = fr.mutable_inv();
    for (const auto& blk : bc.getChain())
        inv->add_hashes(blk.getHash());
    sendFrame(it->second.tx, fr);
}

// cleanup
void Network::cleanupPeers() {
    ScopedLockTracer tracer("cleanupPeers");
    std::vector<std::string> inactivePeers;
    {
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        for (const auto &peer : peerTransports) {
            try {
                if (!peer.second.tx || !peer.second.tx->isOpen()) {
                    std::cerr << "⚠️ Peer transport closed: " << peer.first << "\n";
                    inactivePeers.push_back(peer.first);
                    continue;
                }

                alyncoin::net::Frame f; f.mutable_ping();
                sendFrame(peer.second.tx, f);

                std::cout << "✅ Peer active: " << peer.first << "\n";
            } catch (const std::exception &e) {
                std::cerr << "⚠️ Exception checking peer " << peer.first << ": "
                          << e.what() << "\n";
                inactivePeers.push_back(peer.first);
            }
        }

        for (const auto &peer : inactivePeers) {
            peerTransports.erase(peer);
            std::cout << "🗑️ Removed inactive peer: " << peer << "\n";
        }
        if (!inactivePeers.empty()) {
            savePeers();
        }
    }

    if (!inactivePeers.empty()) {
        broadcastPeerList();
    }

}

// Add methods to handle rollup block synchronization
void Network::receiveRollupBlock(const std::string &data) {
  if (data.empty()) {
    std::cerr << "❌ [ERROR] Received empty rollup block data!\n";
    return;
  }

  // Deserialize rollup block and handle it
  RollupBlock rollupBlock = RollupBlock::deserialize(data);
  Blockchain::getInstance().addRollupBlock(rollupBlock);
  std::cout << "✅ Rollup block received and added to blockchain!\n";
}
//
void Network::handleNewRollupBlock(const RollupBlock &newRollupBlock) {
  if (Blockchain::getInstance().isRollupBlockValid(newRollupBlock)) {
    Blockchain::getInstance().addRollupBlock(newRollupBlock);
    std::lock_guard<std::mutex> lock(blockchainMutex);
    Blockchain::getInstance().saveRollupChain();
    std::cout << "[INFO] New rollup block added. Index: "
              << newRollupBlock.getIndex() << "\n";
  } else {
    std::cerr << "[ERROR] Received invalid rollup block. Index: "
              << newRollupBlock.getIndex() << "\n";
  }
}
//
bool Network::validateBlockSignatures(const Block &blk) {
    std::vector<unsigned char> msgBytes = blk.getSignatureMessage();

    std::vector<unsigned char> sigDil = blk.getDilithiumSignature();
    std::vector<unsigned char> sigFal = blk.getFalconSignature();

    std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(blk.getMinerAddress());
    std::vector<unsigned char> pubFal = Crypto::getPublicKeyFalcon(blk.getMinerAddress());

    if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
        std::cerr << "Invalid Dilithium signature for block: " << blk.getHash() << std::endl;
        return false;
    }

    if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
        std::cerr << "Invalid Falcon signature for block: " << blk.getHash() << std::endl;
        return false;
    }

    return true;
}
//
void Network::broadcastRollupBlock(const RollupBlock& rollup) {
    ScopedLockTracer tracer("broadcastRollupBlock");
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto& [peerID, entry] : peerTransports) {
        auto transport = entry.tx;
        if (transport && transport->isOpen()) {
            alyncoin::net::Frame fr;
            fr.mutable_rollup_block()->set_data(rollup.serialize());
            sendFrame(transport, fr);
        }
    }
}
//
void Network::broadcastEpochProof(int epochIdx, const std::string& rootHash,
                                  const std::vector<uint8_t>& proofBytes) {
    ScopedLockTracer tracer("broadcastEpochProof");
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto& [peerID, entry] : peerTransports) {
        auto transport = entry.tx;
        if (transport && transport->isOpen()) {
            alyncoin::net::Frame fr;
            std::string blob;
            blob.reserve(sizeof(int) + rootHash.size() + proofBytes.size());
            blob.append(reinterpret_cast<const char*>(&epochIdx), sizeof(int));
            blob.append(rootHash);
            blob.append(proofBytes.begin(), proofBytes.end());
            fr.mutable_agg_proof()->set_data(blob);
            sendFrame(transport, fr);
        }
    }
}
//
bool Network::peerSupportsAggProof(const std::string& peerId) const {
    auto it = peerTransports.find(peerId);
    if (it == peerTransports.end()) return false;
    auto st = it->second.state;
    return st ? st->supportsAggProof : false;
}
//
bool Network::peerSupportsSnapshot(const std::string& peerId) const {
    auto it = peerTransports.find(peerId);
    if (it == peerTransports.end()) return false;
    auto st = it->second.state;
    return st ? st->supportsSnapshot : false;
}
//
void Network::sendSnapshot(std::shared_ptr<Transport> transport, int upToHeight) {
    Blockchain& bc = Blockchain::getInstance();
    int height = upToHeight < 0 ? bc.getHeight() : upToHeight;
    std::vector<Block> blocks = bc.getChainUpTo(height);  // Implement as needed
    SnapshotProto snap;
    snap.set_height(height);
    snap.set_merkle_root(bc.getHeaderMerkleRoot());
    for (const auto& blk : blocks)
        *snap.add_blocks() = blk.toProtobuf();

    std::string raw;
    if (!snap.SerializeToString(&raw)) return;

    const size_t CHUNK_SIZE = MAX_SNAPSHOT_CHUNK_SIZE - 64; // keep under limit
    for (size_t off = 0; off < raw.size(); off += CHUNK_SIZE) {
        size_t len = std::min(CHUNK_SIZE, raw.size() - off);
        std::cerr << "[SNAPSHOT] ➡️ Sending chunk offset=" << off
                  << " len=" << len << "\n";
        alyncoin::net::Frame fr;
        fr.mutable_snapshot_chunk()->set_data(raw.substr(off, len));
        sendFrame(transport, fr);
    }
    std::cerr << "[SNAPSHOT] ➡️ Sending final snapshot_end\n";
    alyncoin::net::Frame end; end.mutable_snapshot_end();
    sendFrame(transport, end);
}
//

void Network::sendTailBlocks(std::shared_ptr<Transport> transport, int fromHeight) {
    Blockchain& bc = Blockchain::getInstance();
    std::vector<Block> tail;
    for (int i = fromHeight + 1; i <= bc.getHeight(); ++i) {
        tail.push_back(bc.getChain()[i]);
    }
    alyncoin::net::TailBlocks proto;
    for (const auto& blk : tail)
        *proto.add_blocks() = blk.toProtobuf();

    alyncoin::net::Frame fr;
    *fr.mutable_tail_blocks() = proto;
    sendFrame(transport, fr);
}
//
void Network::handleSnapshotChunk(const std::string& peer, const std::string& chunk) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.state) return;
    auto ps = it->second.state;
    std::cerr << "[SNAPSHOT] 🔸 Got chunk from " << peer
              << " size=" << chunk.size()
              << " (active=" << ps->snapshotActive << ")\n";
    std::cerr << "[SNAPSHOT]    first bytes: "
              << chunk.substr(0, std::min<size_t>(chunk.size(), 16)) << "\n";

    if (chunk.size() > MAX_SNAPSHOT_CHUNK_SIZE) {
        std::cerr << "⚠️ [SNAPSHOT] Oversized chunk, clearing buffer\n";
        ps->snapshotActive = false;
        ps->snapshotB64.clear();
        return;
    }
    ps->snapshotB64 += chunk;
    ps->snapshotActive = true;
}

//
void Network::handleTailRequest(const std::string& peer, int fromHeight) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    sendTailBlocks(it->second.tx, fromHeight);
}
void Network::handleSnapshotEnd(const std::string& peer) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.state) return;
    auto ps = it->second.state;
    std::cerr << "[SNAPSHOT] 🔴 SnapshotEnd from " << peer
              << ", total buffered=" << ps->snapshotB64.size() << " bytes\n";
    try {
        std::string raw = ps->snapshotB64;
        SnapshotProto snap;
        if (!snap.ParseFromString(raw)) throw std::runtime_error("Bad snapshot");

        Blockchain& chain = Blockchain::getInstance();

        // --- Validate snapshot height and integrity ---
        if (snap.height() < 1 || snap.blocks_size() == 0) throw std::runtime_error("Empty snapshot");
        if (static_cast<size_t>(snap.height()) != snap.blocks_size() - 1) {
            throw std::runtime_error("Snapshot height mismatch");
        }

        // --- Replace local chain up to snapshot height ---
        std::vector<Block> snapBlocks;
        for (const auto& pb : snap.blocks()) {
            snapBlocks.push_back(Block::fromProto(pb, false));
        }

        // [Optional] Validate Merkle root if provided
        if (!snap.merkle_root().empty()) {
            if (!snapBlocks.empty()) {
                std::string localRoot = snapBlocks.back().getMerkleRoot();
                if (localRoot != snap.merkle_root())
                    throw std::runtime_error("Merkle root mismatch in snapshot");
            }
        }

        // --- Fork choice: accept snapshot only if heavier ---
        int localHeight = chain.getHeight();
        uint64_t localWork = chain.computeCumulativeDifficulty(chain.getChain());
        uint64_t remoteWork = chain.computeCumulativeDifficulty(snapBlocks);

        if (snap.height() <= localHeight || remoteWork <= localWork) {
            std::cerr << "⚠️ [SNAPSHOT] Rejected snapshot from " << peer
                      << " (height " << snap.height() << ", work " << remoteWork
                      << ") localHeight=" << localHeight
                      << " localWork=" << localWork << "\n";
            ps->snapshotActive = false;
            ps->snapshotB64.clear();
            return;
        }

        // Actually apply: truncate and replace local chain
        chain.replaceChainUpTo(snapBlocks, snap.height());

        std::cout << "✅ [SNAPSHOT] Applied snapshot from peer " << peer << " at height " << snap.height() << "\n";
        ps->snapshotActive = false;
        ps->snapshotB64.clear();

        // Immediately request tail blocks for any missing blocks
        requestTailBlocks(peer, snap.height());

    } catch (const std::exception& ex) {
        std::cerr << "❌ [SNAPSHOT] Failed to apply snapshot from peer " << peer << ": " << ex.what() << "\n";
        ps->snapshotActive = false;
        ps->snapshotB64.clear();
    } catch (...) {
        std::cerr << "❌ [SNAPSHOT] Unknown error applying snapshot from peer " << peer << "\n";
        ps->snapshotActive = false;
        ps->snapshotB64.clear();
    }
}
//
void Network::handleTailBlocks(const std::string& peer, const std::string& data) {
    try {
        alyncoin::net::TailBlocks proto;
        if (!proto.ParseFromString(data)) throw std::runtime_error("Bad tailblocks");
        Blockchain& chain = Blockchain::getInstance();

        // Convert proto to vector of blocks
        std::vector<Block> blocks;
        blocks.reserve(proto.blocks_size());
        for (const auto& pb : proto.blocks()) {
            blocks.push_back(Block::fromProto(pb, false));
        }

        int tipIndex = chain.getHeight();
        const auto& localChain = chain.getChain();

        size_t pos = 0;
        while (pos < blocks.size() && blocks[pos].getIndex() <= tipIndex) {
            const Block& remote = blocks[pos];
            if (remote.getIndex() < chain.getBlockCount()) {
                const Block& local = localChain[remote.getIndex()];
                if (remote.getHash() != local.getHash()) {
                    throw std::runtime_error("Fork mismatch in tail blocks");
                }
            }
            ++pos;
        }

        if (pos == blocks.size()) return; // nothing new

        if (blocks[pos].getPreviousHash() != localChain.back().getHash()) {
            throw std::runtime_error("Tail does not connect to tip");
        }

        size_t appended = 0;
        for (; pos < blocks.size(); ++pos) {
            if (chain.addBlock(blocks[pos])) {
                ++appended;
            } else {
                throw std::runtime_error("Invalid block in tail set");
            }
        }

        std::cout << "✅ [TAIL_BLOCKS] Appended " << appended
                  << " of " << proto.blocks_size()
                  << " tail blocks from peer " << peer << "\n";
    } catch (const std::exception& ex) {
        std::cerr << "❌ [TAIL_BLOCKS] Failed to apply tail blocks from peer "
                  << peer << ": " << ex.what() << "\n";
    } catch (...) {
        std::cerr << "❌ [TAIL_BLOCKS] Unknown error applying tail blocks from peer "
                  << peer << "\n";
    }
}

//
void Network::requestSnapshotSync(const std::string& peer) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr; fr.mutable_snapshot_req();
    sendFrame(it->second.tx, fr);
}

void Network::requestTailBlocks(const std::string& peer, int fromHeight) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    fr.mutable_tail_req()->set_from_height(fromHeight);
    sendFrame(it->second.tx, fr);
}
//
void Network::sendForkRecoveryRequest(const std::string& peer, const std::string& tip) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx) return;
    alyncoin::net::Frame fr;
    if (!tip.empty())
        fr.mutable_snapshot_req()->set_until_hash(tip);
    else
        fr.mutable_snapshot_req();
    sendFrame(it->second.tx, fr);
}

void Network::handleBlockchainSyncRequest(const std::string& peer,
                                          const alyncoin::BlockchainSyncProto& request) {
    std::cout << "📡 [SYNC REQUEST] Received from " << peer
              << " type: " << request.request_type() << "\n";

    if (request.request_type() == "full_sync") {
        if (peerSupportsSnapshot(peer)) {
            requestSnapshotSync(peer);
        } else if (peerSupportsAggProof(peer)) {
            requestEpochHeaders(peer);
        } else {
            int peerHeight = peerManager ? peerManager->getPeerHeight(peer) : 0;
            auto it = peerTransports.find(peer);
            if (it != peerTransports.end() && it->second.tx)
                sendTailBlocks(it->second.tx, peerHeight);
        }
    } else if (request.request_type() == "latest_block") {
        sendLatestBlock(peer);
    } else {
        std::cerr << "⚠️ [SYNC REQUEST] Unknown request type: "
                  << request.request_type() << "\n";
    }
}
