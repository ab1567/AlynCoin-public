#include "generated/block_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include "network.h"
#include "blockchain.h"
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
#include <chrono>
#include <json/json.h>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include <cctype>
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

// ==== [Globals, Statics] ====
static std::unordered_map<std::string, std::vector<Block>> incomingChains;
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
struct InFlightData {
    std::string peer;
    std::string prefix;
    std::string base64;
    bool active{false};
};
static thread_local std::unordered_map<std::string, InFlightData> inflight;
static inline bool looksLikeBase64(const std::string& s) {
    if (s.size() < 16 || s.size() % 4 != 0) return false;
    for (unsigned char c : s) {
        if (!(std::isalnum(c) || c == '+' || c == '/' || c == '='))
            return false;
    }
    return true;
}
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
        std::cout << "✅ [UPnP] Port mapping added on port " << port << "\n";
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
        std::cout << "✅ [NAT-PMP] Port mapping added on port " << port << "\n";
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

        std::cout << "🌐 Network listener started on port: " << port << "\n";

        peerManager = new PeerManager(blacklistPtr, this);
        isRunning = true;
        listenerThread = std::thread(&Network::listenForConnections, this);

    } catch (const std::exception& ex) {
        std::cerr << "❌ [Network Exception] " << ex.what() << "\n";
    }
}

// ✅ Correct Destructor:

Network::~Network() {
    try {
        ioContext.stop();
        acceptor.close();
        if (listenerThread.joinable()) listenerThread.join();
        std::cout << "✅ Network instance cleaned up safely." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "❌ Error during Network destruction: " << e.what() << std::endl;
    }
}
//
 void Network::listenForConnections() {
     std::cout << "🌐 Listening for connections on port: " << port << std::endl;

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
void Network::broadcastMessage(const std::string &message) {
    ScopedLockTracer tracer("broadcastMessage");
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &peer : peerTransports) {
        auto transport = peer.second;
        if (transport && transport->isOpen()) {
            try {
                transport->queueWrite(message + "\n");
            } catch (const std::exception &e) {
                std::cerr << "⚠️ [broadcastMessage] Failed: " << e.what() << "\n";
            }
        }
    }
}

// ✅ **Getter function for syncing status**
bool Network::isSyncing() const { return syncing; }
// ✅ **Connect to a peer and send a message**
void Network::sendMessage(std::shared_ptr<Transport> transport, const std::string &message) {
    try {
        if (!transport || !transport->isOpen()) return;
        transport->queueWrite(message + "\n");
        std::cout << "📡 Sent message: " << message.substr(0, 200) << "...\n";
    } catch (const std::exception &e) {
        std::cerr << "⚠️ [WARNING] Failed sendMessage: " << e.what() << "\n";
    }
}

//
void Network::sendMessageToPeer(const std::string &peer, const std::string &message) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second || !it->second->isOpen()) {
        std::cerr << "❌ [sendMessageToPeer] Peer not found or transport closed: " << peer << "\n";
        return;
    }
    try {
        it->second->queueWrite(message + "\n");
        std::cout << "📡 Sent message to peer " << peer << ": " << message << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "❌ [sendMessageToPeer] Failed to send: " << e.what() << "\n";
    }
}

// ✅ **Broadcast a transaction to all peers**

void Network::broadcastTransaction(const Transaction &tx) {
    std::string txData = tx.serialize();
    for (const auto &peer : peerTransports) {
        auto transport = peer.second;
        if (transport && transport->isOpen()) {
            try {
                transport->queueWrite(txData + "\n");
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
    std::string txData = tx.serialize();
    for (const auto &peer : peerTransports) {
        if (peer.first == excludePeer) continue;
        auto transport = peer.second;
        if (transport && transport->isOpen()) {
            try {
                transport->queueWrite(txData + "\n");
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

    size_t myHeight = Blockchain::getInstance().getHeight();
    for (const auto &[peer, transport] : peerTransports) {
        if (peer.empty()) continue;

        int peerHeight = -1;
        if (peerManager) peerHeight = peerManager->getPeerHeight(peer);

        if (peerHeight == -1) {
            Json::Value j; j["type"] = "height_request";
            Json::StreamWriterBuilder b; b["indentation"] = "";
            sendData(peer, "ALYN|" + Json::writeString(b, j) + '\n');
            continue;
        }

        if (static_cast<size_t>(peerHeight) > myHeight) {
            std::cout << "📡 [DEBUG] Requesting blockchain sync from " << peer << "...\n";
            requestBlockchainSync(peer);
        } else if (static_cast<size_t>(peerHeight) < myHeight && transport && transport->isOpen()) {
            sendFullChain(transport);
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

    std::string majorityTipHash = peerManager->getMajorityTipHash();
    if (majorityTipHash.empty()) {
        std::cerr << "⚠️ [Smart Sync] No majority tip hash found. Skipping sync.\n";
        return;
    }

    int localHeight = blockchain->getHeight();
    int networkHeight = peerManager->getMedianNetworkHeight();

    if (networkHeight <= localHeight) {
        std::cout << "✅ [Smart Sync] Local blockchain is up-to-date. No sync needed.\n";
        return;
    }

    std::cout << "📡 [Smart Sync] Local height: " << localHeight
              << ", Network height: " << networkHeight
              << ". Sync needed.\n";

    // Find a healthy peer to sync from
    for (const auto &[peer, socket] : peerTransports) {
        if (peer.empty()) continue;
        requestBlockchainSync(peer);
        break;
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
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    if (peerTransports.empty()) return;

    Json::Value peerListJson;
    peerListJson["type"] = "peer_list";
    peerListJson["data"] = Json::arrayValue;

    for (const auto &[peerAddr, _] : peerTransports) {
        if (peerAddr.find(":") == std::string::npos) continue;
        peerListJson["data"].append(peerAddr);
    }

    Json::StreamWriterBuilder writer;
     writer["indentation"] = "";
    std::string peerListMessage = Json::writeString(writer, peerListJson);

    for (const auto &[peerAddr, _] : peerTransports) {
        sendData(peerAddr, "ALYN|" + peerListMessage);
        }

}

//
PeerManager* Network::getPeerManager() {
    return peerManager;
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
  for (const auto &[peerAddr, socket] : peerTransports) {
    sendData(peerAddr, "ALYN|{\"type\": \"request_peers\"}");
        }

  std::cout << "📡 Requesting peer list from all known peers..." << std::endl;
}
//
void Network::receiveFullChain(const std::string &senderIP, const std::string &data)
{
    std::cout << "[INFO] Receiving full blockchain from " << senderIP << std::endl;

    Blockchain &chain = Blockchain::getInstance();

    // 🔥 No base64 decode: data is already raw protobuf!
    const std::string &decodedData = data;

    std::cerr << "INCOMING RAW Proto from peer " << senderIP << ", size: " << decodedData.size()
              << ", first 8 bytes: "
              << (decodedData.size() >= 8
                    ? Crypto::toHex(std::vector<unsigned char>(decodedData.begin(), decodedData.begin() + 8))
                    : "[short]") << "\n";

    // 2) Parse into vector<Block>
    alyncoin::BlockchainProto protoChain;
    if (!protoChain.ParseFromString(decodedData)) {
        std::cerr << "❌ [ERROR] Failed to parse BlockchainProto from " << senderIP << "\n";
        return;
    }

    std::cout << "[DEBUG] Parsed BlockchainProto, block count = " << protoChain.blocks_size() << std::endl;

    if (protoChain.blocks_size() == 0) {
        std::cerr << "⚠️ [Network] Received empty blockchain.\n";
        return;
    }

    std::vector<Block> receivedBlocks;
    int failCount = 0;
    for (const auto& protoBlock : protoChain.blocks()) {
        try {
            Block blk = Block::fromProto(protoBlock, /*allowPartial=*/false);
            std::cout << "[SYNC] Block parsed: idx=" << blk.getIndex()
                      << " hash=" << blk.getHash().substr(0,12)
                      << " zkProof=" << blk.getZkProof().size()
                      << " falPK=" << blk.getPublicKeyFalcon().size()
                      << " dilPK=" << blk.getPublicKeyDilithium().size()
                      << " falSig=" << blk.getFalconSignature().size()
                      << " dilSig=" << blk.getDilithiumSignature().size()
                      << ", prev=" << blk.getPreviousHash()
                      << ", timestamp=" << blk.getTimestamp()
                      << ", merkleRoot=" << blk.getMerkleRoot()
                      << " txs=" << blk.getTransactions().size()
                      << std::endl;
            receivedBlocks.push_back(blk);
        } catch (const std::exception& e) {
            std::cerr << "⚠️ [Network] Failed to parse block: " << e.what() << "\n";
            failCount++;
        }
    }

    if (receivedBlocks.empty()) {
        std::cerr << "❌ [Network] No valid blocks parsed from received chain.\n";
        return;
    }
    if (failCount > 0) {
        std::cerr << "❌ [Network] Warning: " << failCount << " blocks could not be parsed.\n";
    }

    // 3) Validate Genesis Match
    if (!chain.getChain().empty() && chain.getChain()[0].getHash() != receivedBlocks[0].getHash()) {
        std::cerr << "⚠️ [Network] Genesis mismatch. Aborting sync.\n";
        std::cerr << "  Local genesis: " << chain.getChain()[0].getHash() << "\n";
        std::cerr << "  Remote genesis: " << receivedBlocks[0].getHash() << "\n";
        return;
    }

    std::cout << "🔍 Local chain length: " << chain.getChain().size()
              << ", Received: " << receivedBlocks.size() << "\n";

    // 4) Validate entire fork safety BEFORE touching chain
    bool forkSafe = chain.verifyForkSafety(receivedBlocks);
    if (!forkSafe) {
        std::cerr << "⚠️ [Network] Received fork failed safety check.\n";

        if (receivedBlocks.size() > chain.getChain().size()) {
            std::cerr << "✅ [Fallback Override] Longer chain with same genesis detected. Proceeding.\n";
            // continue to merge below
        } else {
            std::cerr << "❌ [Reject] Unsafe or shorter fork. Saved for analysis.\n";
            chain.saveForkView(receivedBlocks);
            return;
        }
    } else {
        std::cout << "✅ [Network] Fork safety passed.\n";
    }

    // 5) Merge using difficulty-aware fork logic
    std::cout << "[SYNC] Calling compareAndMergeChains: local=" << chain.getChain().size()
              << " remote=" << receivedBlocks.size() << std::endl;
    size_t prevHeight = chain.getChain().size();
    chain.compareAndMergeChains(receivedBlocks);
    size_t newHeight = chain.getChain().size();
    if (newHeight > prevHeight) {
        std::cout << "✅ [SYNC] Chain successfully merged! Local height now: " << newHeight << std::endl;
    } else {
        std::cerr << "❌ [SYNC] compareAndMergeChains() did not merge the incoming chain.\n";
    }
}

// Handle Peer (Transport version)
void Network::handlePeer(std::shared_ptr<Transport> transport)
{
    std::string realPeerId, claimedPeerId, handshakeLine;
    std::string claimedPort, claimedVersion, claimedNetwork, claimedIP;
    int remoteHeight = 0;  // <-- Declare here so it's in scope

    // Helper: what _we_ look like to the network
    const auto selfAddr = [this]() -> std::string {
        return this->publicPeerId.empty()
            ? "127.0.0.1:" + std::to_string(this->port)
            : this->publicPeerId;
    };

    // 1. Read & verify the handshake line
    try {
        handshakeLine = transport->readLineBlocking();
        static constexpr const char* protoPrefix = "ALYN|";
        if (handshakeLine.rfind(protoPrefix, 0) == 0)
            handshakeLine = handshakeLine.substr(std::strlen(protoPrefix));

        std::string handshakeBuf = handshakeLine;
        Json::Value root;
        Json::CharReaderBuilder rdr; std::string errs;
        auto parseHandshake = [&]() -> bool {
            std::istringstream iss(handshakeBuf);
            return Json::parseFromStream(rdr, iss, &root, &errs) &&
                   root.isMember("type") && root["type"].asString() == "handshake" &&
                   root.isMember("port") && root.isMember("version");
        };

        int readAttempts = 0;
        while (!parseHandshake()) {
            if (++readAttempts > 3 || handshakeBuf.size() > 4096)
                throw std::runtime_error("invalid handshake");
            std::string extra = transport->readLineBlocking();
            if (extra.rfind(protoPrefix, 0) == 0)
                extra = extra.substr(std::strlen(protoPrefix));
            handshakeBuf += extra;
        }

        handshakeLine = handshakeBuf;
        // who’s really at the other end of the TCP stream?
        const auto senderIP   = transport->getRemoteIP();
        const auto senderPort = transport->getRemotePort();
        realPeerId            = senderIP + ":" + std::to_string(senderPort);

        // what the peer *claims*
        claimedPort    = root["port"].asString();
        claimedVersion = root["version"].asString();
        claimedNetwork = root.get("network_id", "").asString();
        claimedIP      = root.get("ip", senderIP).asString();
        remoteHeight   = root.get("height", 0).asInt();
        // (1) normalize the port so it’s ALWAYS decimal
        try {
            const auto portDec = std::stoi(claimedPort, nullptr, 0);
            claimedPort = std::to_string(portDec);
        } catch (...) {
            throw std::runtime_error("bad port in handshake");
        }

        claimedPeerId = claimedIP + ":" + claimedPort;

        std::cout << "🤝 Handshake from   " << realPeerId
                  << " | claimed "        << claimedPeerId
                  << " | ver "            << claimedVersion
                  << " | net "            << claimedNetwork
                  << " | height "         << remoteHeight << '\n';

        if (claimedNetwork != "mainnet") {
            std::cerr << "⚠️  [handlePeer] Peer is on different network ("
                      << claimedNetwork << ") – ignored.\n";
            return;
        }

    } catch (const std::exception& ex) {
        // fallback: treat as unknown peer
        try {
            const auto ip   = transport->getRemoteIP();
            const auto port = transport->getRemotePort();
            realPeerId      = claimedPeerId = ip + ":" + std::to_string(port);

            std::cerr << "⚠️  [handlePeer] handshake failed ("
                      << ex.what() << "); registering fallback peer "
                      << realPeerId << '\n';

            if (realPeerId == selfAddr()) return; // ← self-connect

            {
                ScopedLockTracer t("handlePeer/fallback");
                std::lock_guard<std::timed_mutex> lk(peersMutex);
                peerTransports[realPeerId] = transport;
            }
            if (!handshakeLine.empty())
                handleIncomingData(realPeerId, handshakeLine, transport);
        }
        catch (...) {
            std::cerr << "❌ [handlePeer] totally failed to register peer\n";
        }
        return;    // finished with fallback path
    }

    // 2. refuse self-connects (claimed OR real)
    if (claimedPeerId == selfAddr() || realPeerId == selfAddr()) {
        std::cout << "🛑 Self-connect attempt ignored: " << claimedPeerId << '\n';
        return;
    }

    // 3. Add (or update) the peer socket
    {
        ScopedLockTracer t("handlePeer/register");
        std::lock_guard<std::timed_mutex> lk(peersMutex);

        auto it = peerTransports.find(claimedPeerId);
        if (it != peerTransports.end()) {
            it->second = transport; // refresh
        } else {
            peerTransports.emplace(claimedPeerId, transport);  // brand-new peer
            if (peerManager) peerManager->connectToPeer(claimedPeerId);
        }

        if (peerManager) {
            peerManager->setPeerHeight(claimedPeerId, remoteHeight);
        }
        // Add to pubsub mesh
        g_pubsub.addPeer(
            claimedPeerId,
            [transport](const std::string& line){
                if (transport && transport->isOpen()) transport->queueWrite(line + "\n");
            });

        std::cout << "✅ Registered peer transport: " << claimedPeerId
                  << "  (real endpoint " << realPeerId << ")\n";
    }

    // 4. share our current peer list with him
    broadcastPeerList();

    {
        Json::Value hs;
        hs["type"]        = "handshake";
        hs["port"]        = std::to_string(this->port);
        hs["version"]     = "1.0.0";
        hs["network_id"]  = "mainnet";
        hs["capabilities"] = Json::arrayValue;
        hs["capabilities"].append("full");
        hs["capabilities"].append("miner");
        hs["height"]      = Blockchain::getInstance().getHeight();

        Json::StreamWriterBuilder wr;  wr["indentation"] = "";
        std::string payload = Json::writeString(wr, hs);
        if (transport && transport->isOpen())
            transport->queueWrite(std::string("ALYN|") + payload + "\n");
    }

    // 5. send the initial sync requests

    transport->startReadLoop(
        [this, claimedPeerId](const std::string& line) {
            handleIncomingData(claimedPeerId, line, peerTransports[claimedPeerId]);
        }
    );

    sendInitialRequests(claimedPeerId);

    size_t myHeight = Blockchain::getInstance().getHeight();
    std::cerr << "[DEBUG] Local height=" << myHeight
              << ", peer " << claimedPeerId
              << " height=" << remoteHeight << "\n";
    if (remoteHeight > static_cast<int>(myHeight) && transport && transport->isOpen()) {
        sendData(transport, "ALYN|REQUEST_BLOCKCHAIN");
    } else if (remoteHeight < static_cast<int>(myHeight) && transport && transport->isOpen()) {
        sendFullChain(transport);
    }

    this->autoSyncIfBehind();
    this->syncWithPeers();
    // 6. if they gave us an external port – dial back
    try {
        const int theirPort = std::stoi(claimedPort, nullptr, 0);
        if ( theirPort>0 && theirPort!=this->port &&
            claimedPeerId!=selfAddr() && !peerTransports.count(claimedPeerId) )
        {
            std::cout << "🔁 Reverse-connecting to "
                    << claimedIP << ':' << theirPort << '\n';
            connectToPeer(claimedIP, theirPort);
        }
    } catch (...) {/* ignore bad port here */ }

    // 7. Start async read loop using transport's API
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
    Blockchain &blockchain = Blockchain::getInstance();
    size_t myHeight = blockchain.getHeight();
    std::string myTip = blockchain.getLatestBlockHash();

    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &[peerAddr, peerTransport] : peerTransports) {
        if (!peerTransport || !peerTransport->isOpen()) continue;

        std::cerr << "🌐 [autoSyncIfBehind] Requesting height from peer: " << peerAddr << std::endl;
        peerTransport->send("ALYN|{\"type\":\"height_request\"}\n");
        peerTransport->send("ALYN|{\"type\":\"tip_hash_request\"}\n");

        if (peerManager) {
            int ph = peerManager->getPeerHeight(peerAddr);
            std::string peerTip = peerManager->getPeerTipHash(peerAddr);

            if (ph > static_cast<int>(myHeight)) {
                peerTransport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
            } else if (ph == static_cast<int>(myHeight) && !peerTip.empty() && peerTip != myTip) {
                peerTransport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
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
void Network::periodicSync()
{
    ScopedLockTracer tracer("periodicSync");
    std::lock_guard<std::timed_mutex> lock(peersMutex);

    for (const auto &p : peerTransports)
    {
        const auto &peerId  = p.first;
        const auto &transport  = p.second;
        if (!transport || !transport->isOpen()) continue;

        Json::Value req;   req["type"] = "height_request";
        Json::StreamWriterBuilder b; b["indentation"] = "";
        std::string msg = "ALYN|" + Json::writeString(b, req) + "\n";
        transport->send(msg);

        std::cerr << "📡 [DEBUG] Height probe sent to " << peerId << '\n';
    }
}

//
std::vector<std::string> Network::getPeers() {
    std::vector<std::string> peerList;
    for (const auto &peer : peerTransports) {
        if (peer.second && peer.second->isOpen()) {
            peerList.push_back(peer.first); // Only include connected peers
        }
    }
    return peerList;
}

//
RollupBlock deserializeRollupBlock(const std::string &data) {
  return RollupBlock::deserialize(data);
}

std::vector<RollupBlock> deserializeRollupChain(const std::string &data) {
  std::vector<RollupBlock> chain;
  Json::Reader reader;
  Json::Value root;
  reader.parse(data, root);

  for (const auto &blk : root) {
    chain.push_back(RollupBlock::deserialize(blk.toStyledString()));
  }
  return chain;
}

// ✅ **Handle Incoming Data with Protobuf Validation**
void Network::handleIncomingData(const std::string& claimedPeerId,
                                 std::string data,
                                 std::shared_ptr<Transport> transport)
{
    std::cerr << "\n========== [handleIncomingData] ==========\n";
    std::cerr << "Peer: " << claimedPeerId << "\n";
    std::cerr << "Raw (first100): [" << data.substr(0,100) << "]\n";
    std::cerr << "Transport open? " << (transport && transport->isOpen() ? "YES" : "NO") << "\n";
    std::cerr << "==========================================\n";

    while (!data.empty() && (data.back() == '\n' || data.back() == '\r'))
        data.pop_back();

    static constexpr const char* protocolPrefix     = "ALYN|";
    static constexpr const char* fullChainPrefix    = "FULL_CHAIN|";
    static constexpr const char* rollupPrefix       = "ROLLUP_BLOCK|";
    static constexpr const char* blockBroadcastPrefix = "BLOCK_BROADCAST|";
    static constexpr const char* blockBatchPrefix   = "BLOCK_BATCH|";
    static constexpr size_t MAX_INFLIGHT_CHAIN_BYTES = 20 * 1024 * 1024; // 20MB

    // Strip protocol prefix (so all checks below work)
    if (data.rfind(protocolPrefix, 0) == 0)
        data = data.substr(std::strlen(protocolPrefix));

    static thread_local std::unordered_map<std::string, std::string> partialJsonBuf;

    // Accumulate JSON fragments if message was split or truncated
    if (!data.empty() && data.front() == '{' && data.back() != '}') {
        partialJsonBuf[claimedPeerId] += data;
        if (partialJsonBuf[claimedPeerId].size() > 8192)
            partialJsonBuf.erase(claimedPeerId);
        return;
    }
    if (partialJsonBuf.count(claimedPeerId)) {
        data = partialJsonBuf[claimedPeerId] + data;
        if (!data.empty() && data.front() == '{' && data.back() == '}') {
            partialJsonBuf.erase(claimedPeerId);
        } else {
            partialJsonBuf[claimedPeerId] = data;
            if (partialJsonBuf[claimedPeerId].size() > 8192)
                partialJsonBuf.erase(claimedPeerId);
            return;
        }
    }

    // === FULL_CHAIN inflight buffer for peer sync ===
    static std::unordered_map<std::string, std::string> inflightFullChainBase64;
    static std::unordered_map<std::string, std::string> legacyChainBuf;

    // --- Robust FULL_CHAIN handler: single-shot or multi-chunk
    if (data.rfind(fullChainPrefix, 0) == 0) {
        const std::string b64 = data.substr(strlen(fullChainPrefix));
        // If this is a *large* message or (likely) single-shot, decode and process now!
        if (b64.size() > 10000 || b64.find("BLOCKCHAIN_END") != std::string::npos) {
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockchainProto protoChain;
                if (!protoChain.ParseFromString(raw)) {
                    std::cerr << "[handleIncomingData] ❌ Invalid FULL_CHAIN protobuf (single shot)\n";
                } else {
                    std::vector<Block> blocks;
                    for (const auto& pb : protoChain.blocks()) {
                        try { blocks.push_back(Block::fromProto(pb, false)); }
                        catch (...) { std::cerr << "⚠️ Skipped malformed block\n"; }
                    }
                    Blockchain& chain = Blockchain::getInstance();
                    size_t before = chain.getChain().size();
                    chain.compareAndMergeChains(blocks);
                    size_t after = chain.getChain().size();
                    if (peerManager)
                        peerManager->setPeerHeight(claimedPeerId, static_cast<int>(blocks.size()) - 1);
                    std::cerr << "[handleIncomingData] ✅ Synced full chain from peer (single shot). "
                              << before << " -> " << after << " blocks\n";
                }
            } catch (...) {
                std::cerr << "[handleIncomingData] ❌ Base64 decode failed for FULL_CHAIN (single shot)\n";
            }
            return;
        } else {
            // Otherwise, treat as multi-chunk and buffer
            inflightFullChainBase64[claimedPeerId] = b64;
            if (inflightFullChainBase64[claimedPeerId].size() > MAX_INFLIGHT_CHAIN_BYTES) {
                std::cerr << "[handleIncomingData] ⚠️ FULL_CHAIN buffer exceeded limit from "
                          << claimedPeerId << " ("
                          << inflightFullChainBase64[claimedPeerId].size()
                          << " bytes)\n";
                inflightFullChainBase64.erase(claimedPeerId);
            }
	    return;
        }
    }
    if (inflightFullChainBase64.count(claimedPeerId)) {
        if (data == "BLOCKCHAIN_END") {
            // Finalize and process the buffered base64
            std::string& b64 = inflightFullChainBase64[claimedPeerId];
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockchainProto protoChain;
                if (!protoChain.ParseFromString(raw)) {
                    std::cerr << "[handleIncomingData] ❌ Invalid FULL_CHAIN protobuf (multi-chunk)\n";
                } else {
                    std::vector<Block> blocks;
                    for (const auto& pb : protoChain.blocks()) {
                        try { blocks.push_back(Block::fromProto(pb, false)); }
                        catch (...) { std::cerr << "⚠️ Skipped malformed block\n"; }
                    }
                    Blockchain& chain = Blockchain::getInstance();
                    chain.compareAndMergeChains(blocks);
                    if (peerManager)
                        peerManager->setPeerHeight(claimedPeerId, static_cast<int>(blocks.size()) - 1);
                    std::cerr << "[handleIncomingData] ✅ Synced full chain from peer (multi-chunk)\n";
                }
            } catch (...) {
                std::cerr << "[handleIncomingData] ❌ Base64 decode failed for FULL_CHAIN (multi-chunk)\n";
            }
            inflightFullChainBase64.erase(claimedPeerId);
            return;
        } else {
            // Intermediate chunk: append
            inflightFullChainBase64[claimedPeerId] += data;
            if (inflightFullChainBase64[claimedPeerId].size() > MAX_INFLIGHT_CHAIN_BYTES) {
                std::cerr << "[handleIncomingData] ⚠️ FULL_CHAIN buffer exceeded limit from "
                          << claimedPeerId << " ("
                          << inflightFullChainBase64[claimedPeerId].size()
                          << " bytes)\n";
                inflightFullChainBase64.erase(claimedPeerId);
                return;
            }
            return;
        }
    }

    // --- Legacy multi-line FULL_CHAIN handler ---
    if (data == "BLOCKCHAIN_END" && legacyChainBuf.count(claimedPeerId)) {
        try {
            std::string raw = Crypto::base64Decode(legacyChainBuf[claimedPeerId], false);
            alyncoin::BlockchainProto protoChain;
            if (protoChain.ParseFromString(raw)) {
                std::vector<Block> blocks;
                for (const auto& pb : protoChain.blocks()) {
                    try { blocks.push_back(Block::fromProto(pb, false)); }
                    catch (...) { std::cerr << "⚠️ Skipped malformed block\n"; }
                }
                Blockchain& chain = Blockchain::getInstance();
                chain.compareAndMergeChains(blocks);
                if (peerManager)
                    peerManager->setPeerHeight(claimedPeerId, static_cast<int>(blocks.size()) - 1);
                std::cerr << "[handleIncomingData] ✅ Synced full chain from peer (legacy base64)\n";
            }
        } catch (...) {
            std::cerr << "[handleIncomingData] ❌ Legacy base64 decode failed\n";
        }
        legacyChainBuf.erase(claimedPeerId);
        return;
    }

    if (legacyChainBuf.count(claimedPeerId) && data.rfind(protocolPrefix, 0) == 0) {
        try {
            std::string raw = Crypto::base64Decode(legacyChainBuf[claimedPeerId], false);
            alyncoin::BlockchainProto protoChain;
            if (protoChain.ParseFromString(raw)) {
                std::vector<Block> blocks;
                for (const auto& pb : protoChain.blocks()) {
                    try { blocks.push_back(Block::fromProto(pb, false)); }
                    catch (...) { std::cerr << "⚠️ Skipped malformed block\n"; }
                }
                Blockchain& chain = Blockchain::getInstance();
                chain.compareAndMergeChains(blocks);
                if (peerManager)
                    peerManager->setPeerHeight(claimedPeerId, static_cast<int>(blocks.size()) - 1);
                std::cerr << "[handleIncomingData] ✅ Synced full chain from peer (legacy base64)\n";
            }
        } catch (...) {
            std::cerr << "[handleIncomingData] ❌ Legacy base64 decode failed\n";
        }
        legacyChainBuf.erase(claimedPeerId);
        // fall through to process current message normally
    }

    // ---- Existing protocol logic ----

    static thread_local std::unordered_map<std::string, InFlightData> inflight;

    if (data.rfind(blockBroadcastPrefix, 0) == 0) {
        InFlightData& infl = inflight[claimedPeerId];
        infl.peer   = claimedPeerId;
        infl.prefix = blockBroadcastPrefix;
        infl.base64 = data.substr(strlen(blockBroadcastPrefix));
        infl.active = true;
        try {
            std::string raw = Crypto::base64Decode(infl.base64, false);
            alyncoin::BlockProto proto;
            if (proto.ParseFromString(raw) && proto.hash().size() == 64 &&
                !proto.previous_hash().empty())
            {
                handleBase64Proto(claimedPeerId, blockBroadcastPrefix,
                                  infl.base64, transport);
                infl.active = false;
            }
        } catch (...) {
            /* wait for more lines */
        }
        return;
    }
    if (data.rfind(blockBatchPrefix, 0) == 0) {
        InFlightData& infl = inflight[claimedPeerId];
        infl.peer   = claimedPeerId;
        infl.prefix = blockBatchPrefix;
        infl.base64 = data.substr(strlen(blockBatchPrefix));
        infl.active = true;
        try {
            std::string raw = Crypto::base64Decode(infl.base64, false);
            alyncoin::BlockchainProto proto;
            if (proto.ParseFromString(raw) && proto.blocks_size() > 0) {
                handleBase64Proto(claimedPeerId, blockBatchPrefix,
                                  infl.base64, transport);
                infl.active = false;
            }
        } catch (...) {
            /* wait for more lines */
        }
        return;
    }

    auto inflIt = inflight.find(claimedPeerId);
    if (inflIt != inflight.end() && looksLikeBase64(data)) {
        inflIt->second.base64 += data;
        try {
            std::string raw = Crypto::base64Decode(inflIt->second.base64, false);
            if (inflIt->second.prefix == blockBroadcastPrefix) {
                alyncoin::BlockProto proto;
                if (proto.ParseFromString(raw) && proto.hash().size() == 64 &&
                    !proto.previous_hash().empty())
                {
                    handleBase64Proto(claimedPeerId, blockBroadcastPrefix,
                                      inflIt->second.base64, transport);
                    inflIt->second.active = false;
                }
            } else if (inflIt->second.prefix == blockBatchPrefix) {
                alyncoin::BlockchainProto proto;
                if (proto.ParseFromString(raw) && proto.blocks_size() > 0) {
                    handleBase64Proto(claimedPeerId, blockBatchPrefix,
                                      inflIt->second.base64, transport);
                    inflIt->second.active = false;
                }
            }
            if (inflIt->second.active && inflIt->second.base64.size() > 5000)
                inflIt->second.active = false;
        } catch (...) {
            if (inflIt->second.base64.size() > 5000) inflIt->second.active = false;
        }
        if (inflIt->second.active)
            return; // Wait for more fragments
    }

    // === Rollup ===
    if (data.rfind(rollupPrefix, 0) == 0) {
        try {
            RollupBlock rb = RollupBlock::deserialize(data.substr(std::strlen(rollupPrefix)));
            handleNewRollupBlock(rb);
        } catch (...) {
            std::cerr << "⚠️ Rollup block failed to deserialize\n";
        }
        return;
    }

    // === Ping/Pong ===
    if (data == "PING") {
        if (transport && transport->isOpen())
            transport->queueWrite("ALYN|PONG\n");
        return;
    }
    if (data == "PONG")
        return;

    if (data == "BLOCKCHAIN_END") {
        Blockchain& chain = Blockchain::getInstance();
        size_t myHeight = chain.getHeight();
        int peerHeight = -1;
        if (peerManager) {
            peerHeight = peerManager->getPeerHeight(claimedPeerId);
        }
        if (peerHeight > static_cast<int>(myHeight) && transport && transport->isOpen()) {
            transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
        } else if (peerHeight < static_cast<int>(myHeight) && transport && transport->isOpen()) {
            sendFullChain(transport);
        }
        return;
    }

    // === Blockchain Request ===
    if (data == "REQUEST_BLOCKCHAIN") {
        if (transport && transport->isOpen())
            sendFullChain(transport);
        return;
    }

    // === JSON Messages ===
    if (!data.empty() && data.front() == '{' && data.back() == '}') {
        try {
            Json::Value root;
            std::istringstream s(data);
            Json::CharReaderBuilder rb;
            std::string errs;
            if (!Json::parseFromStream(rb, s, &root, &errs)) return;

            auto& chain = Blockchain::getInstance();
            std::string type = root["type"].asString();

            if (type == "handshake" && peerManager) {
                int h = root.get("height", 0).asInt();
                peerManager->setPeerHeight(claimedPeerId, h);

                if (h > (int)chain.getHeight() && transport && transport->isOpen())
                    transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
                else if (h < (int)chain.getHeight() && transport && transport->isOpen())
                    sendFullChain(transport);
                return;
            }

            if (type == "height_response") {
                int h = root["data"].asInt();
                if (peerManager) peerManager->setPeerHeight(claimedPeerId, h);
                if (h > (int)chain.getHeight() && transport && transport->isOpen())
                    transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
                return;
            }

            if (type == "tip_hash_response" && peerManager) {
                std::string tip = root["data"].asString();
                peerManager->recordTipHash(claimedPeerId, tip);

                int ph = peerManager->getPeerHeight(claimedPeerId);
                if (ph == static_cast<int>(chain.getHeight()) &&
                    !tip.empty() && tip != chain.getLatestBlockHash() &&
                    transport && transport->isOpen()) {
                    transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
                }
                return;
            }

            if (type == "peer_list") {
                for (const auto& p : root["data"]) {
                    std::string str = p.asString();
                    auto pos = str.find(':');
                    if (pos == std::string::npos) continue;
                    std::string ip = str.substr(0, pos);
                    int port = std::stoi(str.substr(pos + 1));
                    if ((ip == "127.0.0.1" || ip == "localhost") && port == this->port) continue;
                    if (peerTransports.count(str)) continue;
                    connectToNode(ip, port);
                }
                return;
            }

            if (type == "request_peers") {
                Json::Value out;
                out["type"] = "peer_list";
                out["data"] = Json::arrayValue;
                {
                    std::lock_guard<std::timed_mutex> lk(peersMutex);
                    for (const auto& kv : peerTransports)
                        out["data"].append(kv.first);
                }
                if (transport && transport->isOpen())
                    transport->queueWrite("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
                return;
            }

            if (type == "height_request") {
                Json::Value out;
                out["type"] = "height_response";
                out["data"] = chain.getHeight();
                if (transport && transport->isOpen())
                    transport->queueWrite("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
                return;
            }

            if (type == "tip_hash_request") {
                Json::Value out;
                out["type"] = "tip_hash_response";
                out["data"] = chain.getLatestBlockHash();
                if (transport && transport->isOpen())
                    transport->queueWrite("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
                return;
            }

            if (type == "inv") {
                std::vector<std::string> hashes;
                for (const auto& h : root["hashes"]) hashes.push_back(h.asString());
                std::vector<std::string> missing;
                for (const auto& h : hashes)
                    if (!chain.hasBlockHash(h)) missing.push_back(h);
                if (!missing.empty()) {
                    Json::Value req; req["type"] = "getdata"; req["hashes"] = Json::arrayValue;
                    for (const auto& h : missing) req["hashes"].append(h);
                    if (transport && transport->isOpen())
                        transport->queueWrite("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), req) + "\n");
                }
                return;
            }

            if (type == "getdata") {
                std::vector<std::string> hashes;
                for (const auto& h : root["hashes"]) hashes.push_back(h.asString());
                handleGetData(claimedPeerId, hashes);
                return;
            }

            if (root.isMember("txid")) {
                Transaction tx = Transaction::fromJSON(root);
                std::string hash = tx.getHash();

                {
                    std::lock_guard<std::mutex> lk(seenTxMutex);
                    if (seenTxHashes.count(hash)) return;
                    seenTxHashes.insert(hash);
                }

                if (tx.isValid(tx.getSenderPublicKeyDilithium(),
                               tx.getSenderPublicKeyFalcon()))
                {
                    chain.addTransaction(tx);
                    chain.savePendingTransactionsToDB();
                    broadcastTransactionToAllExcept(tx, claimedPeerId);
                }
                return;
            }

        } catch (...) {
            std::cerr << "⚠️ Malformed JSON from peer\n";
        }
        return;
    }

 // === Fallback: accumulate legacy base64 chunks (older peers may split messages)
    try {
        if (!data.empty() && data.find('|') == std::string::npos &&
            data.size() > 50 && looksLikeBase64(data)) {
            std::string& buf = legacyChainBuf[claimedPeerId];
            buf += data;
            std::cerr << "[handleIncomingData] 📡 Legacy base64 chunk received (" << data.size()
                      << " chars, total " << buf.size() << ")\n";
            try {
                std::string raw = Crypto::base64Decode(buf, false);
                alyncoin::BlockchainProto protoChain;
                if (protoChain.ParseFromString(raw)) {
                    std::vector<Block> blocks;
                    for (const auto& pb : protoChain.blocks()) {
                        try { blocks.push_back(Block::fromProto(pb, false)); }
                        catch (...) { std::cerr << "⚠️ Skipped malformed block\n"; }
                    }
                    Blockchain& chain = Blockchain::getInstance();
                    chain.compareAndMergeChains(blocks);
                    if (peerManager)
                        peerManager->setPeerHeight(claimedPeerId, static_cast<int>(blocks.size()) - 1);
                    std::cerr << "[handleIncomingData] ✅ Synced full chain from peer (legacy base64)\n";
                    legacyChainBuf.erase(claimedPeerId);
                    return;
                }
            } catch (...) {
                // keep accumulating until parse succeeds
            }
            if (buf.size() > 300000) legacyChainBuf.erase(claimedPeerId);
            return;
        }
    } catch (...) {
        std::cerr << "[handleIncomingData] ❌ Legacy base64 handling failed\n";
    }

    // === Fallback base64-encoded block ===
    try {
        if (!data.empty() && data.size() > 50 && data.find('|') == std::string::npos &&
            looksLikeBase64(data)) {
            std::string decoded = Crypto::base64Decode(data, false);
            alyncoin::BlockProto proto;
            if (proto.ParseFromString(decoded)) {
                Block blk = Block::fromProto(proto, false);
                std::cerr << "[handleIncomingData] 📦 Fallback block idx=" << blk.getIndex()
                          << ", hash=" << blk.getHash().substr(0, 12) << "...\n";

                Blockchain& bc = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
                if (bc.addBlock(blk)) {
                    std::cerr << "✅ Fallback block added\n";
                } else {
                    std::cerr << "⚠️ Fallback block rejected\n";
                }
                return;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ Exception in fallback block parse: " << e.what() << "\n";
    }

    std::cerr << "⚠️ [handleIncomingData] Unknown or unhandled message from " << claimedPeerId
              << ": [" << data.substr(0, 100) << "]\n";
}

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
    std::string b64 = Crypto::base64Encode(raw, false);

    // Frame: "ALYN|BLOCK_BROADCAST|" + [base64] + "\n"
    const std::string message = "ALYN|BLOCK_BROADCAST|" + b64 + "\n";

    std::unordered_map<std::string, std::shared_ptr<Transport>> peersCopy;
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
    for (auto& [peerId, transport] : peersCopy)
    {
        if (isSelfPeer(peerId) || !transport || !transport->isOpen()) continue;
        if (!seen.insert(transport).second) continue;

        try {
            transport->queueWrite(message);
            std::cout << "✅ [broadcastBlock] Block " << block.getIndex() << " sent (base64 protobuf) to " << peerId << '\n';
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
    std::string b64 = Crypto::base64Encode(raw, false);
    const std::string msg = "ALYN|BLOCK_BATCH|" + b64 + "\n";
    for (auto& [peerId, transport] : peerTransports) {
        if (isSelfPeer(peerId) || !transport || !transport->isOpen()) continue;
        transport->queueWrite(msg);
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
    std::string b64 = Crypto::base64Encode(raw, false);
    sendData(peer, "ALYN|BLOCK_BROADCAST|" + b64);
}

//
bool Network::isSelfPeer(const std::string& peer) const {
    std::string selfAddr = getSelfAddressAndPort();
    return
        peer == selfAddr ||
        peer == "127.0.0.1:" + std::to_string(this->port) ||
        peer == "localhost:" + std::to_string(this->port);
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
void Network::handleBase64Proto(const std::string &peer, const std::string &prefix,
                                const std::string &b64, std::shared_ptr<Transport> transport)
{
    // Lambda for handling an incoming block (from BLOCK_BROADCAST)
    auto processBlock = [&](const Block& blk, const std::string& fromPeer)
    {
        Blockchain& chain = Blockchain::getInstance();
        auto& buf = incomingChains[fromPeer];

        {
            std::lock_guard<std::mutex> lk(seenBlockMutex);
            if (seenBlockHashes.count(blk.getHash())) {
                std::cerr << "[handleBase64Proto] Duplicate block "
                          << blk.getHash().substr(0,12) << " ignored\n";
                return;
            }
            seenBlockHashes.insert(blk.getHash());
        }

        // Prevent double-buffer of same block
        if (std::any_of(buf.begin(), buf.end(), [&](const Block& b){ return b.getHash()==blk.getHash(); })) {
            std::cerr << "[handleBase64Proto] Duplicate BLOCK_BROADCAST ignored (hash already buffered)\n";
            return;
        }

        // Direct tip-append if the parent matches
        if (blk.getPreviousHash() == chain.getLatestBlockHash()) {
            std::cerr << "[handleBase64Proto] ✨ Directly appending live block (idx=" << blk.getIndex() << ")\n";
            if (chain.addBlock(blk)) {
                buf.clear();
                // Propagate block to all peers except the sender
                for (auto& [peerId, peerTransport] : peerTransports) {
                    if (peerId == fromPeer) continue;
                    if (peerTransport && peerTransport->isOpen()) {
                        alyncoin::BlockProto proto = blk.toProtobuf();
                        std::string raw;
                        if (proto.SerializeToString(&raw)) {
                            std::string b64 = Crypto::base64Encode(raw, false);
                            peerTransport->queueWrite("ALYN|BLOCK_BROADCAST|" + b64 + "\n");
                        }
                    }
                }
                // Try to flush orphan buffer
                bool flushed = true;
                while (flushed) {
                    flushed = false;
                    for (auto it = buf.begin(); it != buf.end(); ) {
                        if (it->getPreviousHash() == chain.getLatestBlockHash()) {
                            if (chain.addBlock(*it)) {
                                for (auto& [peerId2, peerTransport2] : peerTransports) {
                                    if (peerId2 == fromPeer) continue;
                                    if (peerTransport2 && peerTransport2->isOpen()) {
                                        alyncoin::BlockProto proto2 = it->toProtobuf();
                                        std::string raw2;
                                        if (proto2.SerializeToString(&raw2)) {
                                            std::string b64_2 = Crypto::base64Encode(raw2, false);
                                            peerTransport2->queueWrite("ALYN|BLOCK_BROADCAST|" + b64_2 + "\n");
                                        }
                                    }
                                }
                                it = buf.erase(it);
                                flushed = true;
                            } else {
                                ++it;
                            }
                        } else {
                            ++it;
                        }
                    }
                }
            }
            return;
        }

        // Buffer as orphan if missing parent
        if (blk.getIndex() > 0 && !chain.hasBlockHash(blk.getPreviousHash())) {
            std::cerr << "⚠️  [handleBase64Proto] [Orphan Block] Parent missing for block idx="
                      << blk.getIndex() << '\n';
            if (transport && transport->isOpen())
                transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
            buf.push_back(blk);
            return;
        }

        // Potential fork: parent exists but isn't the current tip
        if (blk.getIndex() > 0 && chain.hasBlockHash(blk.getPreviousHash()) &&
            blk.getPreviousHash() != chain.getLatestBlockHash()) {
            std::cerr << "🔀 [handleBase64Proto] Fork block at idx=" << blk.getIndex()
                      << ", requesting full chain\n";
            if (transport && transport->isOpen())
                transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
            buf.push_back(blk);
            return;
        }
        // Otherwise, just buffer
        buf.push_back(blk);
        std::cerr << "[handleBase64Proto] Buffered block idx=" << blk.getIndex()
                  << " for peer " << fromPeer
                  << ". Current buffer size: " << buf.size() << '\n';
    };

    // Now decode and route
    try {
        if (prefix == "BLOCK_BROADCAST|") {
            Block blk;
            bool ok = false;
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockProto proto;
                bool parseOk = proto.ParseFromString(raw);
                if (parseOk && proto.hash().size() == 64 && !proto.previous_hash().empty()) {
                    blk = Block::fromProto(proto, /*strict=*/true);
                    ok = true;
                }
            } catch (...) {
                std::cerr << "[handleBase64Proto] Exception decoding base64 block!\n";
            }
            if (ok) processBlock(blk, peer);
            return;
        } else if (prefix == "BLOCK_BATCH|") {
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockchainProto protoChain;
                if (protoChain.ParseFromString(raw)) {
                    for (const auto& pb : protoChain.blocks()) {
                        try {
                            Block blk = Block::fromProto(pb, /*strict=*/true);
                            processBlock(blk, peer);
                        } catch (...) {
                            std::cerr << "⚠️ [handleBase64Proto] Skipped malformed block in batch\n";
                        }
                    }
                } else {
                    std::cerr << "[handleBase64Proto] Failed to parse incoming block batch (base64)\n";
                }
            } catch (...) {
                std::cerr << "[handleBase64Proto] Exception decoding base64 block batch!\n";
            }
            return;
        } else if (prefix == "FULL_CHAIN|") {
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockchainProto protoChain;
                if (protoChain.ParseFromString(raw)) {
                    std::vector<Block> receivedBlocks;
                    for (const auto& protoBlock : protoChain.blocks()) {
                        try {
                            // be lenient when syncing from peers
                            receivedBlocks.push_back(Block::fromProto(protoBlock, /*allowPartial=*/true));
                        } catch (const std::exception& e) {
                            std::cerr << "⚠️ [handleBase64Proto] Skipped malformed block: "
                                      << e.what() << "\n";
                        } catch (...) {
                            std::cerr << "⚠️ [handleBase64Proto] Skipped malformed block (unknown error)\n";
                        }
                    }
                    Blockchain& chain = Blockchain::getInstance();
                    size_t before = chain.getChain().size();
                    chain.compareAndMergeChains(receivedBlocks);
                    size_t after = chain.getChain().size();
                    if (peerManager)
                        peerManager->setPeerHeight(peer, static_cast<int>(receivedBlocks.size()) - 1);
                    std::cerr << "[handleBase64Proto] Chain merge complete (base64 streaming). "
                              << before << " -> " << after << " blocks\n";
                } else {
                    std::cerr << "[handleBase64Proto] Failed to parse incoming BlockchainProto (base64)\n";
                }
            } catch (...) {
                std::cerr << "[handleBase64Proto] Exception decoding base64 full chain!\n";
            }
            return;
        }
    } catch (...) {
        std::cerr << "[handleBase64Proto] Unknown exception\n";
    }
}

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
bool Network::validatePeer(const std::string &peer) {
  if (peer.find(":") == std::string::npos) { // ✅ Correct format check
    return false;
  }

  if (peerTransports.find(peer) != peerTransports.end()) {
    return false;
  }

  std::string handshakeMessage = "PEER_HANDSHAKE";
  sendData(peer, handshakeMessage);

  std::cout << "✅ Peer validated: " << peer << std::endl;
  return true;
}

// Handle new block
void Network::handleNewBlock(const Block &newBlock) {
    Blockchain &blockchain = Blockchain::getInstance();
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
                sendData(peer.first, "ALYN|REQUEST_BLOCKCHAIN");
            }
            return;
        }
    }

    // 3) Index ordering
    if (newBlock.getIndex() < expectedIndex) {
        std::cerr << "⚠️ [Node] Ignoring duplicate or old block (idx=" << newBlock.getIndex() << ").\n";
        return;
    }
    if (newBlock.getIndex() > expectedIndex) {
        std::cerr << "⚠️ [Node] Received future block. Buffering (idx=" << newBlock.getIndex() << ").\n";
        futureBlockBuffer[newBlock.getIndex()] = newBlock;

        if (newBlock.getIndex() > expectedIndex + 5) {
            for (const auto& peer : peerTransports) {
                sendData(peer.first, "ALYN|REQUEST_BLOCKCHAIN");
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

        transport->queueWrite(finalMessage);
        std::cout << "📡 [DEBUG] Queued message to transport: " << finalMessage.substr(0, 100) << "...\n";
        return true;
    } catch (const std::exception &e) {
        std::cerr << "❌ [sendData] Transport send failed: " << e.what() << "\n";
        return false;
    }
}
// The original version (by peerID) can call the socket version
bool Network::sendData(const std::string &peer, const std::string &data) {
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second || !it->second->isOpen()) {
        std::cerr << "❌ [ERROR] Peer transport not found or closed: " << peer << "\n";
        return false;
    }
    return sendData(it->second, data);
}

// ✅ **Request Blockchain Sync from Peers**
std::string Network::requestBlockchainSync(const std::string &peer) {
    if (peerTransports.find(peer) == peerTransports.end()) {
        std::cerr << "❌ [ERROR] Peer not found: " << peer << "\n";
        return "";
    }
    std::cout << "📡 Requesting blockchain sync from: " << peer << "\n";
    if (!sendData(peer, "ALYN|REQUEST_BLOCKCHAIN")) {
        std::cerr << "❌ Failed to send sync request to " << peer << "\n";
        return "";
    }
    return "";
}

// ✅ **Start Listening for Incoming Connections**
void Network::startServer() {
    try {
        std::cout << "🌐 Node is now listening for connections on port: " << port << "\n";

        ioContext.restart();  // Must come before async_accept
        listenForConnections();

        std::thread ioThread([this]() {
            std::cout << "🚀 IO context thread started for port " << port << "\n";
            try {
                ioContext.run();
                std::cout << "✅ IO context exited normally for port " << port << "\n";
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
        auto it = peerTransports.find(peer);
        if (it == peerTransports.end() || !it->second) {
            std::cerr << "❌ [ERROR] Peer not found or transport null: " << peer << std::endl;
            return "";
        }
        auto transport = it->second;
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

    peerTransports.emplace(peer, transport);
    std::cout << "📡 Peer added: " << peer << std::endl;
    savePeers(); // ✅ Save immediately
}

// ------------------------------------------------------------------
//  Helper: send the three “kick-off” messages after a connection
// ------------------------------------------------------------------
void Network::sendInitialRequests(const std::string& peerId)
{
    Json::StreamWriterBuilder b;  b["indentation"] = "";
    Json::Value j;

    j["type"] = "height_request";
    sendData(peerId, "ALYN|" + Json::writeString(b, j) + "\n");

    j["type"] = "tip_hash_request";
    sendData(peerId, "ALYN|" + Json::writeString(b, j) + "\n");

    j["type"] = "request_peers";
    sendData(peerId, "ALYN|" + Json::writeString(b, j) + "\n");
    sendData(peerId, "ALYN|REQUEST_BLOCKCHAIN\n");

    sendInventory(peerId);
}

// ------------------------------------------------------------------
//  Helper: set up an endless async-read loop for a socket
// ------------------------------------------------------------------
void Network::startReadLoop(const std::string&           peerId,
                            std::shared_ptr<Transport>   transport)
{
    /*  We need a std::function that can capture *itself* so we wrap it in a
        std::shared_ptr.  This is the classic “recursive lambda” pattern.     */
    using ReadCB = std::function<void(const boost::system::error_code&,
                                      const std::string&)>;

    auto self = std::make_shared<ReadCB>();     // forward declaration

    *self = [this, peerId, transport, self]     // capture *self* by value
              (const boost::system::error_code& ec,
               const std::string&               line)
    {
        /* ── connection closed / error ─────────────────────────────────── */
        if (ec || !transport->isOpen()) {
            std::cerr << "🔌 disconnect " << peerId
                      << " : " << ec.message() << '\n';

            std::lock_guard<std::timed_mutex> lk(peersMutex);
            peerTransports.erase(peerId);
            return;
        }

        /* ── dispatch valid line ───────────────────────────────────────── */
        if (!line.empty())
            handleIncomingData(peerId, line, transport);

        /* ── re-arm for next line ──────────────────────────────────────── */
        transport->asyncReadLine(*self);
    };

    std::cout << "🔄 Read-loop armed for " << peerId << '\n';
    transport->asyncReadLine(*self);
}
// Connect to Node
bool Network::connectToNode(const std::string &host, int port)
{
    if (peerTransports.size() > 32) {
        std::cerr << "⚠️ [connectToNode] Max-peer cap reached.  Skipping "
                  << host << ':' << port << '\n';
        return false;
    }
    std::string peerKey = host + ':' + std::to_string(port);
    if (bannedPeers.count(peerKey)) {
        std::cerr << "⚠️ [connectToNode] Peer " << peerKey << " is banned. Skipping connect.\n";
        return false;
    }
    try {
        std::cout << "[PEER_CONNECT] Attempting to connect to "
                  << host << ':' << port << '\n';

        auto transport = std::make_shared<TcpTransport>(ioContext);
        if (!transport->connect(host, port)) {
            std::cerr << "❌ [connectToNode] Could not connect to "
                      << host << ':' << port << '\n';
            return false;
        }

        // peerKey already set above
        {
            ScopedLockTracer _t("connectToNode");
            std::lock_guard<std::timed_mutex> g(peersMutex);

            if (peerTransports.count(peerKey)) {
                std::cout << "🔁 Already connected to peer: " << peerKey << '\n';
                return false;
            }
            peerTransports[peerKey] = transport;
            if (peerManager) peerManager->connectToPeer(peerKey);
        }

    Json::Value handshake;
    handshake["type"]        = "handshake";
    handshake["port"]        = std::to_string(this->port);
    handshake["version"]     = "1.0.0";
    handshake["network_id"]  = "mainnet";
    handshake["capabilities"]= Json::arrayValue;
    handshake["capabilities"].append("full");
    handshake["capabilities"].append("miner");
    handshake["height"]      = Blockchain::getInstance().getHeight();

        Json::StreamWriterBuilder wr;  wr["indentation"] = "";
        std::string payload = Json::writeString(wr, handshake);
        transport->queueWrite(std::string("ALYN|") + payload + '\n');

        std::cout << "🤝 Sent handshake to " << peerKey << ": ALYN|"
                  << payload << std::flush
                  << "✅ Connected to new peer: " << peerKey << '\n';

        // --- wait briefly for their handshake so we know their height ---
        std::string remoteHs = transport->readLineWithTimeout(2);
        if (!remoteHs.empty() && remoteHs.rfind("ALYN|",0)==0)
            remoteHs = remoteHs.substr(5);
        if (!remoteHs.empty() && remoteHs.front()=='{' && remoteHs.back()=='}') {
            Json::Value rh;
            Json::CharReaderBuilder rb; std::string errs;
            std::istringstream iss(remoteHs);
            if (Json::parseFromStream(rb, iss, &rh, &errs) &&
                rh["type"].asString()=="handshake" && peerManager)
            {
                int h = rh.get("height",0).asInt();
                peerManager->setPeerHeight(peerKey, h);
                if (h > (int)Blockchain::getInstance().getHeight())
                    transport->queueWrite("ALYN|REQUEST_BLOCKCHAIN\n");
                else if (h < (int)Blockchain::getInstance().getHeight())
                    sendFullChain(transport);
            }
        }

        startReadLoop(peerKey, transport);

        sendInitialRequests(peerKey);

        this->autoSyncIfBehind();
        this->syncWithPeers();
        return true;
    }
    catch (const std::exception &e) {
        std::cerr << "❌ [connectToNode] Error connecting to "
                  << host << ':' << port << " — " << e.what() << '\n';
        return false;
    }
}

//
void Network::sendLatestBlockIndex(const std::string &peerIP) {
  Json::Value msg;
  msg["type"] = "latest_block_index";
  msg["data"] = Blockchain::getInstance().getLatestBlock().getIndex();
  msg["note"] =
      "Supports Dilithium + Falcon signatures"; // Optional extra clarity
  Json::StreamWriterBuilder writer;
  sendData(peerIP, Json::writeString(writer, msg));
}
//
void Network::handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex) {
    int localIndex = Blockchain::getInstance().getLatestBlock().getIndex();

    if (localIndex <= 0) { // Only genesis present
        std::cout << "⚠️ [Node] Only Genesis block found locally. Requesting full blockchain sync from " << peerIP << "\n";
        sendData(peerIP, "ALYN|REQUEST_BLOCKCHAIN");
        return;
    }

    if (peerBlockIndex > localIndex) {
        std::cout << "📡 Peer " << peerIP
                  << " has longer chain. Requesting sync...\n";
        sendData(peerIP, "ALYN|REQUEST_BLOCKCHAIN");
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
    if (blockchain.getChain().empty()) {
        std::cerr << "⚠️ Warning: Blockchain is empty! No block to send.\n";
        return;
    }

    Block latestBlock = blockchain.getLatestBlock();
    alyncoin::BlockProto protoBlock = latestBlock.toProtobuf();

    std::string serializedBlock;
    if (!protoBlock.SerializeToString(&serializedBlock)) {
        std::cerr << "❌ [ERROR] Failed to serialize latest block\n";
        return;
    }

    std::string base64Block = Crypto::base64Encode(serializedBlock, false);
    base64Block.erase(std::remove(base64Block.begin(), base64Block.end(), '\n'), base64Block.end());
    base64Block.erase(std::remove(base64Block.begin(), base64Block.end(), '\r'), base64Block.end());


if (base64Block.empty()) {
    std::cerr << "[BUG] EMPTY BASE64 in sendLatestBlock for hash=" << latestBlock.getHash() << "\n";
    return; // <--- DON'T send if empty!
}
    sendData(peerIP, "ALYN|BLOCK_BROADCAST|" + base64Block + '\n');

    std::cout << "📡 [LIVE BROADCAST] Latest block sent to " << peerIP << " (Dilithium + Falcon signatures included)\n";
}

void Network::sendInventory(const std::string& peer)
{
    Blockchain& bc = Blockchain::getInstance();
    Json::Value inv;
    inv["type"] = "inv";
    inv["hashes"] = Json::arrayValue;
    for (const auto& blk : bc.getChain())
        inv["hashes"].append(blk.getHash());
    Json::StreamWriterBuilder b; b["indentation"] = "";
    sendData(peer, std::string("ALYN|") + Json::writeString(b, inv));
}
//
void Network::sendFullChain(const std::string &peerId)
{
    std::shared_ptr<Transport> targetTransport;
    {
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        auto it = peerTransports.find(peerId);
        if (it == peerTransports.end() || !it->second || !it->second->isOpen())
        {
            std::cerr << "❌ [sendFullChain] No open transport for peer " << peerId << "\n";
            return;
        }
        targetTransport = it->second;
    }
    sendFullChain(targetTransport);
}

// ---------------------------------------------------------------------------
// 2b. socket-overload: *new* MTU-safe implementation
// ---------------------------------------------------------------------------
void Network::sendFullChain(std::shared_ptr<Transport> transport)
{
    if (!transport || !transport->isOpen()) {
        std::cerr << "❌ [sendFullChain] Provided transport is null/closed\n";
        return;
    }

    Blockchain& bc = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
    bc.loadFromDB();  // ensure we have the latest chain
    const auto& chain = bc.getChain();

    if (chain.empty()) {
        std::cerr << "⚠️ [sendFullChain] Local chain empty, nothing to send\n";
        return;
    }

    std::cerr << "[sendFullChain] About to send " << chain.size() << " blocks:\n";
    for (const auto& blk : chain) {
        std::cerr << "  - idx=" << blk.getIndex()
                  << " hash=" << blk.getHash()
                  << " prev=" << blk.getPreviousHash()
                  << " miner=" << blk.getMinerAddress()
                  << std::endl;
    }

    // Build the protobuf
    alyncoin::BlockchainProto chainProto;
    for (const Block& blk : chain) {
        *chainProto.add_blocks() = blk.toProtobuf();
    }

    // Serialize + base64
    std::string serialized;
    if (!chainProto.SerializeToString(&serialized) || serialized.empty()) {
        std::cerr << "❌ [sendFullChain] Couldn’t serialize chain (" << chain.size() << " blocks)\n";
        return;
    }
    std::string b64 = Crypto::base64Encode(serialized, false);

    // Send the full-chain in one shot
    transport->queueWrite(std::string("ALYN|FULL_CHAIN|") + b64 + "\n");
    std::cerr << "📡 [sendFullChain] Full chain sent ("
              << chain.size() << " blocks, "
              << serialized.size() << " bytes raw, "
              << b64.size() << " base64 chars)\n";

    // **CRITICAL**: signal end of chain so peer calls compareAndMergeChains()
    transport->queueWrite("ALYN|BLOCKCHAIN_END\n");
    std::cerr << "📡 [sendFullChain] Sent BLOCKCHAIN_END marker\n";

    Json::Value heightMsg;
    heightMsg["type"] = "height_response";
    heightMsg["data"] = bc.getHeight();
    transport->queueWrite(std::string("ALYN|") + Json::writeString(Json::StreamWriterBuilder(), heightMsg) + "\n");
}


// cleanup
void Network::cleanupPeers() {
    ScopedLockTracer tracer("cleanupPeers");
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    std::vector<std::string> inactivePeers;

    for (const auto &peer : peerTransports) {
        try {
            if (!peer.second || !peer.second->isOpen()) {
                std::cerr << "⚠️ Peer transport closed: " << peer.first << "\n";
                inactivePeers.push_back(peer.first);
                continue;
            }

            // ✅ Use prefixed ping (non-breaking protocol message)
            std::string ping = "ALYN|PING\n";
            peer.second->queueWrite(ping);
            std::cout << "✅ Peer active: " << peer.first << "\n";
        } catch (const std::exception &e) {
            std::cerr << "⚠️ Exception checking peer " << peer.first << ": "
                      << e.what() << "\n";
            inactivePeers.push_back(peer.first);
        }
    }

    // Remove inactive peers
    for (const auto &peer : inactivePeers) {
        peerTransports.erase(peer);
        std::cout << "🗑️ Removed inactive peer: " << peer << "\n";
    }
    if (!inactivePeers.empty()) {
        broadcastPeerList();
        savePeers();
    }
}

// Add methods to handle rollup block synchronization
void Network::receiveRollupBlock(const std::string &data) {
  if (data.empty()) {
    std::cerr << "❌ [ERROR] Received empty rollup block data!\n";
    return;
  }

  // Deserialize rollup block and handle it
  RollupBlock rollupBlock = deserializeRollupBlock(data);
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
    std::string payload = "ROLLUP_BLOCK|" + rollup.serialize();

    ScopedLockTracer tracer("broadcastRollupBlock");
    std::lock_guard<std::timed_mutex> lock(peersMutex);

    for (const auto& [peerID, transport] : peerTransports) {
        if (transport && transport->isOpen()) {
            try {
                transport->queueWrite(std::string("ALYN|") + payload + "\n");
                std::cout << "✅ Sent rollup block to " << peerID << "\n";
            } catch (const std::exception& e) {
                std::cerr << "❌ Failed to send rollup block to " << peerID << ": " << e.what() << "\n";
            }
        }
    }
}
