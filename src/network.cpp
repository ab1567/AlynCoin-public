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
#include <json/json.h>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include "proto_utils.h"
#include <cstdlib>
#include <cstdio>
#ifdef HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
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
struct InFlightData {
    std::string peer;
    std::string prefix;
    std::string base64;
    bool active{false};
};
static thread_local std::unordered_map<std::string, InFlightData> inflight;
static inline bool looksLikeBase64(const std::string& s) {
    return !s.empty() && s.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos;
}
static std::map<uint64_t, Block> futureBlockBuffer;
PubSubRouter g_pubsub;
namespace fs = std::filesystem;
Network* Network::instancePtr = nullptr;

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
    pclose(pipe);
    if (peers.empty()) {
        std::cerr << "⚠️ [DNS] No valid TXT peer records found at " << domain << "\n";
    }
    return peers;
}

// ==== [Network Ctor/Dtor] ====
#ifdef HAVE_MINIUPNPC
void tryUPnPPortMapping(int port) { /* ... */ }
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
                transport->write(message + "\n");
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
        transport->write(message + "\n");
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
        it->second->write(message + "\n");
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
                transport->write(txData + "\n");
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
                transport->write(txData + "\n");
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

    for (const auto &[peer, transport] : peerTransports) {
        if (peer.empty()) continue;
        std::cout << "📡 [DEBUG] Requesting blockchain sync from " << peer << "...\n";
        requestBlockchainSync(peer);
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

        Json::Value root;
        Json::CharReaderBuilder rdr; std::string errs;
        std::istringstream iss(handshakeLine);

        if (!(Json::parseFromStream(rdr, iss, &root, &errs) &&
            root.isMember("type") && root["type"].asString() == "handshake" &&
            root.isMember("port") && root.isMember("version")))
            throw std::runtime_error("invalid handshake");

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
                  << " | net "            << claimedNetwork << '\n';

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
                if (transport && transport->isOpen()) transport->write(line + "\n");
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
            transport->write("ALYN|" + payload + "\n");
    }

    // 5. send the initial sync requests
    const auto sendInitialRequests = [this](const std::string& pid)
    {
        Json::StreamWriterBuilder b;  b["indentation"] = "";
        Json::Value j;

        j["type"] = "height_request";  sendData(pid,"ALYN|"+Json::writeString(b,j)+'\n');
        j["type"] = "tip_hash_request";sendData(pid,"ALYN|"+Json::writeString(b,j)+'\n');
        j["type"] = "request_peers";   sendData(pid,"ALYN|"+Json::writeString(b,j)+'\n');
    };
    sendInitialRequests(claimedPeerId);

    size_t myHeight = Blockchain::getInstance().getHeight();
    if (remoteHeight > static_cast<int>(myHeight) && transport && transport->isOpen())
        transport->write("ALYN|REQUEST_BLOCKCHAIN\n");

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
    transport->startReadLoop(
        [this, claimedPeerId](const std::string& line) {
            handleIncomingData(claimedPeerId, line, peerTransports[claimedPeerId]);
        }
    );
}


// ✅ **Run Network Thread**
void Network::run() {
    std::cout << "🚀 [Network] Starting network stack for port " << port << "\n";
        #ifdef HAVE_MINIUPNPC
            tryUPnPPortMapping(this->port);
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
        if (p == this->port) continue; // don't connect to our own port
        connectToNode(ip, p);
    }

    // Initial sync/gossip setup
    requestPeerList();
    autoMineBlock();

    // Give some time for peers to connect, then trigger height-aware cold sync
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

    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &[peerAddr, peerTransport] : peerTransports) {
        if (peerTransport && peerTransport->isOpen()) {
            std::cerr << "🌐 [autoSyncIfBehind] Requesting height from peer: " << peerAddr << std::endl;
            peerTransport->send("ALYN|{\"type\":\"height_request\"}\n");
        }
    }
    // Handler for "height_response" remains the same.
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

    // Make inflight a thread_local unordered_map if it isn't already:
    static thread_local std::unordered_map<std::string, InFlightData> inflight;

    if (data.rfind(protocolPrefix, 0) == 0)
        data = data.substr(std::strlen(protocolPrefix));

    if (data.rfind(blockBroadcastPrefix, 0) == 0 ||
        data.rfind(fullChainPrefix, 0) == 0)
    {
        InFlightData& infl = inflight[claimedPeerId];
        infl.peer   = claimedPeerId;
        infl.prefix = data.rfind(blockBroadcastPrefix, 0) == 0
                        ? blockBroadcastPrefix
                        : fullChainPrefix;
        infl.base64 = data.substr(std::strlen(infl.prefix.c_str()));
        infl.active = true;
        try {
            std::string raw = Crypto::base64Decode(infl.base64, false);
            if (infl.prefix == blockBroadcastPrefix) {
                alyncoin::BlockProto proto;
                if (proto.ParseFromString(raw) && proto.hash().size() == 64 &&
                    !proto.previous_hash().empty())
                {
                    handleBase64Proto(claimedPeerId, blockBroadcastPrefix,
                                      infl.base64, transport);
                    infl.active = false;
                }
            } else {
                alyncoin::BlockchainProto proto;
                if (proto.ParseFromString(raw)) {
                    handleBase64Proto(claimedPeerId, fullChainPrefix,
                                      infl.base64, transport);
                    infl.active = false;
                }
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
            } else {
                alyncoin::BlockchainProto proto;
                if (proto.ParseFromString(raw)) {
                    handleBase64Proto(claimedPeerId, fullChainPrefix,
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

    // === Full Blockchain Sync ===
    if (data.rfind(fullChainPrefix, 0) == 0) {
        std::string b64 = data.substr(std::strlen(fullChainPrefix));
        try {
            std::string raw = Crypto::base64Decode(b64, false);
            alyncoin::BlockchainProto protoChain;
            if (!protoChain.ParseFromString(raw)) {
                std::cerr << "[handleIncomingData] ❌ Invalid FULL_CHAIN protobuf\n";
                return;
            }

            std::vector<Block> blocks;
            for (const auto& pb : protoChain.blocks()) {
                try {
                    blocks.push_back(Block::fromProto(pb, false));
                } catch (...) {
                    std::cerr << "⚠️ Skipped malformed block\n";
                }
            }

            Blockchain& chain = Blockchain::getInstance();
            chain.compareAndMergeChains(blocks);
            std::cerr << "[handleIncomingData] ✅ Synced full chain from peer\n";
        } catch (...) {
            std::cerr << "[handleIncomingData] ❌ Base64 decode failed for FULL_CHAIN\n";
        }
        return;
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
            transport->write("ALYN|PONG\n");
        return;
    }

    if (data == "PONG")
        return;

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
                return;
            }

            if (type == "height_response") {
                int h = root["data"].asInt();
                if (peerManager) peerManager->setPeerHeight(claimedPeerId, h);
		if (h > (int)chain.getHeight() && transport && transport->isOpen())
                    transport->write("ALYN|REQUEST_BLOCKCHAIN\n");
                return;
            }

            if (type == "tip_hash_response" && peerManager) {
                peerManager->recordTipHash(claimedPeerId, root["data"].asString());
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
                    transport->write("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
                return;
            }

            if (type == "height_request") {
                Json::Value out;
                out["type"] = "height_response";
                out["data"] = chain.getHeight();
                if (transport && transport->isOpen())
                    transport->write("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
                return;
            }

            if (type == "tip_hash_request") {
                Json::Value out;
                out["type"] = "tip_hash_response";
                out["data"] = chain.getLatestBlockHash();
                if (transport && transport->isOpen())
                    transport->write("ALYN|" + Json::writeString(Json::StreamWriterBuilder(), out) + "\n");
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

    // === Fallback base64-encoded block ===
    try {
        if (!data.empty() && data.size() > 50 && data.find('|') == std::string::npos) {
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
            transport->write(message);
            std::cout << "✅ [broadcastBlock] Block " << block.getIndex() << " sent (base64 protobuf) to " << peerId << '\n';
        }
        catch (const std::exception& e) {
            std::cerr << "❌ [broadcastBlock] Send to " << peerId << " failed: " << e.what() << '\n';
        }
    }
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
                            peerTransport->write("ALYN|BLOCK_BROADCAST|" + b64 + "\n");
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
                                            peerTransport2->write("ALYN|BLOCK_BROADCAST|" + b64_2 + "\n");
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
            std::cerr << "⚠️  [handleBase64Proto] [Orphan Block] Parent missing for block idx=" << blk.getIndex() << '\n';
            if (transport && transport->isOpen())
                transport->write("ALYN|REQUEST_BLOCKCHAIN\n");
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
        } else if (prefix == "FULL_CHAIN|") {
            try {
                std::string raw = Crypto::base64Decode(b64, false);
                alyncoin::BlockchainProto protoChain;
                if (protoChain.ParseFromString(raw)) {
                    std::vector<Block> receivedBlocks;
                    for (const auto& protoBlock : protoChain.blocks()) {
                        try { receivedBlocks.push_back(Block::fromProto(protoBlock, false)); }
                        catch (...) {}
                    }
                    Blockchain& chain = Blockchain::getInstance();
                    chain.compareAndMergeChains(receivedBlocks);
                    std::cerr << "[handleBase64Proto] Chain merge complete (base64 streaming)\n";
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

        transport->write(finalMessage);
        std::cout << "📡 [DEBUG] Sent message direct to transport: " << finalMessage.substr(0, 100) << "...\n";
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
    try {
        std::cout << "[PEER_CONNECT] Attempting to connect to "
                  << host << ':' << port << '\n';

        auto transport = std::make_shared<TcpTransport>(ioContext);
        if (!transport->connect(host, port)) {
            std::cerr << "❌ [connectToNode] Could not connect to "
                      << host << ':' << port << '\n';
            return false;
        }

        const std::string peerKey = host + ':' + std::to_string(port);
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
        std::string payload = Json::writeString(wr, handshake) + '\n';
        transport->write(payload);

        std::cout << "🤝 Sent handshake to " << peerKey << ": "
                  << payload << std::flush
                  << "✅ Connected to new peer: " << peerKey << '\n';

        startReadLoop(peerKey, transport);

        sendInitialRequests(peerKey);

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
    transport->write(std::string("ALYN|FULL_CHAIN|") + b64 + "\n");
    std::cerr << "📡 [sendFullChain] Full chain sent ("
              << chain.size() << " blocks, "
              << serialized.size() << " bytes raw, "
              << b64.size() << " base64 chars)\n";

    // **CRITICAL**: signal end of chain so peer calls compareAndMergeChains()
    transport->write("ALYN|BLOCKCHAIN_END\n");
    std::cerr << "📡 [sendFullChain] Sent BLOCKCHAIN_END marker\n";
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
            if (!peer.second->write(ping)) {
                std::cerr << "⚠️ Failed to ping peer: " << peer.first
                          << " - Marking as inactive.\n";
                inactivePeers.push_back(peer.first);
            } else {
                std::cout << "✅ Peer active: " << peer.first << "\n";
            }
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
                transport->write(payload + "\n");
                std::cout << "✅ Sent rollup block to " << peerID << "\n";
            } catch (const std::exception& e) {
                std::cerr << "❌ Failed to send rollup block to " << peerID << ": " << e.what() << "\n";
            }
        }
    }
}
