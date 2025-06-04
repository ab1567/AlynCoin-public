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
#include <unordered_map>
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

#include <json/json.h>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include "proto_utils.h"
//
#include <cstdlib>
#include <cstdio>
#ifdef HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

static std::unordered_set<std::string> seenTxHashes;
static std::mutex seenTxMutex;

std::vector<std::string> fetchPeersFromDNS(const std::string& domain) {
    std::vector<std::string> peers;

    // 🔍 Use nslookup for TXT records
    std::string cmd = "nslookup -type=TXT " + domain;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "❌ [DNS] Failed to run nslookup for domain: " << domain << "\n";
        return peers;
    }

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);

        // Only extract from lines with text record
        if (line.find("text =") != std::string::npos || line.find("\"") != std::string::npos) {
            size_t start = line.find("\"");
            size_t end = line.find_last_of("\"");
            if (start != std::string::npos && end > start) {
                std::string peer = line.substr(start + 1, end - start - 1);

                // Must contain ":" and not be malformed
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


//
std::map<std::string, std::shared_ptr<tcp::socket>> peerSockets;
std::timed_mutex peersMutex;
#define ENABLE_DEBUG 0
namespace fs = std::filesystem;
Network* Network::instancePtr = nullptr;
static std::map<uint64_t, Block> futureBlockBuffer;


#ifdef HAVE_MINIUPNPC
void tryUPnPPortMapping(int port) {
    UPNPDev *devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, NULL);
    if (!devlist) {
        std::cerr << "[UPnP] No UPnP devices found.\n";
        return;
    }
    char lanaddr[64] = {0};
    UPNPUrls urls;
    IGDdatas data;
    int r = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr));
    if (r == 1) {
        std::string portStr = std::to_string(port);
        int rc = UPNP_AddPortMapping(
            urls.controlURL, data.first.servicetype,
            portStr.c_str(), portStr.c_str(), lanaddr,
            "AlynCoin Node", "TCP", 0, "0"
        );
        if (rc == UPNPCOMMAND_SUCCESS) {
            std::cout << "[UPnP] Port " << port << " mapped via UPnP.\n";
        } else {
            std::cerr << "[UPnP] Port mapping failed: " << strupnperror(rc) << "\n";
        }
    } else {
        std::cerr << "[UPnP] No valid IGD found.\n";
    }
    freeUPNPDevlist(devlist);
    FreeUPNPUrls(&urls);
}
#endif

// ✅ Correct Constructor:
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
    if (listenerThread.joinable()) {
      listenerThread.join();
    }
    std::cout << "✅ Network instance cleaned up safely." << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "❌ Error during Network destruction: " << e.what()
              << std::endl;
  }
}
//
void Network::listenForConnections() {
    std::cout << "🌐 Listening for connections on port: " << port << std::endl;

    acceptor.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::cout << "🌐 [ACCEPTED] Incoming connection accepted.\n";
            auto sockPtr = std::make_shared<tcp::socket>(std::move(socket));
            std::thread(&Network::handlePeer, this, sockPtr).detach();
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
            Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).saveToDB();
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
    for (const auto &peer : peerSockets) {
        sendMessageToPeer(peer.first, message);
    }
}

// ✅ **Getter function for syncing status**
bool Network::isSyncing() const { return syncing; }
// ✅ **Connect to a peer and send a message**
void Network::sendMessage(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const std::string &message) {
    try {
        if (!socket || !socket->is_open()) {
            return;
        }
        boost::asio::write(*socket, boost::asio::buffer(message + "\n"), boost::asio::transfer_all());
        std::cout << "📡 Sent message: " << message.substr(0, 200) << "...\n";
    } catch (const std::exception &e) {
        std::cerr << "⚠️ [WARNING] Failed sendMessage: " << e.what() << "\n";
    }
}

//
void Network::sendMessageToPeer(const std::string &peer,
                                const std::string &message) {
  try {
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::resolver resolver(io_context);

    std::size_t colonPos = peer.find(":");
    if (colonPos == std::string::npos) {
      return;
    }

    std::string host = peer.substr(0, colonPos);
    std::string port = peer.substr(colonPos + 1);

    if (host.empty() || port.empty()) {
      return;
    }

    boost::asio::ip::tcp::resolver::results_type endpoints =
        resolver.resolve(host, port);
    boost::asio::ip::tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    boost::asio::write(socket, boost::asio::buffer(message + "\n"));
    std::cout << "📡 Sent message to peer " << peer << ": " << message
              << std::endl;
  } catch (const std::exception &e) {
  }
}

// ✅ **Broadcast a transaction to all peers**

void Network::broadcastTransaction(const Transaction &tx) {
    std::string txData = tx.serialize();

    for (const auto &peer : peerSockets) {
        auto socket = peer.second;
        if (socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(txData + "\n"));
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
    for (const auto &peer : peerSockets) {
        if (peer.first == excludePeer) continue;
        auto socket = peer.second;
        if (socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(txData + "\n"));
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

    if (peerSockets.empty()) {
        std::cerr << "⚠️ [WARNING] No peers available for sync!\n";
        return;
    }

    for (const auto &[peer, socket] : peerSockets) {
        if (peer.empty()) continue;

        std::cout << "📡 [DEBUG] Requesting blockchain sync from " << peer << "...\n";
        requestBlockchainSync(peer); // Only send REQUEST_BLOCKCHAIN
    }
}
//
// ✅ New smart sync method
void Network::intelligentSync() {
    std::cout << "🔄 [Smart Sync] Starting intelligent sync process...\n";

    if (!peerManager || peerSockets.empty()) {
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
    for (const auto &[peer, socket] : peerSockets) {
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
    if (peerSockets.empty()) return;

    Json::Value peerListJson;
    peerListJson["type"] = "peer_list";
    peerListJson["data"] = Json::arrayValue;

    for (const auto &[peerAddr, _] : peerSockets) {
        if (peerAddr.find(":") == std::string::npos) continue;
        peerListJson["data"].append(peerAddr);
    }

    Json::StreamWriterBuilder writer;
     writer["indentation"] = "";
    std::string peerListMessage = Json::writeString(writer, peerListJson);

    for (const auto &[peerAddr, _] : peerSockets) {
    	sendData(peerAddr, "ALYN|" + peerListMessage);
	}

}

//
PeerManager* Network::getPeerManager() {
    return peerManager;
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
  for (const auto &[peerAddr, socket] : peerSockets) {
    sendData(peerAddr, "ALYN|{\"type\": \"request_peers\"}");
        }

  std::cout << "📡 Requesting peer list from all known peers..." << std::endl;
}
//
void Network::receiveFullChain(const std::string &senderIP, const std::string &data) {
    std::cout << "[INFO] Receiving full blockchain from " << senderIP << std::endl;

    Blockchain &chain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);

    // 1) Decode base64
    std::string decodedData;
    try {
        decodedData = Crypto::base64Decode(data);
    } catch (...) {
        std::cerr << "❌ [ERROR] Failed to base64 decode blockchain data from " << senderIP << "\n";
        return;
    }

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

// Handle Peer
void Network::handlePeer(std::shared_ptr<tcp::socket> socket) {
    std::string realPeerId, claimedPeerId, handshakeLine;
    std::string claimedPort, claimedVersion, claimedNetwork, claimedIP;
    auto selfAddr = [this]() -> std::string {
        return this->publicPeerId.empty()
            ? "127.0.0.1:" + std::to_string(this->port)
            : this->publicPeerId;
    };

    try {
        boost::asio::streambuf handshakeBuf;
        boost::asio::read_until(*socket, handshakeBuf, "\n");
        std::istream handshakeStream(&handshakeBuf);
        std::getline(handshakeStream, handshakeLine);

        Json::Value root;
        Json::CharReaderBuilder reader;
        std::string errs;
        std::istringstream ss(handshakeLine);

        if (Json::parseFromStream(reader, ss, &root, &errs) &&
            root.isMember("type") && root["type"].asString() == "handshake" &&
            root.isMember("port") && root.isMember("version")) {

            std::string senderIP = socket->remote_endpoint().address().to_string();
            int senderPort = socket->remote_endpoint().port();
            realPeerId = senderIP + ":" + std::to_string(senderPort);

            claimedPort = root["port"].asString();
            claimedVersion = root["version"].asString();
            claimedNetwork = root.get("network_id", "").asString();
            claimedIP = root.get("ip", senderIP).asString();
            claimedPeerId = claimedIP + ":" + claimedPort;

            std::cout << "🤝 Handshake received from real " << realPeerId
                      << " | Claimed: " << claimedPeerId
                      << " | Version: " << claimedVersion
                      << " | Network: " << claimedNetwork << "\n";

            if (claimedNetwork != "mainnet") {
                std::cerr << "⚠️ [handlePeer] Ignoring peer from different network: " << claimedNetwork << "\n";
                return;
            }
        } else {
            throw std::runtime_error("Invalid or missing handshake fields");
        }
    } catch (const std::exception &e) {
        // fallback code (unchanged)
        try {
            std::string ip = socket->remote_endpoint().address().to_string();
            int port = socket->remote_endpoint().port();
            realPeerId = ip + ":" + std::to_string(port);
            claimedPeerId = realPeerId;

            std::cerr << "⚠️ [handlePeer] Handshake failed (" << e.what()
                      << "), registering fallback peer: " << realPeerId << "\n";

            if (realPeerId == selfAddr()) {
                std::cout << "🛑 Not registering self as peer: " << realPeerId << "\n";
                return;
            }
            {
                ScopedLockTracer tracer("handlePeer");
                std::lock_guard<std::timed_mutex> lock(peersMutex);
                peerSockets[realPeerId] = socket;
            }
            if (!handshakeLine.empty()) {
                handleIncomingData(realPeerId, handshakeLine, socket);
            }
        } catch (...) {
            std::cerr << "❌ [handlePeer] Total failure to register peer.\n";
            return;
        }
        return;
    }

    // Prevent self-connect based on claimed or real
    if (claimedPeerId == selfAddr() || realPeerId == selfAddr()) {
        std::cout << "🛑 Not registering self as peer: " << claimedPeerId << "\n";
        return;
    }

    // Register peer
    {
        ScopedLockTracer tracer("handlePeer");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        peerSockets[claimedPeerId] = socket;
        if (peerManager) peerManager->connectToPeer(claimedPeerId);

        std::cout << "✅ [handlePeer] Peer socket registered for: " << claimedPeerId << " (real: " << realPeerId << ")\n";
        std::cout << "=== [peerSockets] Registered Peers ===\n";
        for (const auto& kv : peerSockets) {
            std::cout << "   " << kv.first
                      << (kv.second && kv.second->is_open() ? " [open]" : " [closed]") << "\n";
        }
        std::cout << "======================================\n";
    }

    // Broadcast peer list after every new connection
    broadcastPeerList();

    // Trigger initial sync requests to the claimed peerId
    auto sendInitialRequests = [&](const std::string &peerId) {
        sendData(peerId, "ALYN|REQUEST_BLOCKCHAIN\n");

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";

        Json::Value heightReq;
        heightReq["type"] = "height_request";
        sendData(peerId, "ALYN|" + Json::writeString(builder, heightReq) + "\n");

        Json::Value tipReq;
        tipReq["type"] = "tip_hash_request";
        sendData(peerId, "ALYN|" + Json::writeString(builder, tipReq) + "\n");

        Json::Value peersReq;
        peersReq["type"] = "request_peers";
        sendData(peerId, "ALYN|" + Json::writeString(builder, peersReq) + "\n");
    };
    sendInitialRequests(claimedPeerId);

    // Reverse connect if claimed port is valid and not our own
    if (!claimedPort.empty()) {
        int peerClaimedPort = 0;
        try { peerClaimedPort = std::stoi(claimedPort); } catch (...) {}
        std::string reverseIP = claimedIP;
        if (peerClaimedPort > 0 &&
            peerClaimedPort != this->port &&
            claimedPeerId != selfAddr() && !peerSockets.count(claimedPeerId)) {
            std::cout << "🔁 [ReverseConnect] Connecting back to " << reverseIP << ":" << peerClaimedPort << "\n";
            connectToPeer(reverseIP, peerClaimedPort);
        }
    }

    // === Async persistent read loop ===
    std::shared_ptr<boost::asio::streambuf> buf = std::make_shared<boost::asio::streambuf>();
    std::shared_ptr<tcp::socket> sharedSock = socket;
    auto self = this;
    std::cout << "🔄 [handlePeer] Starting persistent async read loop for: " << claimedPeerId << "\n";

    std::shared_ptr<std::function<void(const boost::system::error_code&, std::size_t)>> readHandler =
        std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();

    *readHandler = [self, sharedSock, buf, claimedPeerId, readHandler](const boost::system::error_code &ec, std::size_t /*bytesTransferred*/) {
        if (ec || !sharedSock || !sharedSock->is_open()) {
            std::cerr << "🔌 Peer read error/disconnect: " << claimedPeerId << " (" << ec.message() << ")\n";
            {
                ScopedLockTracer tracer("handlePeer");
                std::lock_guard<std::timed_mutex> lock(self->peersMutex);
                self->peerSockets.erase(claimedPeerId);
            }
            std::cout << "🔌 Cleaned up peer socket: " << claimedPeerId << "\n";
            return;
        }

        std::istream is(buf.get());
        std::string line;
        int linesRead = 0;

        // Improved: Drain all complete lines in buffer!
        while (std::getline(is, line)) {
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.pop_back();
            if (!line.empty()) {
                std::cout << "📥 [MULTILINE] Received from " << claimedPeerId << ": " << line.substr(0, 100) << "\n";
                self->handleIncomingData(claimedPeerId, line, sharedSock);
                linesRead++;
            }
        }

        if (linesRead == 0) {
            std::cout << "📥 [MULTILINE] No complete message lines in buffer from " << claimedPeerId << "\n";
        }

        // Continue persistent async read loop
        boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);
    };

    boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);
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
    Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
    size_t myHeight = blockchain.getHeight();

    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &[peerAddr, peerSocket] : peerSockets) {
        if (peerSocket && peerSocket->is_open()) {
            // Ask for peer height first (optional, makes it smarter)
            std::cerr << "🌐 [autoSyncIfBehind] Requesting height from peer: " << peerAddr << std::endl;
            boost::asio::write(*peerSocket, boost::asio::buffer("ALYN|{\"type\":\"height_request\"}\n"));
        }
    }
    // The response handler for "height_response" should:
    // - If peer height > myHeight, send "REQUEST_BLOCKCHAIN" to that peer only
}


// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
    std::vector<std::string> peers;

    // 1. DNS TXT Records (Cloudflare, ngrok, etc.)
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
        connectToNode(ip, port);
    }
}

//
void Network::periodicSync() {
    while (isRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(10));

        ScopedLockTracer tracer("periodicSync");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        if (peerSockets.empty()) {
            std::cerr << "⚠️ [Periodic Sync] No peers available, skipping.\n";
            continue;
        }

        for (const auto &peer : peerSockets) {
            const std::string &peerAddr = peer.first;
            if (peerAddr.empty()) continue;
            std::cout << "📡 [DEBUG] Periodic sync request to " << peerAddr << "\n";
            requestBlockchainSync(peerAddr);
        }
    }
}

//
std::vector<std::string> Network::getPeers() {
    std::vector<std::string> peerList;
    for (const auto &peer : peerSockets) {
        if (peer.second && peer.second->is_open()) {
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
void Network::handleIncomingData(const std::string &claimedPeerId, std::string data, std::shared_ptr<tcp::socket> socket) {
    std::cerr << "\n========== [handleIncomingData] ==========\n";
    std::cerr << "Peer: " << claimedPeerId << "\n";
    std::cerr << "Raw Data (first 100): [" << data.substr(0, 100) << "]\n";
    std::cerr << "Socket open? " << (socket && socket->is_open() ? "YES" : "NO") << "\n";
    std::cerr << "==========================================\n";

    // Remove all trailing \n or \r
    while (!data.empty() && (data.back() == '\n' || data.back() == '\r'))
        data.pop_back();

    if (data.empty()) {
        std::cerr << "❌ [handleIncomingData] Received completely empty data from " << claimedPeerId << "\n";
        return;
    }

    const std::string protocolPrefix = "ALYN|";
    const std::string blockPrefix = "BLOCK_BROADCAST|";
    const std::string endPrefix   = "BLOCKCHAIN_END";
    const std::string rollupPrefix = "ROLLUP_BLOCK|";

    // -- Protocol Prefix or JSON check
    bool hasPrefix = data.rfind(protocolPrefix, 0) == 0;
    if (hasPrefix) {
        data = data.substr(protocolPrefix.size());
        std::cerr << "[handleIncomingData] Detected protocol prefix (ALYN|). New data: [" << data.substr(0, 100) << "]\n";
    } else if (!(data.front() == '{' && data.back() == '}')) {
        std::cerr << "❌ [handleIncomingData] Rejected non-prefixed message from " << claimedPeerId << ". Full data: [" << data << "]\n";
        return;
    }

    // --- [NEW] Handle streamed base64 blocks during sync ---
    if (data.size() > 200 && data.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == std::string::npos) {
        std::cerr << "[handleIncomingData] Detected base64-encoded block during sync from " << claimedPeerId << "\n";
        try {
            std::string serialized = Crypto::base64Decode(data);

            alyncoin::BlockProto proto;
            if (!proto.ParseFromString(serialized)) {
                std::cerr << "❌ [handleIncomingData] [SYNC] Block Protobuf parse failed (base64=" << data.substr(0,40) << "...)\n";
                return;
            }

            Block blk = Block::fromProto(proto, true);
            std::cerr << "📥 [handleIncomingData] [SYNC] Block received: idx=" << blk.getIndex()
                      << ", Hash=" << blk.getHash()
                      << ", Prev=" << blk.getPreviousHash()
                      << ", txs=" << blk.getTransactions().size()
                      << "\n";

            incomingChains[claimedPeerId].push_back(blk);
            std::cerr << "[handleIncomingData] [SYNC] Buffered block idx=" << blk.getIndex() << " for peer " << claimedPeerId
                      << ". Current buffer size: " << incomingChains[claimedPeerId].size() << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ [handleIncomingData] [SYNC] Block parse failed: " << e.what() << "\n";
        }
        return;
    }

    // --- PING/PONG ---
    if (data == "PING") {
        std::cerr << "[handleIncomingData] Received PING from " << claimedPeerId << " → responding with PONG\n";
        if (socket && socket->is_open()) {
            boost::asio::write(*socket, boost::asio::buffer(protocolPrefix + "PONG\n"));
        } else {
            std::cerr << "[handleIncomingData] Can't send PONG: socket not open\n";
        }
        return;
    }
    if (data == "PONG") {
        std::cerr << "[handleIncomingData] Received PONG from " << claimedPeerId << "\n";
        return;
    }

    // --- Blockchain Sync: Request ---
    if (data == "REQUEST_BLOCKCHAIN") {
        std::cerr << "[handleIncomingData] REQUEST_BLOCKCHAIN received from " << claimedPeerId << "\n";
        if (socket && socket->is_open()) {
            std::cerr << "[handleIncomingData] Replying with sendFullChain(socket) for " << claimedPeerId << "\n";
            sendFullChain(socket);
        } else {
            std::cerr << "❌ [handleIncomingData] No valid socket found for direct reply to " << claimedPeerId << "\n";
        }
        return;
    }

    // --- Rollup Block ---
    if (data.rfind(rollupPrefix, 0) == 0) {
        std::cerr << "[handleIncomingData] Rollup block detected from " << claimedPeerId << "\n";
        try {
            RollupBlock rb = RollupBlock::deserialize(data.substr(rollupPrefix.size()));
            handleNewRollupBlock(rb);
            std::cerr << "✅ [handleIncomingData] Rollup block applied from " << claimedPeerId << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ [handleIncomingData] Rollup parse failed: " << e.what() << "\n";
        }
        return;
    }

    // --- Block-by-block Sync: Buffer blocks & live block path ---
    if (data.rfind(blockPrefix, 0) == 0) {
        std::cerr << "[handleIncomingData] Block broadcast received from " << claimedPeerId << "\n";
        try {
            std::string base64 = data.substr(blockPrefix.size());
            std::string serialized = Crypto::base64Decode(base64);

            alyncoin::BlockProto proto;
            if (!proto.ParseFromString(serialized)) {
                std::cerr << "❌ [handleIncomingData] Block Protobuf parse failed (base64=" << base64.substr(0,40) << "...)\n";
                return;
            }

            Block blk = Block::fromProto(proto, true);
            std::cerr << "📥 [handleIncomingData] Block received: idx=" << blk.getIndex()
                      << ", Hash=" << blk.getHash()
                      << ", Prev=" << blk.getPreviousHash()
                      << ", txs=" << blk.getTransactions().size()
                      << "\n";

            Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);

            // 1. Drop duplicate hash before buffering
            auto &buf = incomingChains[claimedPeerId];
            if (std::any_of(buf.begin(), buf.end(),
                            [&](const Block &b){ return b.getHash() == blk.getHash(); })) {
                std::cerr << "[handleIncomingData] Duplicate BLOCK_BROADCAST ignored (hash already buffered)\n";
                return;
            }

            // 2. Fast-path: If block extends our tip, add to chain immediately & clear buffer
            if (blk.getPreviousHash() == blockchain.getLatestBlockHash()) {
                std::cerr << "[handleIncomingData] Directly appending live block (idx=" << blk.getIndex() << ")\n";
                if (blockchain.addBlock(blk)) {
                    buf.clear(); // live path drained – nothing left to merge
                }
                return;
            }

            // 3. Orphan? Ask for full chain
            if (blk.getIndex() > 0 && !blockchain.hasBlockHash(blk.getPreviousHash())) {
                std::cerr << "⚠️ [handleIncomingData] [Orphan Block] Parent missing for block idx=" << blk.getIndex()
                          << ", hash=" << blk.getHash()
                          << " prev=" << blk.getPreviousHash()
                          << ". Buffer size for peer [" << claimedPeerId << "]: " << buf.size() << "\n";
                if (socket && socket->is_open()) {
                    std::cerr << "[handleIncomingData] Requesting full chain again from peer " << claimedPeerId << "\n";
                    boost::asio::write(*socket, boost::asio::buffer("ALYN|REQUEST_BLOCKCHAIN\n"));
                }
                return;
            }

            // 4. Standard: buffer for merge on BLOCKCHAIN_END
            buf.push_back(blk);
            std::cerr << "[handleIncomingData] Buffered block idx=" << blk.getIndex() << " for peer " << claimedPeerId
                      << ". Current buffer size: " << buf.size() << "\n";
            std::cerr << "All incomingChains keys:\n";
            for (const auto& kv : incomingChains) std::cerr << "  - " << kv.first << "\n";

        } catch (const std::exception &e) {
            std::cerr << "❌ [handleIncomingData] Block parse failed: " << e.what() << "\n";
        }
        return;
    }

    // --- Block Sync: End marker, trigger merge ---
    if (data == endPrefix) {
        std::cerr << "✅ [handleIncomingData] BLOCKCHAIN_END marker received from " << claimedPeerId << "\n";
        if (incomingChains.count(claimedPeerId)) {
            const std::vector<Block>& peerChain = incomingChains[claimedPeerId];
            Blockchain& blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
            std::cerr << "[handleIncomingData] Buffer size for peer: " << peerChain.size() << "\n";
            if (!peerChain.empty()) {
                std::cerr << "[handleIncomingData] About to call compareAndMergeChains (local height="
                          << blockchain.getChain().size() << ", remote=" << peerChain.size() << ")\n";
                blockchain.compareAndMergeChains(peerChain);
                std::cerr << "✅ [handleIncomingData] compareAndMergeChains() called for peer " << claimedPeerId << "\n";
            } else {
                std::cerr << "⚠️ [handleIncomingData] Peer chain buffer empty on END for " << claimedPeerId << "\n";
            }
            incomingChains.erase(claimedPeerId);
        } else {
            std::cerr << "⚠️ [handleIncomingData] No buffer found for peer on END marker: " << claimedPeerId << "\n";
            std::cerr << "All available incomingChains keys at END:\n";
            for (const auto& kv : incomingChains) std::cerr << "  - " << kv.first << "\n";
        }
        return;
    }

    // --- JSON-based messages (peer gossip, tx, etc) ---
    if (!data.empty() && data.front() == '{' && data.back() == '}') {
        std::cerr << "[handleIncomingData] JSON-based message detected from " << claimedPeerId << "\n";
        try {
            Json::Value root;
            std::istringstream s(data);
            Json::CharReaderBuilder rb;
            std::string errs;

            if (!Json::parseFromStream(rb, s, &root, &errs)) {
                std::cerr << "❌ [handleIncomingData] JSON parse error: " << errs << "\n";
                return;
            }

            Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
            std::string type = root["type"].asString();

            if (type == "height_response") {
                int peerHeight = root["data"].asInt();
                size_t myHeight = blockchain.getHeight();
                std::cerr << "[handleIncomingData] Peer " << claimedPeerId << " has height " << peerHeight
                          << ", local height is " << myHeight << std::endl;

                if (peerHeight > myHeight) {
                    // Current: You are behind, request their chain
                    if (socket && socket->is_open()) {
                        std::cerr << "[handleIncomingData] Detected longer peer. Requesting full chain from " << claimedPeerId << std::endl;
                        boost::asio::write(*socket, boost::asio::buffer("ALYN|REQUEST_BLOCKCHAIN\n"));
                    }
                } else if (peerHeight < myHeight) {
                    // NEW: You are ahead, offer your tip so they can request if needed
                    if (socket && socket->is_open()) {
                        Json::StreamWriterBuilder builder;
                        builder["indentation"] = "";
                        Json::Value tipReq;
                        tipReq["type"] = "tip_hash_request";
                        boost::asio::write(*socket, boost::asio::buffer("ALYN|" + Json::writeString(builder, tipReq) + "\n"));
                    }
                } else {
                    // Equal height, optionally compare tips to detect forks
                    if (socket && socket->is_open()) {
                        Json::StreamWriterBuilder builder;
                        builder["indentation"] = "";
                        Json::Value tipReq;
                        tipReq["type"] = "tip_hash_request";
                        boost::asio::write(*socket, boost::asio::buffer("ALYN|" + Json::writeString(builder, tipReq) + "\n"));
                    }
                }
                return;
            }

            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";

            // Peer List Gossip
            if (type == "peer_list") {
                const Json::Value& peers = root["data"];
                int connectedNow = 0;
                std::cerr << "[handleIncomingData] peer_list contains " << peers.size() << " peers\n";
                for (const auto& peer : peers) {
                    std::string peerStr = peer.asString();
                    if (peerStr.find(":") == std::string::npos) continue;
                    size_t colon = peerStr.find(":");
                    std::string ip = peerStr.substr(0, colon);
                    int prt = std::stoi(peerStr.substr(colon + 1));
                    if ((ip == "127.0.0.1" || ip == "localhost") && prt == this->port) continue;
                    if (ip == "127.0.0.1" || ip == "localhost") continue;
                    if (peerSockets.count(peerStr)) continue;
                    if (peerSockets.size() > 32) break;
                    std::cerr << "[handleIncomingData] [GOSSIP] Connecting to new peer from gossip: " << peerStr << std::endl;
                    connectToNode(ip, prt);

                    connectedNow++;
                }
                std::cerr << "[handleIncomingData] Connected to " << connectedNow << " new peers from peer_list\n";
                if (connectedNow > 0) savePeers();
                return;
            }

            // Respond to peer list requests
            if (type == "request_peers") {
                Json::Value peerListJson;
                peerListJson["type"] = "peer_list";
                peerListJson["data"] = Json::arrayValue;
                {
                    std::lock_guard<std::timed_mutex> lock(peersMutex);
                    for (const auto &[peerAddr, _] : peerSockets) {
                        if (peerAddr.find(":") != std::string::npos)
                            peerListJson["data"].append(peerAddr);
                    }
                }
                Json::StreamWriterBuilder writer;
                writer["indentation"] = "";
                std::string peerListMessage = Json::writeString(writer, peerListJson);
                if (socket && socket->is_open()) {
                    boost::asio::write(*socket, boost::asio::buffer("ALYN|" + peerListMessage + "\n"));
                }
                std::cerr << "[handleIncomingData] Responded with peer list to " << claimedPeerId << "\n";
                return;
            }

            // Respond to height request
            if (type == "height_request") {
                Json::Value res;
                res["type"] = "height_response";
                res["data"] = blockchain.getHeight();
                if (socket && socket->is_open()) {
                    boost::asio::write(*socket, boost::asio::buffer(protocolPrefix + Json::writeString(builder, res) + "\n"));
                }
                std::cerr << "[handleIncomingData] Responded with height_response to " << claimedPeerId << "\n";
                return;
            }

            // Respond to tip hash request
            if (type == "tip_hash_request") {
                Json::Value res;
                res["type"] = "tip_hash_response";
                res["data"] = blockchain.getLatestBlockHash();
                if (socket && socket->is_open()) {
                    boost::asio::write(*socket, boost::asio::buffer(protocolPrefix + Json::writeString(builder, res) + "\n"));
                }
                std::cerr << "[handleIncomingData] Responded with tip_hash_response to " << claimedPeerId << "\n";
                return;
            }

            // Accept and propagate transaction
            if (root.isMember("txid")) {
                Transaction tx = Transaction::fromJSON(root);
                const std::string txHash = tx.getHash();

                {
                    std::lock_guard<std::mutex> lock(seenTxMutex);
                    if (seenTxHashes.count(txHash) > 0) {
                        std::cerr << "⚠️ [handleIncomingData] [TX] Duplicate received from " << claimedPeerId << "\n";
                        return;
                    }
                    seenTxHashes.insert(txHash);
                }

                if (tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
                    blockchain.addTransaction(tx);
                    blockchain.savePendingTransactionsToDB();
                    std::cerr << "✅ [handleIncomingData] [TX] Accepted and saved from " << claimedPeerId << "\n";
                    broadcastTransactionToAllExcept(tx, claimedPeerId);
                } else {
                    std::cerr << "❌ [handleIncomingData] [TX] Invalid transaction from " << claimedPeerId << "\n";
                }
                return;
            }
        } catch (const std::exception &e) {
            std::cerr << "❌ [handleIncomingData] JSON exception: " << e.what() << "\n";
        }
        return;
    }

    // --- Unknown ---
    std::cerr << "⚠️ [handleIncomingData] Unknown message from " << claimedPeerId
              << ": [" << data.substr(0, std::min<size_t>(100, data.size())) << "]\n";
}

// ✅ **Broadcast a mined block to all peers*
void Network::broadcastBlock(const Block &block, bool force) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);
    std::string base64Block = Crypto::base64Encode(serializedBlock);
    std::string message = "ALYN|BLOCK_BROADCAST|" + base64Block + "\n";

    std::unordered_map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> peersCopy;
    bool lockAcquired = false;

    for (int attempts = 0; attempts < 3; ++attempts) {
        std::cerr << "[DEBUG] Attempting to acquire peersMutex in broadcastBlock() [Attempt "
                  << (attempts + 1) << "]\n";

        ScopedLockTracer tracer("broadcastBlock");
        std::unique_lock<std::timed_mutex> lock(peersMutex, std::defer_lock);
        if (lock.try_lock_for(std::chrono::milliseconds(500))) {
            std::cerr << "✅ [broadcastBlock] Acquired peersMutex.\n";
            peersCopy = peerSockets;
            lockAcquired = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    if (!lockAcquired) {
        std::cerr << "❌ [broadcastBlock] Failed to acquire peer lock after 3 attempts. Skipping broadcast.\n";
        return;
    }

    if (peersCopy.empty()) {
        std::cerr << "⚠️ [broadcastBlock] No connected peers to broadcast to.\n";
        return;
    }

    std::cerr << "📡 [broadcastBlock] Broadcasting to " << peersCopy.size() << " peers...\n";

    std::set<std::shared_ptr<boost::asio::ip::tcp::socket>> sentSockets;
    for (auto &[peer, socket] : peersCopy) {
        if (isSelfPeer(peer)) continue; // Don't send to yourself
        if (!socket || !socket->is_open()) {
            std::cerr << "⚠️ [broadcastBlock] Skipping closed or null socket: " << peer << "\n";
            continue;
        }
        if (sentSockets.count(socket)) continue;
        sentSockets.insert(socket);
        try {
            boost::asio::write(*socket, boost::asio::buffer(message));
            std::cout << "✅ [broadcastBlock] Block sent to " << peer << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ [broadcastBlock] Failed to send to " << peer << ": " << e.what() << "\n";
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
void Network::receiveTransaction(const Transaction &tx) {
    std::string txHash = tx.getHash();
    {
        std::lock_guard<std::mutex> lock(seenTxMutex);
        if (seenTxHashes.count(txHash) > 0)
            return;
        seenTxHashes.insert(txHash);
    }

    Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).addTransaction(tx);
    broadcastTransaction(tx);
}

// Valid peer
bool Network::validatePeer(const std::string &peer) {
  if (peer.find(":") == std::string::npos) { // ✅ Correct format check
    return false;
  }

  if (peerSockets.find(peer) != peerSockets.end()) {
    return false;
  }

  std::string handshakeMessage = "PEER_HANDSHAKE";
  sendData(peer, handshakeMessage);

  std::cout << "✅ Peer validated: " << peer << std::endl;
  return true;
}

// Handle new block
void Network::handleNewBlock(const Block &newBlock) {
    Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
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

            for (const auto& peer : peerSockets) {
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
            for (const auto& peer : peerSockets) {
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
  peerSockets.erase(peer);
  bannedPeers.insert(peer);
}

bool Network::isBlacklisted(const std::string &peer) {
  return bannedPeers.find(peer) != bannedPeers.end();
}

// ✅ **Send Data to Peer with Error Handling**
bool Network::sendData(std::shared_ptr<tcp::socket> socket, const std::string &data) {
    if (!socket || !socket->is_open()) {
        std::cerr << "❌ [sendData] Socket is null or closed\n";
        return false;
    }
    try {
        std::string finalMessage = data;
        while (!finalMessage.empty() && (finalMessage.back() == '\n' || finalMessage.back() == '\r')) {
            finalMessage.pop_back();
        }
        finalMessage += '\n';

        boost::asio::write(*socket, boost::asio::buffer(finalMessage));
        std::cout << "📡 [DEBUG] Sent message direct to socket: " << finalMessage.substr(0, 100) << "...\n";
        return true;
    } catch (const std::exception &e) {
        std::cerr << "❌ [sendData] Socket send failed: " << e.what() << "\n";
        // Do not try to erase from peerSockets, as we may not know the peerID
        return false;
    }
}

// The original version (by peerID) can call the socket version
bool Network::sendData(const std::string &peer, const std::string &data) {
    auto it = peerSockets.find(peer);
    if (it == peerSockets.end() || !it->second || !it->second->is_open()) {
        std::cerr << "❌ [ERROR] Peer socket not found or closed: " << peer << "\n";
        return false;
    }
    return sendData(it->second, data);
}


// ✅ **Request Blockchain Sync from Peers**
std::string Network::requestBlockchainSync(const std::string &peer) {
    if (peerSockets.find(peer) == peerSockets.end()) {
        std::cerr << "❌ [ERROR] Peer not found: " << peer << "\n";
        return "";
    }

    std::cout << "📡 Requesting blockchain sync from: " << peer << "\n";

    if (!sendData(peer, "ALYN|REQUEST_BLOCKCHAIN")) {
        std::cerr << "❌ Failed to send sync request to " << peer << "\n";
        return "";
    }

    // ✅ No blocking wait for reply — just send and return immediately
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
        auto it = peerSockets.find(peer);
        if (it == peerSockets.end() || !it->second) {
            std::cerr << "❌ [ERROR] Peer not found or socket null: " << peer << std::endl;
            return "";
        }

        std::shared_ptr<tcp::socket> socket = it->second;
        boost::asio::streambuf buf;
        boost::system::error_code ec;

        boost::asio::deadline_timer timer(ioContext);
        bool timed_out = false;
        bool read_done = false;

        // ✅ Required before any async run cycle
        ioContext.restart();

        // Start timer
        timer.expires_from_now(boost::posix_time::seconds(3));
        timer.async_wait([socket, &timed_out](const boost::system::error_code&) {
            timed_out = true;
            if (socket && socket->is_open()) {
                boost::system::error_code cancel_ec;
                socket->cancel(cancel_ec);
            }
        });

        // Start async read
        boost::asio::async_read_until(*socket, buf, "\n", [&](const boost::system::error_code& error, std::size_t) {
            ec = error;
            read_done = true;
        });

        // Run IO loop
        while (!read_done && !timed_out) {
            ioContext.run_one();
        }

        if (timed_out) {
            std::cerr << "⚠️ [receiveData] Timeout from peer: " << peer << "\n";
            return "";
        }

        if (ec && ec != boost::asio::error::eof) {
            std::cerr << "❌ [receiveData] Error from peer " << peer << ": " << ec.message() << "\n";
            return "";
        }

        std::istream is(&buf);
        std::string receivedData;
        std::getline(is, receivedData);
        std::cout << "📥 [DEBUG] Received Data from " << peer << ": "
                  << receivedData.substr(0, 200) << "...\n";

        return receivedData;

    } catch (const std::exception &e) {
        std::cerr << "❌ [EXCEPTION] receiveData: " << e.what() << "\n";
        return "";
    }
}

// ✅ Add peer
void Network::addPeer(const std::string &peer) {
  if (peerSockets.find(peer) != peerSockets.end()) {
    return;
  }

  std::shared_ptr<boost::asio::ip::tcp::socket> socket =
      std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
  peerSockets.emplace(peer, socket);

  std::cout << "📡 Peer added: " << peer << std::endl;
  savePeers(); // ✅ Save immediately
}

// Connect to Node
bool Network::connectToNode(const std::string &host, int port) {
    if (peerSockets.size() > 32) {
        std::cerr << "⚠️ [connectToNode] Max peer cap reached. Not connecting to: "
                  << host << ":" << port << "\n";
        return false;
    }
    try {
        std::cout << "[PEER_CONNECT] Attempting to connect to: "
                  << host << ":" << port << std::endl;

        auto socketPtr = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::ip::tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(host, std::to_string(port));

        boost::asio::connect(*socketPtr, endpoints);

        std::string peerKey = host + ":" + std::to_string(port);

        {
            ScopedLockTracer tracer("connectToNode");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            if (peerSockets.find(peerKey) != peerSockets.end()) {
                std::cout << "🔁 Already connected to peer: " << peerKey << "\n";
                return false;
            }
            peerSockets[peerKey] = socketPtr;
            if (peerManager) peerManager->connectToPeer(peerKey);
        }

        // --- Send handshake ---
        Json::Value handshake;
        handshake["type"] = "handshake";
        handshake["port"] = std::to_string(this->port);
        handshake["version"] = "1.0.0";
        handshake["network_id"] = "mainnet";
        handshake["capabilities"] = Json::arrayValue;
        handshake["capabilities"].append("full");
        handshake["capabilities"].append("miner");

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        std::string payload = Json::writeString(builder, handshake);
        if (!payload.empty() && payload.back() != '\n') payload += "\n";

        boost::asio::write(*socketPtr, boost::asio::buffer(payload));
        std::cout << "🤝 Sent handshake to " << peerKey << ": " << payload << std::endl;

        std::cout << "✅ Connected to new peer: " << peerKey << "\n";

        // --- Start async read loop (DRAIN ALL LINES, production correct) ---
        auto buf = std::make_shared<boost::asio::streambuf>();
        std::shared_ptr<tcp::socket> sharedSock = socketPtr;
        auto self = this;
        std::string realPeerId = peerKey;

        std::shared_ptr<std::function<void(const boost::system::error_code&, std::size_t)>> readHandler =
            std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();

        *readHandler = [self, sharedSock, buf, realPeerId, readHandler](const boost::system::error_code &ec, std::size_t /*bytesTransferred*/) {
            if (ec || !sharedSock || !sharedSock->is_open()) {
                std::cerr << "🔌 Peer read error/disconnect (outgoing): " << realPeerId
                          << " (" << ec.message() << ")\n";
                {
                    ScopedLockTracer tracer("connectToNode");
                    std::lock_guard<std::timed_mutex> lock(self->peersMutex);
                    self->peerSockets.erase(realPeerId);
                }
                std::cout << "🔌 Cleaned up outgoing peer socket: " << realPeerId << "\n";
                return;
            }

            std::istream is(buf.get());
            std::string line;
            int linesRead = 0;

            // FIX: Drain every complete line from the buffer
            while (std::getline(is, line)) {
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                    line.pop_back();
                if (!line.empty()) {
                    std::cout << "📥 [OUT] Received from " << realPeerId
                              << ": " << line.substr(0, 100) << "\n";
                    self->handleIncomingData(realPeerId, line, sharedSock);
                    linesRead++;
                }
            }
            if (linesRead == 0) {
                std::cout << "📥 [OUT] No complete message lines in buffer from " << realPeerId << "\n";
            }

            boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);
        };
        boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);

        // --- Initiate sync ---
        std::cout << "📡 [SYNC] Sending REQUEST_BLOCKCHAIN to " << peerKey << "\n";
        sendData(peerKey, "ALYN|REQUEST_BLOCKCHAIN");

        return true;

    } catch (const std::exception &e) {
        std::cerr << "❌ [connectToNode] Error connecting to node "
                  << host << ":" << port << " — " << e.what() << "\n";
        return false;
    }
}

//
void Network::sendLatestBlockIndex(const std::string &peerIP) {
  Json::Value msg;
  msg["type"] = "latest_block_index";
  msg["data"] = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).getLatestBlock().getIndex();
  msg["note"] =
      "Supports Dilithium + Falcon signatures"; // Optional extra clarity
  Json::StreamWriterBuilder writer;
  sendData(peerIP, Json::writeString(writer, msg));
}
//
void Network::handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex) {
    int localIndex = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).getLatestBlock().getIndex();
    
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

        // Avoid connecting to self
	std::string ip = line.substr(0, line.find(":"));
	int portVal = std::stoi(line.substr(line.find(":") + 1));
	// Block any local-only addresses
	if ((ip == "127.0.0.1" || ip == "localhost") && portVal == this->port) continue;
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
    if (!peerSockets.empty()) {
        std::cout << "✅ [scanForPeers] Mesh established, skipping DNS scan.\n";
        return;
    }
    std::vector<std::string> potentialPeers = fetchPeersFromDNS("peers.alyncoin.com");
    std::cout << "🔍 [DNS] Scanning for AlynCoin nodes..." << std::endl;

    for (const auto& peer : potentialPeers) {
	std::string ip = peer.substr(0, peer.find(":"));
	int peerPort = std::stoi(peer.substr(peer.find(":") + 1));
	if ((ip == "127.0.0.1" || ip == "localhost") && peerPort == this->port) continue;
	if (ip == "127.0.0.1" || ip == "localhost") continue;
	connectToNode(ip, peerPort);

    }
    if (peerSockets.empty()) {
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

    for (const auto &[peer, _] : peerSockets) {
        if (!peer.empty() && peer.find(":") != std::string::npos) {
            file << peer << std::endl;
        }
    }

    file.close();
    std::cout << "✅ Peer list saved successfully. Total peers: "
            << peerSockets.size() << std::endl;
}

// ✅ **Broadcast Latest Block Correctly (Base64 Encoded)**
void Network::sendLatestBlock(const std::string &peerIP) {
    Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);

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

    std::string base64Block = Crypto::base64Encode(serializedBlock);
    sendData(peerIP, "ALYN|BLOCK_BROADCAST|" + base64Block);

    std::cout << "📡 [LIVE BROADCAST] Latest block sent to " << peerIP << " (Dilithium + Falcon signatures included)\n";
}

// ---------------------------------------------------------------------------
// 🚀 1. Helper – write a long string in safe 1 024 B slices
// ---------------------------------------------------------------------------
static void writeChunked(tcp::socket &sock, const std::string &data,
                         std::size_t chunk = 1024)
{
    for (std::size_t off = 0; off < data.size(); off += chunk)
    {
        boost::asio::write(
            sock,
            boost::asio::buffer(data.data() + off,
                                std::min<std::size_t>(chunk, data.size() - off)));
    }
}

// ---------------------------------------------------------------------------
// 2a. find-peer-id overload (unchanged except for heading comment)
// ---------------------------------------------------------------------------
void Network::sendFullChain(const std::string &peerId)
{
    std::shared_ptr<tcp::socket> targetSocket;

    {
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        auto it = peerSockets.find(peerId);
        if (it == peerSockets.end() || !it->second || !it->second->is_open())
        {
            std::cerr << "❌ [sendFullChain] No open socket for peer " << peerId << "\n";
            return;
        }
        targetSocket = it->second;
    }
    sendFullChain(targetSocket);
}

// ---------------------------------------------------------------------------
// 2b. socket-overload: *new* MTU-safe implementation
// ---------------------------------------------------------------------------
void Network::sendFullChain(std::shared_ptr<tcp::socket> socket)
{
    if (!socket || !socket->is_open())
    {
        std::cerr << "❌ [sendFullChain] Provided socket is null/closed\n";
        return;
    }

    // --  ⭐  disable Nagle / DF so kernel may fragment if needed
    boost::asio::ip::tcp::no_delay option(true);
    socket->set_option(option);

    Blockchain &bc  = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
    const auto &chain = bc.getChain();

    if (chain.empty())
    {
        std::cerr << "⚠️ [sendFullChain] Local chain empty, nothing to send\n";
        return;
    }

    std::cerr << "[sendFullChain] 🚀 Streaming " << chain.size() << " blocks…\n";

    for (const Block &blk : chain)
    {
        try
        {
            alyncoin::BlockProto proto = blk.toProtobuf();
            std::string raw;
            if (!proto.SerializeToString(&raw))
            {
                std::cerr << "❌ Couldn’t serialise block " << blk.getIndex() << '\n';
                continue;
            }

            const std::string base64 = Crypto::base64Encode(raw);
            const std::string line   = "ALYN|BLOCK_BROADCAST|" + base64 + '\n';

            // --------  write in 1 024 B slices  ------------------
            writeChunked(*socket, line);

            std::cerr << "📡  Sent block " << blk.getIndex()
                      << "  (" << base64.size() << " B base64)\n";
        }
        catch (const std::exception &e)
        {
            std::cerr << "⚠️  sendFullChain: exception on blk "
                      << blk.getIndex() << " – " << e.what() << '\n';
        }
    }

    // --- chain end marker ---
    try
    {
        writeChunked(*socket, std::string("ALYN|BLOCKCHAIN_END\n"));
        std::cerr << "[sendFullChain] 🏁  Chain end marker sent\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "❌ Failed to send end marker: " << e.what() << '\n';
    }
}

// cleanup
void Network::cleanupPeers() {
    ScopedLockTracer tracer("cleanupPeers");
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    std::vector<std::string> inactivePeers;

    for (const auto &peer : peerSockets) {
        try {
            if (!peer.second || !peer.second->is_open()) {
                std::cerr << "⚠️ Peer socket closed: " << peer.first << "\n";
                inactivePeers.push_back(peer.first);
                continue;
            }

            // ✅ Use prefixed ping (non-breaking protocol message)
            std::string ping = "ALYN|PING";
            boost::system::error_code ec;
            peer.second->send(boost::asio::buffer(ping + "\n"), 0, ec);
            if (ec) {
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
        peerSockets.erase(peer);
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
  Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).addRollupBlock(rollupBlock);
  std::cout << "✅ Rollup block received and added to blockchain!\n";
}
//
void Network::handleNewRollupBlock(const RollupBlock &newRollupBlock) {
  if (Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).isRollupBlockValid(newRollupBlock)) {
    Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).addRollupBlock(newRollupBlock);
    std::lock_guard<std::mutex> lock(blockchainMutex);
    Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).saveRollupChain();
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

    for (const auto& [peerID, sock] : peerSockets) {
        if (sock && sock->is_open()) {
            try {
                boost::asio::write(*sock, boost::asio::buffer(payload + "\n"));
                std::cout << "✅ Sent rollup block to " << peerID << "\n";
            } catch (const std::exception& e) {
                std::cerr << "❌ Failed to send rollup block to " << peerID << ": " << e.what() << "\n";
            }
        }
    }
}
