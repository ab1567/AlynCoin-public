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
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include "crypto_utils.h"
#include <filesystem>
#include <iostream>
#include <set>

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
        std::cout << "📡 Transaction broadcasted to peer: " << peer.first
                  << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "❌ [ERROR] Failed to broadcast transaction to "
                  << peer.first << ": " << e.what() << std::endl;
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
    if (port <= 0 || port > 65535) {
        std::cerr << "❌ Invalid port in connectToPeer: " << port << "\n";
        return;
    }
    connectToNode(ip, port); // Delegates to the unified function
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
    std::string peerListMessage = Json::writeString(writer, peerListJson);

    for (const auto &[peerAddr, _] : peerSockets) {
        sendData(peerAddr, peerListMessage);
    }
}

//
PeerManager* Network::getPeerManager() {
    return peerManager;
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
  for (const auto &[peerAddr, socket] : peerSockets) {
    sendData(peerAddr, R"({"type": "request_peers"})");
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

    if (protoChain.blocks_size() == 0) {
        std::cerr << "⚠️ [Network] Received empty blockchain.\n";
        return;
    }

    std::vector<Block> receivedBlocks;
    for (const auto& protoBlock : protoChain.blocks()) {
        try {
            Block blk = Block::fromProto(protoBlock, /*allowPartial=*/false);
            receivedBlocks.push_back(blk);
        } catch (const std::exception& e) {
            std::cerr << "⚠️ [Network] Failed to parse block: " << e.what() << "\n";
        }
    }

    if (receivedBlocks.empty()) {
        std::cerr << "❌ [Network] No valid blocks parsed from received chain.\n";
        return;
    }

    // 3) Validate Genesis Match
    if (!chain.getChain().empty() && chain.getChain()[0].getHash() != receivedBlocks[0].getHash()) {
        std::cerr << "⚠️ [Network] Genesis mismatch. Aborting sync.\n";
        return;
    }

    std::cout << "🔍 Local chain length: " << chain.getChain().size()
              << ", Received: " << receivedBlocks.size() << "\n";

    // 4) Validate entire fork safety BEFORE touching chain
    if (!chain.verifyForkSafety(receivedBlocks)) {
        std::cerr << "⚠️ [Network] Received fork failed safety check.\n";

        if (receivedBlocks.size() > chain.getChain().size()) {
            std::cerr << "✅ [Fallback Override] Longer chain with same genesis detected. Proceeding.\n";
            // continue to merge below
        } else {
            std::cerr << "❌ [Reject] Unsafe or shorter fork. Saved for analysis.\n";
            chain.saveForkView(receivedBlocks);
            return;
        }
    }

    // 5) Merge using difficulty-aware fork logic
    chain.compareAndMergeChains(receivedBlocks);
}

// Handle Peer
void Network::handlePeer(std::shared_ptr<tcp::socket> socket) {
    std::string peerId, reverseIP;
    int reversePort = 0;
    std::string handshakeLine;

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
            peerId = senderIP + ":" + root["port"].asString();

            reverseIP = senderIP;
            reversePort = std::stoi(root["port"].asString());

            std::string remoteVersion = root["version"].asString();
            std::string remoteNetwork = root.get("network_id", "").asString();
            std::cout << "🤝 Handshake received from " << peerId
                      << " | Version: " << remoteVersion
                      << ", Network: " << remoteNetwork << "\n";

            if (remoteNetwork != "mainnet") {
                std::cerr << "⚠️ [handlePeer] Ignoring peer from different network: " << remoteNetwork << "\n";
                return;
            }

        } else {
            throw std::runtime_error("Invalid or missing handshake fields");
        }

    } catch (const std::exception &e) {
        try {
            std::string ip = socket->remote_endpoint().address().to_string();
            int port = socket->remote_endpoint().port();
            peerId = ip + ":" + std::to_string(port);

            std::cerr << "⚠️ [handlePeer] Handshake failed (" << e.what()
                      << "), registering fallback peer: " << peerId << "\n";

            {
                ScopedLockTracer tracer("handlePeer");
                std::lock_guard<std::timed_mutex> lock(peersMutex);
                peerSockets[peerId] = socket;
                if (peerManager) peerManager->connectToPeer(peerId);
            }

            if (!handshakeLine.empty()) {
                handleIncomingData(peerId, handshakeLine);
            }

        } catch (...) {
            std::cerr << "❌ [handlePeer] Total failure to register peer.\n";
            return;
        }
    }

    {
        ScopedLockTracer tracer("handlePeer");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        peerSockets[peerId] = socket;
        std::cout << "✅ [handlePeer] Peer socket registered for: " << peerId << "\n";

        if (peerManager) peerManager->connectToPeer(peerId);
    }

    std::cout << "✅ [handlePeer] Incoming peer registered: " << peerId << "\n";

    // Send initial sync requests
    sendData(peerId, "ALYN|REQUEST_BLOCKCHAIN\n");

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    Json::Value heightReq;
    heightReq["type"] = "height_request";
    sendData(peerId, "ALYN|" + Json::writeString(builder, heightReq) + "\n");

    Json::Value tipReq;
    tipReq["type"] = "tip_hash_request";
    sendData(peerId, "ALYN|" + Json::writeString(builder, tipReq) + "\n");

    if (!reverseIP.empty() && reversePort > 0 && reversePort != this->port) {
        std::string selfIP = "127.0.0.1";
        if (!(reverseIP == selfIP && reversePort == this->port)) {
            std::cout << "🔁 [ReverseConnect] Connecting back to " << reverseIP << ":" << reversePort << "\n";
            connectToPeer(reverseIP, reversePort);
        }
    }

    // ✅ Persistent async read loop using shared_ptr trick
    std::shared_ptr<boost::asio::streambuf> buf = std::make_shared<boost::asio::streambuf>();
    std::shared_ptr<tcp::socket> sharedSock = socket;
    auto self = this;

    std::shared_ptr<std::function<void(const boost::system::error_code&, std::size_t)>> readHandler =
        std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();

    *readHandler = [self, sharedSock, buf, peerId, readHandler](const boost::system::error_code &ec, std::size_t bytesTransferred) {
        if (ec || !sharedSock || !sharedSock->is_open()) {
            std::cerr << "🔌 Peer read error/disconnect: " << peerId << " (" << ec.message() << ")\n";
            {
                ScopedLockTracer tracer("handlePeer");
                std::lock_guard<std::timed_mutex> lock(self->peersMutex);
                self->peerSockets.erase(peerId);
            }
            std::cout << "🔌 Cleaned up peer socket: " << peerId << "\n";
            return;
        }

        std::istream is(buf.get());
        std::string line;
        std::getline(is, line);

        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();

        if (!line.empty()) {
            std::cout << "📥 Received from " << peerId << ": " << line.substr(0, 100) << "\n";
            self->handleIncomingData(peerId, line);
        }

        // 🔁 Continue async read
        boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);
    };

    boost::asio::async_read_until(*sharedSock, *buf, "\n", *readHandler);
}

// ✅ **Run Network Thread**
void Network::run() {
    std::cout << "🚀 [Network] Starting network stack for port " << port << "\n";

    // ✅ Start listener and IO thread from here
    startServer();  // Runs listen + ioContext in background via listenerThread

    std::this_thread::sleep_for(std::chrono::seconds(2));  // Allow socket layer to bind

    // ✅ 1. DNS-based peer discovery
    std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
    for (const std::string& peer : dnsPeers) {
        size_t colonPos = peer.find(":");
        if (colonPos == std::string::npos) continue;

        std::string ip = peer.substr(0, colonPos);
        int port = std::stoi(peer.substr(colonPos + 1));
        if (ip != "127.0.0.1" && port != this->port) {
            connectToNode(ip, port);
        }
    }

    // ✅ 2. Fallback LAN/WSL peers
    std::vector<std::string> fallbackLANPeers = {
        "192.168.1.205:8333",
        "172.17.80.1:8333"
    };

    for (const auto& peer : fallbackLANPeers) {
        size_t pos = peer.find(":");
        if (pos == std::string::npos) continue;

        std::string ip = peer.substr(0, pos);
        int port = std::stoi(peer.substr(pos + 1));
        if (port != this->port) {
            connectToNode(ip, port);
        }
    }

    // ✅ Initial sync tasks
    requestPeerList();
    scanForPeers();
    autoMineBlock();

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

    std::cout << "✅ [Network] Network loop launched successfully.\n";
}

// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
    std::vector<std::string> peers;

    // ✅ 1. DNS TXT Records (Cloudflare, ngrok, etc.)
    std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
    for (const auto& peer : dnsPeers) {
        if (!peer.empty()) {
            std::cout << "🌐 [DNS] Found peer: " << peer << "\n";
            peers.push_back(peer);
        }
    }

    // ✅ 2. Local file fallback
    if (!std::filesystem::exists("data"))
        std::filesystem::create_directory("data");

    std::ifstream file("data/peers.list");
    if (!file) {
        std::cerr << "⚠️ [WARNING] No known peers file found.\n";
        return peers;
    }

    std::string line;
    while (std::getline(file, line)) {
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (!line.empty() && line[0] != '#') {
            std::cout << "📁 [File] Found peer: " << line << "\n";
            peers.push_back(line);
        }
    }

    file.close();
    return peers;
}

//
void Network::connectToDiscoveredPeers() {
  std::vector<std::string> peers = discoverPeers();
  for (const std::string &peer : peers) {
    if (peer.empty()) continue;

    std::string ip = peer;
    int port = DEFAULT_PORT;

    if (peer.find(":") != std::string::npos) {
      size_t pos = peer.find(":");
      ip = peer.substr(0, pos);
      try {
        port = std::stoi(peer.substr(pos + 1));
      } catch (...) {
        std::cerr << "⚠️ [WARNING] Invalid port for peer: " << peer << "\n";
        continue;
      }
    }

    if (ip == "127.0.0.1" && port == this->port) {
      std::cout << "⚠️ Skipping self in discovered peers: " << peer << "\n";
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
void Network::handleIncomingData(const std::string &peerID, std::string data) {
    std::cout << "📥 handleIncomingData() from " << peerID
              << " | Raw: " << data.substr(0, 100) << "\n";

    while (!data.empty() && (data.back() == '\n' || data.back() == '\r'))
        data.pop_back();

    const std::string protocolPrefix = "ALYN|";
    const std::string chainPrefix = "BLOCKCHAIN_DATA|";
    const std::string blockPrefix = "BLOCK_BROADCAST|";
    const std::string rollupPrefix   = "ROLLUP_BLOCK|";

    bool hasPrefix = data.rfind(protocolPrefix, 0) == 0;
    if (hasPrefix) {
        data = data.substr(protocolPrefix.size());
    } else if (!(data.front() == '{' && data.back() == '}')) {
        std::cerr << "❌ [handleIncomingData] Rejected non-prefixed message from " << peerID << "\n";
        return;
    }

    if (data == "PING") {
        std::cout << "📡 Received PING from " << peerID << " → responding with PONG\n";
        sendData(peerID, protocolPrefix + "PONG");
        return;
    }

    if (data == "PONG") {
        std::cout << "📡 Received PONG from " << peerID << "\n";
        return;
    }

    if (data == "REQUEST_BLOCKCHAIN") {
        std::cerr << "📡 REQUEST_BLOCKCHAIN received from " << peerID << "\n";

        std::shared_ptr<tcp::socket> targetSocket = nullptr;
        std::string matchKey = "";

        {
            ScopedLockTracer tracer("handleIncomingData");
            std::lock_guard<std::timed_mutex> lock(peersMutex);

            auto it = peerSockets.find(peerID);
            if (it != peerSockets.end()) {
                targetSocket = it->second;
                matchKey = peerID;
            } else {
                std::string peerIP = peerID.substr(0, peerID.find(":"));
                for (const auto &entry : peerSockets) {
                    std::string entryIP = entry.first.substr(0, entry.first.find(":"));
                    if (entryIP == peerIP && entry.second && entry.second->is_open()) {
                        targetSocket = entry.second;
                        matchKey = entry.first;
                        std::cerr << "✅ [SYNC] Matched fallback peer by IP: " << matchKey << "\n";
                        break;
                    }
                }
            }
        }

        if (targetSocket && !matchKey.empty()) {
            std::cout << "✅ [SYNC] Sending full chain to: " << matchKey << "\n";
            sendFullChain(matchKey);
        } else {
            std::cerr << "❌ [SYNC] No valid socket found for " << peerID << "\n";
        }

        return;
    }

    if (data.rfind(rollupPrefix, 0) == 0) {
        try {
            RollupBlock rb = RollupBlock::deserialize(data.substr(rollupPrefix.size()));
            handleNewRollupBlock(rb);
            std::cout << "✅ Rollup block applied from " << peerID << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ Rollup parse failed: " << e.what() << "\n";
        }
        return;
    }

    // === Handle full blockchain sync ===
    if (data.rfind(chainPrefix, 0) == 0) {
        try {
            std::string encoded = data.substr(chainPrefix.size());
            receiveFullChain(peerID, encoded);
        } catch (const std::exception &e) {
            std::cerr << "❌ [SYNC] Error in receiveFullChain: " << e.what() << "\n";
        }
        return;
    }

    // === Handle individual block broadcast ===

if (data.rfind(blockPrefix, 0) == 0) {
    try {
        std::string base64 = data.substr(blockPrefix.size());
        std::string serialized = Crypto::base64Decode(base64);

        alyncoin::BlockProto proto;
        if (!proto.ParseFromString(serialized)) {
            std::cerr << "❌ Block Protobuf parse failed.\n";
            return;
        }

        Block blk = Block::fromProto(proto, true);
        std::cerr << "📥 Block received: #" << blk.getIndex()
                  << ", Hash: " << blk.getHash().substr(0, 12) << "\n";
        handleNewBlock(blk);
    } catch (const std::exception &e) {
        std::cerr << "❌ Block parse failed: " << e.what() << "\n";
    }
    return;
}

    // === JSON-based messages ===
    if (!data.empty() && data.front() == '{' && data.back() == '}') {
        try {
            Json::Value root;
            std::istringstream s(data);
            Json::CharReaderBuilder rb;
            std::string errs;

            if (!Json::parseFromStream(rb, s, &root, &errs)) {
                std::cerr << "❌ JSON parse error: " << errs << "\n";
                return;
            }

            Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
            std::string type = root["type"].asString();

            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";

            if (type == "height_request") {
                Json::Value res;
                res["type"] = "height_response";
                res["data"] = blockchain.getHeight();
                sendData(peerID, protocolPrefix + Json::writeString(builder, res));
                return;
            }

            if (type == "tip_hash_request") {
                Json::Value res;
                res["type"] = "tip_hash_response";
                res["data"] = blockchain.getLatestBlockHash();
                sendData(peerID, protocolPrefix + Json::writeString(builder, res));
                return;
            }

            Transaction tx = Transaction::fromJSON(root);
            if (tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
                blockchain.addTransaction(tx);
                blockchain.savePendingTransactionsToDB();
                std::cout << "✅ [TX] Accepted from " << peerID << "\n";
            } else {
                std::cerr << "❌ [TX] Invalid from " << peerID << "\n";
            }

        } catch (const std::exception &e) {
            std::cerr << "❌ JSON exception: " << e.what() << "\n";
        }
        return;
    }

    std::cerr << "⚠️ Unknown message from " << peerID
              << ": " << data.substr(0, std::min<size_t>(100, data.size())) << "\n";
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

    for (auto &[peer, socket] : peersCopy) {
        if (!socket || !socket->is_open()) {
            std::cerr << "⚠️ [broadcastBlock] Skipping closed or null socket: " << peer << "\n";
            continue;
        }

        try {
            boost::asio::write(*socket, boost::asio::buffer(message));
            std::cout << "✅ [broadcastBlock] Block sent to " << peer << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ [broadcastBlock] Failed to send to " << peer << ": " << e.what() << "\n";
        }
    }
}

//
void Network::receiveTransaction(const Transaction &tx) {
  std::string txHash = tx.getHash();
  if (seenTxHashes.count(txHash) > 0)
    return; // Already processed
  seenTxHashes.insert(txHash);

  Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true).addTransaction(tx);
  broadcastTransaction(tx); // Re-broadcast to peers
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
bool Network::sendData(const std::string &peer, const std::string &data) {
    auto it = peerSockets.find(peer);
    if (it == peerSockets.end() || !it->second || !it->second->is_open()) {
        std::cerr << "❌ [ERROR] Peer socket not found or closed: " << peer << "\n";
        return false;
    }

    try {
        std::string finalMessage = data;

        if (finalMessage.empty()) {
            std::cerr << "⚠️ [sendData] Skipping empty message to: " << peer << "\n";
            return false;
        }

        // 🔧 Strip any trailing newlines before appending a single \n
        while (!finalMessage.empty() && 
               (finalMessage.back() == '\n' || finalMessage.back() == '\r')) {
            finalMessage.pop_back();
        }

        finalMessage += '\n';  // ✅ Ensure newline-terminated message

        boost::asio::write(*it->second, boost::asio::buffer(finalMessage));
        std::cout << "📡 [DEBUG] Sent message to " << peer
                  << ": " << finalMessage.substr(0, 100) << "...\n";
        return true;

    } catch (const std::exception &e) {
        std::cerr << "❌ [ERROR] Failed to send data to " << peer << ": " << e.what() << "\n";
        {
            ScopedLockTracer tracer("sendData");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            peerSockets.erase(peer);
            std::cerr << "🧹 [INFO] Removed dead peer: " << peer << "\n";
        }
        return false;
    }
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
bool Network::connectToNode(const std::string &ip, int port) {
    try {
        auto socketPtr = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::ip::tcp::resolver resolver(ioContext);
        boost::asio::ip::tcp::resolver::query query(ip, std::to_string(port));
        auto endpoints = resolver.resolve(query);
        boost::asio::connect(*socketPtr, endpoints);

        // ✅ USE THE INPUT VALUES AS PEER KEY — NOT remote_endpoint()!
        std::string peerKey = ip + ":" + std::to_string(port);

        {
            ScopedLockTracer tracer("connectToNode");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            if (peerSockets.find(peerKey) != peerSockets.end()) {
                std::cout << "🔁 Already connected to peer: " << peerKey << "\n";
                return false;
            }
        }

        // ✅ Enhanced handshake
        Json::Value handshake;
        handshake["type"] = "handshake";
        handshake["port"] = std::to_string(this->port);
        handshake["version"] = "1.0.0";
        handshake["network_id"] = "mainnet";
        handshake["capabilities"] = Json::arrayValue;
        handshake["capabilities"].append("full");
        handshake["capabilities"].append("miner");

        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";  // Compact output
        std::string payload = Json::writeString(builder, handshake);
        if (!payload.empty() && payload.back() != '\n') payload += "\n";

        boost::asio::write(*socketPtr, boost::asio::buffer(payload));

        {
            ScopedLockTracer tracer("connectToNode");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            peerSockets[peerKey] = socketPtr;
            if (peerManager) peerManager->connectToPeer(peerKey);
        }

        std::cout << "✅ Connected to new peer: " << peerKey << "\n";

        std::thread(&Network::handlePeer, this, socketPtr).detach();

        std::cout << "📡 [SYNC] Sending REQUEST_BLOCKCHAIN to " << peerKey << "\n";
        sendData(peerKey, "ALYN|REQUEST_BLOCKCHAIN");

        return true;

    } catch (const std::exception &e) {
        std::cerr << "❌ Error connecting to node: " << e.what() << "\n";
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
    std::cerr << "⚠️ [WARNING] peers.txt not found. Attempting auto-discovery...\n";
    scanForPeers();
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line.find(":") == std::string::npos) continue;

    if (line == "127.0.0.1:" + std::to_string(port)) {
      std::cerr << "⚠️ Skipping self-peer: " << line << "\n";
      continue;
    }

    std::string ip = line.substr(0, line.find(":"));
    int portVal = std::stoi(line.substr(line.find(":") + 1));

    if (connectToNode(ip, portVal)) {
      std::cout << "✅ Peer loaded & connected: " << line << "\n";
    } else {
      std::cerr << "⚠️ Failed to connect to loaded peer: " << line << "\n";
    }
  }

  file.close();
  std::cout << "✅ Peers loaded and connected successfully!\n";
}

//
void Network::scanForPeers() {
    std::vector<std::string> potentialPeers = fetchPeersFromDNS("peers.alyncoin.com");

    std::cout << "🔍 Scanning for active AlynCoin nodes from DNS..." << std::endl;

    for (const auto &peer : potentialPeers) {
        std::string ip = peer.substr(0, peer.find(":"));
        int peerPort = std::stoi(peer.substr(peer.find(":") + 1));

        // ✅ Avoid connecting to self to prevent bind errors
        if (peerPort == this->port && ip == "127.0.0.1")
            continue;

        if (connectToNode(ip, peerPort)) {
            std::cout << "✅ Found & connected to: " << peer << std::endl;
            savePeers();  // Save only after successful connection
        }
    }

    if (peerSockets.empty()) {
        std::cout << "⚠️ No active peers found. Will retry periodically." << std::endl;
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

// ✅ Always send full chain regardless of length (even genesis-only)
void Network::sendFullChain(const std::string &peer) {
    Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true, false);

    const std::vector<Block> &chain = blockchain.getChain();
    alyncoin::BlockchainProto proto;

    for (const auto &blk : chain) {
        try {
            *proto.add_blocks() = blk.toProtobuf();
        } catch (const std::exception &e) {
            std::cerr << "⚠️ [sendFullChain] Skipping block due to serialization error: " << e.what() << "\n";
        }
    }

    std::string rawData;
    if (!proto.SerializeToString(&rawData)) {
        std::cerr << "❌ [ERROR] Failed to serialize BlockchainProto to string.\n";
        return;
    }

    std::string base64Encoded = Crypto::base64Encode(rawData);
    std::string message = "ALYN|BLOCKCHAIN_DATA|" + base64Encoded;

    std::shared_ptr<tcp::socket> targetSocket;

    {
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        auto it = peerSockets.find(peer);
        if (it != peerSockets.end() && it->second && it->second->is_open()) {
            targetSocket = it->second;
        }
    }

    if (targetSocket) {
        try {
            boost::asio::write(*targetSocket, boost::asio::buffer(message + "\n"));
            std::cout << "📡 [SYNC] Sent blockchain (" << chain.size()
                      << " blocks, " << base64Encoded.length() << " chars) to " << peer << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ [sendFullChain] Socket write failed for " << peer << ": " << e.what() << "\n";
        }
    } else {
        std::cerr << "❌ [sendFullChain] No open socket for peer: " << peer << "\n";
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
