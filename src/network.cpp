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

        acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port), ec);
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

        // ✅ Prevent crash due to null or invalid blacklist DB
        if (!blacklistPtr) {
	    std::cerr << "❌ [FATAL] PeerBlacklist is null! Cannot initialize network.\n";
	    throw std::runtime_error("PeerBlacklist is null");
	}
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

    while (isRunning) {
        std::shared_ptr<tcp::socket> socket = std::make_shared<tcp::socket>(ioContext);
        boost::system::error_code ec;
        acceptor.accept(*socket, ec);

        if (ec) {
            std::cerr << "❌ [Network] Accept error: " << ec.message() << "\n";
            continue;
        }

        // 👇 Handshake will be parsed in handlePeer()
        std::thread(&Network::handlePeer, this, socket).detach();
    }
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
            Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).saveToDB();
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

    std::string peerKey = ip + ":" + std::to_string(port);

    {
        ScopedLockTracer tracer("connectToPeer");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        if (peerSockets.find(peerKey) != peerSockets.end()) {
            std::cout << "🔁 Already connected to peer: " << peerKey << "\n";
            return;
        }
    }

    try {
        boost::asio::ip::tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(ip, std::to_string(port));

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::connect(*socket, endpoints);

        {
            ScopedLockTracer tracer("connectToPeer");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            peerSockets[peerKey] = socket;
        }

        std::cout << "✅ Connected to peer: " << peerKey << "\n";

        // Send handshake
        Json::Value handshake;
        handshake["type"] = "handshake";
        handshake["port"] = this->port;
        Json::StreamWriterBuilder writer;
        std::string handshakeStr = Json::writeString(writer, handshake);
        boost::asio::write(*socket, boost::asio::buffer(handshakeStr + "\n"));

        // Begin handling peer
        std::thread([this, socket]() {
            this->handlePeer(socket);
        }).detach();

    } catch (const std::exception &e) {
        std::cerr << "❌ Failed to connect to peer: " << peerKey
                  << " | Error: " << e.what() << std::endl;
    }
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

    Blockchain &chain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

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

    // 4) Validate entire fork safety BEFORE touching chain
    if (!chain.verifyForkSafety(receivedBlocks)) {
        std::cerr << "⚠️ [Network] Received fork is invalid or unsafe. Saving for debug.\n";
        chain.saveForkView(receivedBlocks); // Save rejected fork
        return;
    }

    // 5) Merge using difficulty-aware fork logic
    chain.compareAndMergeChains(receivedBlocks);
}

// Handle Peer
void Network::handlePeer(std::shared_ptr<tcp::socket> socket) {
    std::string peerId;
    std::string reverseIP;
    int reversePort = 0;

    try {
        boost::asio::streambuf handshakeBuf;
        boost::asio::read_until(*socket, handshakeBuf, "\n");

        std::istream handshakeStream(&handshakeBuf);
        std::string handshakeLine;
        std::getline(handshakeStream, handshakeLine);

        Json::Value root;
        Json::CharReaderBuilder reader;
        std::string errs;
        std::istringstream ss(handshakeLine);

        if (Json::parseFromStream(reader, ss, &root, &errs) &&
            root.isMember("type") && root["type"].asString() == "handshake" &&
            root.isMember("port")) {

            std::string senderIP = socket->remote_endpoint().address().to_string();
            std::string senderPort = root["port"].asString();
            peerId = senderIP + ":" + senderPort;

            // Only assign reverseIP/port if port is valid (from handshake)
            reverseIP = senderIP;
            reversePort = std::stoi(senderPort);

        } else {
            std::string senderIP = socket->remote_endpoint().address().to_string();
            int randomPort = socket->remote_endpoint().port();
            peerId = senderIP + ":" + std::to_string(randomPort);

            {
                ScopedLockTracer tracer("handlePeer");
                std::lock_guard<std::timed_mutex> lock(peersMutex);
                peerSockets[peerId] = socket;
                if (peerManager) peerManager->connectToPeer(peerId);
            }

            std::cerr << "⚠️ [handlePeer] No handshake, treating first line as regular message: "
                      << handshakeLine << "\n";
            handleIncomingData(peerId, handshakeLine);
        }

    } catch (const std::exception &e) {
        std::cerr << "⚠️ [handlePeer] Couldn't parse peer handshake: " << e.what() << "\n";
        return;
    }

    {
        ScopedLockTracer tracer("handlePeer");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        peerSockets[peerId] = socket;
        if (peerManager) peerManager->connectToPeer(peerId);
        std::cout << "✅ [handlePeer] Incoming peer registered: " << peerId << "\n";

        std::cout << "📡 [SYNC] Sending REQUEST_BLOCKCHAIN to " << peerId << "\n";
        sendData(peerId, "REQUEST_BLOCKCHAIN");
    }

    if (!reverseIP.empty() && reversePort > 0 && reversePort <= 65535) {
        std::string selfIP = "127.0.0.1";
        if (!(reverseIP == selfIP && reversePort == this->port)) {
            std::cout << "🔁 [ReverseConnect] Connecting back to " << reverseIP << ":" << reversePort << "\n";
            connectToPeer(reverseIP, reversePort);  // ✅ done after lock
        }
    }

    // ⏳ Begin receiving data
    boost::asio::streambuf buf;
    const size_t MAX_BUFFER_SIZE = 4 * 1024 * 1024;

    try {
        while (isRunning) {
            boost::system::error_code ec;
            std::size_t bytes = boost::asio::read_until(*socket, buf, "\n", ec);

            if (ec == boost::asio::error::eof || ec) {
                std::cerr << "🔌 Peer disconnected or read error: " << peerId << " (" << ec.message() << ")\n";
                break;
            }

            if (buf.size() > MAX_BUFFER_SIZE) {
                std::cerr << "❌ [handlePeer] Buffer overflow from " << peerId << ". Disconnecting.\n";
                break;
            }

            std::istream is(&buf);
            std::string line;
            std::getline(is, line);

            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            handleIncomingData(peerId, line);
        }

    } catch (const std::exception &e) {
        std::cerr << "⚠️ Exception in handlePeer for " << peerId << ": " << e.what() << "\n";
    }

    {
        ScopedLockTracer tracer("handlePeer");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        peerSockets.erase(peerId);
    }

    std::cout << "🔌 Cleaned up peer socket: " << peerId << "\n";
}

// ✅ **Run Network Thread**
void Network::run() {
    serverThread = std::thread([this]() { startServer(); });
    serverThread.detach();

    std::this_thread::sleep_for(std::chrono::seconds(2));

    requestPeerList();
    scanForPeers();
    autoMineBlock();

    // 🔁 Live periodic sync every 15 seconds
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            periodicSync();
        }
    }).detach();

    // 🔁 Cleanup dead peers every 20 seconds
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(20));
            cleanupPeers();
        }
    }).detach();
}

// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
    std::vector<std::string> peers;

    if (!std::filesystem::exists("data"))
        std::filesystem::create_directory("data");

    std::ifstream file("data/peers.list");
    if (!file) {
        std::cerr << "⚠️ [WARNING] No known peers found. Bootstrap required!" << std::endl;
        return peers;
    }

    std::string peer;
    while (std::getline(file, peer)) {
        peer.erase(std::remove_if(peer.begin(), peer.end(), ::isspace), peer.end());
        if (!peer.empty() && peer[0] != '#') {
            peers.push_back(peer);
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
void Network::handleIncomingData(const std::string &senderIP, std::string data) {
    if (data.empty()) {
        std::cerr << "❌ [ERROR] Received empty data from peer: " << senderIP << "\n";
        return;
    }

    // Clean input
    data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());
    data.erase(std::remove(data.begin(), data.end(), '\r'), data.end());

    const std::string chainPrefix = "BLOCKCHAIN_DATA|";
    const std::string blockPrefix = "BLOCK_DATA|";

    // ✅ Full sync request
    if (data == "REQUEST_BLOCKCHAIN") {
        std::cout << "📡 [INFO] REQUEST_BLOCKCHAIN received from " << senderIP << "\n";
        sendFullChain(senderIP);
        return;
    }

    // ✅ Full chain reception
    if (data.rfind(chainPrefix, 0) == 0) {
        std::string rawData = Crypto::base64Decode(data.substr(chainPrefix.size()));
        if (rawData.empty()) {
            std::cerr << "❌ [SYNC] Base64 decode failed.\n";
            return;
        }

        std::vector<Block> forkChain;
        auto& blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true, false);

        if (!blockchain.deserializeBlockchainForkView(rawData, forkChain)) {
            std::cerr << "❌ [SYNC] Failed to deserialize fork chain.\n";
            return;
        }

        std::cout << "🔍 [SYNC] Received fork of " << forkChain.size() << " blocks.\n";
        blockchain.setPendingForkChain(forkChain);
        blockchain.compareAndMergeChains(forkChain);  // merge now
        blockchain.clearPendingForkChain();
        return;
    }

    // ✅ Single block broadcast
    if (data.rfind(blockPrefix, 0) == 0) {
        try {
            std::string base64Block = data.substr(blockPrefix.size());
            std::string serialized;
            try {
                serialized = Crypto::base64Decode(base64Block);
            } catch (...) {
                std::cerr << "❌ [BLOCK_DATA] Base64 decode failed.\n";
                return;
            }

            alyncoin::BlockProto proto;
            if (!proto.ParseFromString(serialized)) {
                std::cerr << "❌ [BLOCK_DATA] Protobuf parse failed.\n";
                return;
            }

            Block blk;
            try {
                blk = Block::fromProto(proto, /*allowPartial=*/true);
            } catch (const std::exception& e) {
                std::cerr << "❌ [BLOCK_DATA] fromProto failed: " << e.what() << "\n";
                return;
            }

            std::string hashPreview = blk.getHash().empty()
                ? "<empty>"
                : blk.getHash().substr(0, std::min<size_t>(12, blk.getHash().size()));

            std::cerr << "📥 [BLOCK_DATA] Parsed block. Index: " << blk.getIndex()
                      << ", Hash: " << hashPreview << "...\n";

            handleNewBlock(blk);

        } catch (const std::exception& e) {
            std::cerr << "❌ [BLOCK_DATA] Fatal error: " << e.what() << "\n";
        }
        return;
    }

    // ✅ JSON messages (height, tip, transaction)
    if (!data.empty() && data.front() == '{' && data.back() == '}') {
        try {
            Json::Value root;
            std::istringstream s(data);
            Json::CharReaderBuilder rb;
            std::string errs;
            if (!Json::parseFromStream(rb, s, &root, &errs)) {
                std::cerr << "❌ [ERROR] JSON parse failed: " << errs << "\n";
                return;
            }

            auto& blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);
            std::string type = root["type"].asString();

            if (type == "height_request") {
                Json::Value res;
                res["type"] = "height_response";
                res["data"] = blockchain.getHeight();
                sendData(senderIP, Json::writeString(Json::StreamWriterBuilder(), res));
                return;
            }

            if (type == "tip_hash_request") {
                Json::Value res;
                res["type"] = "tip_hash_response";
                res["data"] = blockchain.getLatestBlockHash();
                sendData(senderIP, Json::writeString(Json::StreamWriterBuilder(), res));
                return;
            }

            // ✅ Incoming transaction (fallback)
            Transaction tx = Transaction::deserialize(data);
            if (tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
                blockchain.addTransaction(tx);
                blockchain.savePendingTransactionsToDB();
                std::cout << "✅ [TX] Accepted transaction from " << senderIP << "\n";
            } else {
                std::cerr << "❌ [TX] Invalid transaction from " << senderIP << "\n";
            }

        } catch (const std::exception& e) {
            std::cerr << "❌ [JSON] Error parsing: " << e.what() << "\n";
        }
        return;
    }

    // Unknown message fallback
    std::cerr << "⚠️ [handleIncomingData] Unknown or unhandled message from "
              << senderIP << ": " << data.substr(0, std::min<size_t>(100, data.size())) << "\n";
}


// ✅ **Broadcast a mined block to all peers*
void Network::broadcastBlock(const Block &block, bool force) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);
    std::string base64Block = Crypto::base64Encode(serializedBlock);
    std::string message = "BLOCK_DATA|" + base64Block + "\n";

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

  Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).addTransaction(tx);
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
                sendData(peer.first, "REQUEST_BLOCKCHAIN");
            }
            return;
        }
    }

    // 3) Index ordering
    if (newBlock.getIndex() < expectedIndex) {
        std::cerr << "⚠️ [Node] Ignoring duplicate or old block.\n";
        return;
    }
    if (newBlock.getIndex() > expectedIndex) {
        std::cerr << "⚠️ [Node] Received future block. Buffering.\n";
        futureBlockBuffer[newBlock.getIndex()] = newBlock;

        if (newBlock.getIndex() > expectedIndex + 5) {
            for (const auto& peer : peerSockets) {
                sendData(peer.first, "REQUEST_BLOCKCHAIN");
            }
        }
        return;
    }

    // 4) Signature validation
    try {
        auto msgBytes = newBlock.getSignatureMessage();

        std::vector<unsigned char> sigDil(newBlock.getDilithiumSignature().begin(), newBlock.getDilithiumSignature().end());
        std::vector<unsigned char> pubDil = newBlock.getPublicKeyDilithium();

        if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
            std::cerr << "❌ Dilithium signature verification failed!\n";
            return;
        }

        std::vector<unsigned char> sigFal(newBlock.getFalconSignature().begin(), newBlock.getFalconSignature().end());
        std::vector<unsigned char> pubFal = newBlock.getPublicKeyFalcon();

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

    // 6) Process buffered future blocks
    uint64_t nextIndex = blockchain.getLatestBlock().getIndex() + 1;
    while (futureBlockBuffer.count(nextIndex)) {
        auto nextBlk = futureBlockBuffer[nextIndex];
        futureBlockBuffer.erase(nextIndex);
        std::cout << "⏩ Processing buffered block: " << nextIndex << "\n";
        handleNewBlock(nextBlk);
        nextIndex++;
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
        if (finalMessage.back() != '\n') finalMessage += "\n";  // Ensure newline

        boost::asio::write(*it->second, boost::asio::buffer(finalMessage));
        std::cout << "📡 [DEBUG] Sent message to " << peer << ": " << finalMessage.substr(0, 100) << "...\n";
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

    if (!sendData(peer, "REQUEST_BLOCKCHAIN")) {
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
    ioContext.run(); // ✅ Only run ioContext, listenerThread already started
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
    std::string peerKey = ip + ":" + std::to_string(port);

    {
        ScopedLockTracer tracer("connectToNode");
        std::lock_guard<std::timed_mutex> lock(peersMutex);
        if (peerSockets.find(peerKey) != peerSockets.end()) {
            std::cout << "🔁 Already connected to peer: " << peerKey << "\n";
            return false;
        }
    }

    try {
        auto socketPtr = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::ip::tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(ip, std::to_string(port));
        boost::asio::connect(*socketPtr, endpoints);

        // ✅ Must send handshake before any message
        Json::Value handshake;
        handshake["type"] = "handshake";
        handshake["port"] = std::to_string(this->port);
        std::string payload = Json::writeString(Json::StreamWriterBuilder(), handshake);
        if (!payload.empty() && payload.back() != '\n') payload += "\n";

        boost::asio::write(*socketPtr, boost::asio::buffer(payload));

        {
            ScopedLockTracer tracer("connectToNode");
            std::lock_guard<std::timed_mutex> lock(peersMutex);
            peerSockets[peerKey] = socketPtr;
        }

        std::cout << "✅ Connected to new peer: " << peerKey << "\n";

        // ✅ Start listening to that peer
        std::thread(&Network::handlePeer, this, socketPtr).detach();

        // 🚀 Immediately request blockchain from newly connected peer
        std::cout << "📡 [SYNC] Sending REQUEST_BLOCKCHAIN to " << peerKey << "\n";
        sendData(peerKey, "REQUEST_BLOCKCHAIN");

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
  msg["data"] = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).getLatestBlock().getIndex();
  msg["note"] =
      "Supports Dilithium + Falcon signatures"; // Optional extra clarity
  Json::StreamWriterBuilder writer;
  sendData(peerIP, Json::writeString(writer, msg));
}
//
void Network::handleReceivedBlockIndex(const std::string &peerIP, int peerBlockIndex) {
    int localIndex = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).getLatestBlock().getIndex();
    
    if (localIndex <= 0) { // Only genesis present
        std::cout << "⚠️ [Node] Only Genesis block found locally. Requesting full blockchain sync from " << peerIP << "\n";
        sendData(peerIP, "REQUEST_BLOCKCHAIN");
        return;
    }
    
    if (peerBlockIndex > localIndex) {
        std::cout << "📡 Peer " << peerIP
                  << " has longer chain. Requesting sync...\n";
        sendData(peerIP, "REQUEST_BLOCKCHAIN");
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
    std::vector<std::string> potentialPeers = {
        "127.0.0.1:8080",
        "127.0.0.1:8334",
        "192.168.1.2:8335"  // Optional external test nodes
    };

    std::cout << "🔍 Scanning for active AlynCoin nodes..." << std::endl;

    for (const auto &peer : potentialPeers) {
        std::string ip = peer.substr(0, peer.find(":"));
        int peerPort = std::stoi(peer.substr(peer.find(":") + 1));

        // ✅ Avoid connecting to self to prevent bind errors
        if (peerPort == this->port)
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
    Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

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
    sendData(peerIP, "BLOCK_DATA|" + base64Block);  // ✅ NOW base64 encoded!

    std::cout << "📡 [LIVE BROADCAST] Latest block sent to " << peerIP << " (Dilithium + Falcon signatures included)\n";
}

// ✅ Always send full chain regardless of length (even genesis-only)
void Network::sendFullChain(const std::string &peer) {
    Blockchain &blockchain = Blockchain::getInstance(this->port, DBPaths::getBlockchainDB(), true);

    // Serialize all blocks
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
    std::string message = "BLOCKCHAIN_DATA|" + base64Encoded;

    std::cout << "📡 [SYNC] Sending blockchain (" << base64Encoded.length()
              << " chars, Blocks: " << chain.size() << ") to " << peer << "\n";

    if (!sendData(peer, message)) {
        std::cerr << "❌ [ERROR] Full chain send failed to peer: " << peer << "\n";
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

      // Optional: send a ping
      boost::system::error_code ec;
      peer.second->send(boost::asio::buffer("PING"), 0, ec);
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
  Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).addRollupBlock(rollupBlock);
  std::cout << "✅ Rollup block received and added to blockchain!\n";
}
//
void Network::handleNewRollupBlock(const RollupBlock &newRollupBlock) {
  if (Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).isRollupBlockValid(newRollupBlock)) {
    Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).addRollupBlock(newRollupBlock);
    std::lock_guard<std::mutex> lock(blockchainMutex);
    Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).saveRollupChain();
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
