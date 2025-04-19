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
#include <json/json.h>
#include <sstream>
#include <thread>
#include <unordered_set>
#include <vector>
#include "proto_utils.h"

#define ENABLE_DEBUG 0
namespace fs = std::filesystem;
Network* Network::instancePtr = nullptr;

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
        acceptor.accept(*socket);

        std::string senderIP = socket->remote_endpoint().address().to_string();
        std::string peerAddr = senderIP + ":" + std::to_string(socket->remote_endpoint().port());

        {
            std::lock_guard<std::mutex> lock(peersMutex);
            if (peerSockets.find(peerAddr) == peerSockets.end()) {
                peerSockets[peerAddr] = socket;
                if (peerManager) {
                    peerManager->connectToPeer(peerAddr);  // ✅ Register in PeerManager
                }
                savePeers();
            }
        }

        std::cout << "📡 New peer connected: " << peerAddr << std::endl;
        std::thread(&Network::handlePeer, this, socket).detach();
    }
}

//

void Network::start() {
  startServer();   // Start listening for connections
  syncWithPeers(); // Automatically sync with peers at startup ✅
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
        std::vector<unsigned char> sigDil = Crypto::fromHex(minedBlock.getDilithiumSignature());
        std::vector<unsigned char> pubDil = Crypto::getPublicKeyDilithium(minedBlock.getMinerAddress());

        std::vector<unsigned char> sigFal = Crypto::fromHex(minedBlock.getFalconSignature());
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
  std::lock_guard<std::mutex> lock(peersMutex); // Thread safety
  for (const auto &peer : peerSockets) {
    sendMessageToPeer(peer.first, message);
  }
}

// ✅ **Getter function for syncing status**
bool Network::isSyncing() const { return syncing; }
// ✅ **Connect to a peer and send a message**
void Network::sendMessage(std::shared_ptr<boost::asio::ip::tcp::socket> socket,
                          const std::string &message) {
  try {
    if (!socket || !socket->is_open()) {
      return;
    }

    boost::asio::write(*socket, boost::asio::buffer(message + "\n"), boost::asio::transfer_all());
    std::cout << "📡 Sent message: " << message << std::endl;
  } catch (const std::exception &e) {
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

    Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

    for (const auto &[peer, socket] : peerSockets) {
        if (peer.empty()) continue;

        std::cout << "📡 [DEBUG] Requesting blockchain sync from " << peer << "...\n";
        std::string base64Response = requestBlockchainSync(peer);

        if (base64Response.empty()) {
            std::cerr << "❌ [ERROR] No data received from " << peer << "!\n";
            continue;
        }

        std::cout << "📡 [DEBUG] Raw Blockchain Data from Peer (" << peer
                  << "): " << base64Response.substr(0, 100) << "...\n";

        std::string syncTempPath = "/tmp/alyncoin_sync_temp";
        Blockchain tempChain(0, syncTempPath, true, true);
        tempChain.clear();

        if (!tempChain.deserializeBlockchainBase64(base64Response)) {
            std::cerr << "❌ [ERROR] Failed to parse blockchain data from peer: " << peer << "\n";
            continue;
        }

        auto safeBinaryToString = [](const std::vector<uint8_t> &vec, size_t maxLen = 100000) -> std::string {
            if (vec.size() > maxLen) {
                std::cerr << "❌ [syncWithPeers] zkProof too large (" << vec.size() << " bytes). Skipping.\n";
                return "";
            }
            return std::string(vec.begin(), vec.end());
        };

        bool zkValid = true;
        for (const auto &blk : tempChain.getChain()) {
            if (blk.getBlockSignature().empty()) {
                std::cerr << "⚠️ Skipping block with empty signature during sync. Hash: " << blk.getHash() << "\n";
                continue;
            }

            std::string proofStr = safeBinaryToString(blk.getZkProof(), 100000);
            if (proofStr.empty()) {
                zkValid = false;
                std::cerr << "❌ [ERROR] Invalid or oversized zk-STARK proof during sync from peer: " << peer << "\n";
                break;
            }

            if (!WinterfellStark::verifyProof(proofStr, blk.getHash(),
                                              blk.getPreviousHash(), blk.getTransactionsHash())) {
                zkValid = false;
                std::cerr << "❌ [ERROR] Invalid zk-STARK proof detected in synced block from: " << peer << "\n";
                break;
            }

            std::vector<unsigned char> msgBytes = blk.getSignatureMessage();
            auto sigDil = Crypto::fromHex(blk.getDilithiumSignature());
            auto pubDil = std::vector<unsigned char>(blk.getPublicKeyDilithium().begin(), blk.getPublicKeyDilithium().end());
            auto sigFal = Crypto::fromHex(blk.getFalconSignature());
            auto pubFal = std::vector<unsigned char>(blk.getPublicKeyFalcon().begin(), blk.getPublicKeyFalcon().end());

            bool dilPass = Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil);
            bool falPass = Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal);

            if (!dilPass || !falPass) {
                zkValid = false;
                std::cerr << "❌ [ERROR] Signature verification failed in block from: " << peer << "\n";
                break;
            }
        }

        if (zkValid && tempChain.getBlockCount() > blockchain.getBlockCount()) {
            std::cout << "✅ Valid zk-STARK chain received. Merging...\n";
            blockchain.mergeWith(tempChain);
            blockchain.saveToDB();
        } else if (!zkValid) {
            std::cerr << "❌ Rejected chain due to invalid zk-STARK proofs or signatures.\n";
        } else {
            std::cout << "✅ Local chain is up-to-date. No merge needed.\n";
        }

        std::filesystem::remove_all(syncTempPath);
    }
}

//
void Network::connectToPeer(const std::string &ip, short port) {
    std::string peerKey = ip + ":" + std::to_string(port);

    {
        std::lock_guard<std::mutex> lock(peersMutex);
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
            std::lock_guard<std::mutex> lock(peersMutex);
            peerSockets[peerKey] = socket;
        }

        std::cout << "✅ Connected to peer: " << peerKey << "\n";

    } catch (const std::exception &e) {
        std::cerr << "❌ Failed to connect to peer: " << peerKey
                  << " | Error: " << e.what() << std::endl;
    }
}

// ✅ **Broadcast peer list to all connected nodes**
void Network::broadcastPeerList() {
    std::lock_guard<std::mutex> lock(peersMutex);
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

    std::string decodedData = Crypto::base64Decode(data);
    if (decodedData.empty()) {
        std::cerr << "[ERROR] Failed to base64 decode blockchain data from " << senderIP << "\n";
        return;
    }

    Blockchain tempChain(0, "/tmp/alyncoin_sync_temp", true, true);
    tempChain.clear();

    if (!tempChain.deserializeBlockchain(decodedData)) {
        std::cerr << "[ERROR] Failed to deserialize blockchain data from " << senderIP << "!\n";
        return;
    }

    bool valid = true;
    for (const auto &blk : tempChain.getChain()) {
        std::string proofStr(blk.getZkProof().begin(), blk.getZkProof().end());
        if (!WinterfellStark::verifyProof(proofStr, blk.getHash(), blk.getPreviousHash(), blk.getTxRoot())) {
            std::cerr << "[ERROR] Invalid zk-STARK proof in block from " << senderIP << "\n";
            valid = false;
            break;
        }

        std::vector<unsigned char> msgBytes = blk.getSignatureMessage();

        auto sigDil = Crypto::fromHex(blk.getDilithiumSignature());
        auto pubDil = std::vector<unsigned char>(blk.getPublicKeyDilithium().begin(), blk.getPublicKeyDilithium().end());
        if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
            std::cerr << "[ERROR] Invalid Dilithium signature in block from " << senderIP << "\n";
            valid = false;
            break;
        }

        auto sigFal = Crypto::fromHex(blk.getFalconSignature());
        auto pubFal = std::vector<unsigned char>(blk.getPublicKeyFalcon().begin(), blk.getPublicKeyFalcon().end());
        if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
            std::cerr << "[ERROR] Invalid Falcon signature in block from " << senderIP << "\n";
            valid = false;
            break;
        }
    }

    Blockchain &mainChain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);
    if (valid && tempChain.getBlockCount() > mainChain.getBlockCount()) {
        std::cout << "✅ Replacing local chain with valid, longer chain from " << senderIP << "\n";
        mainChain.replaceChain(tempChain.getChain());
        mainChain.saveToDB();
    } else {
        std::cerr << "❌ Rejected chain from " << senderIP << ": invalid or shorter.\n";
    }
}
// network node
bool Network::connectToNode(const std::string &ip, int port) {
    std::string peerKey = ip + ":" + std::to_string(port);

    {
        std::lock_guard<std::mutex> lock(peersMutex);
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

        {
            std::lock_guard<std::mutex> lock(peersMutex);
            peerSockets[peerKey] = socketPtr;
        }

        std::cout << "✅ Connected to new peer: " << peerKey << "\n";

        // ✅ Start handling the connection
        std::thread(&Network::handlePeer, this, socketPtr).detach();

        // Request their chain
        sendData(peerKey, "REQUEST_BLOCKCHAIN");
        return true;

    } catch (const std::exception &e) {
        std::cerr << "❌ Error connecting to node: " << e.what() << std::endl;
        return false;
    }
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
}
//
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

    connectToNode(ip, port); // Will update socket inside
  }
}

//
void Network::periodicSync() {
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(10)); // Adjust frequency if needed
            Blockchain &localChain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

            for (const auto &peer : peerSockets) {
                const std::string &peerAddr = peer.first;
                if (peerAddr.empty()) continue;

                std::cout << "📡 [DEBUG] Periodic sync request to " << peerAddr << "\n";

                std::string response = requestBlockchainSync(peerAddr);
                if (response.empty()) {
                    std::cerr << "⚠️ [WARNING] Skipping peer " << peerAddr << " due to empty response.\n";
                    continue;
                }

                std::string decoded = Crypto::base64Decode(response);
                if (decoded.empty()) {
                    std::cerr << "⚠️ [WARNING] Invalid base64 response from peer: " << peerAddr << "\n";
                    continue;
                }

                Blockchain tempChain(0, "/tmp/alyncoin_sync_temp", true, true);
                tempChain.clear();

                if (!tempChain.deserializeBlockchainBase64(decoded)) {
                    std::cerr << "❌ [ERROR] Failed to parse blockchain from peer: " << peerAddr << "\n";
                    continue;
                }

                bool valid = true;
                for (const auto &blk : tempChain.getChain()) {
                    std::string proofStr(blk.getZkProof().begin(), blk.getZkProof().end());
                    if (!WinterfellStark::verifyProof(proofStr, blk.getHash(), blk.getPreviousHash(), blk.getTxRoot())) {
                        std::cerr << "❌ [ERROR] Invalid zk-STARK proof in block from: " << peerAddr << "\n";
                        valid = false;
                        break;
                    }
                }

                if (valid && tempChain.getBlockCount() > localChain.getBlockCount()) {
                    std::cout << "✅ Periodic sync accepted. Replacing local chain with chain from " << peerAddr << "\n";
                    localChain.replaceChain(tempChain.getChain());
                    localChain.saveToDB();
                } else if (!valid) {
                    std::cerr << "❌ Rejected chain from " << peerAddr << " due to invalid zk-STARK proofs.\n";
                } else {
                    std::cout << "ℹ️ Local chain is up-to-date. No sync needed with " << peerAddr << "\n";
                }
            }
        }
    }).detach();
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
// ✅ **Handle Incoming Data with Protobuf Validation**
void Network::handleIncomingData(const std::string &senderIP, std::string data) {
    if (data.empty()) {
        std::cerr << "[ERROR] Received empty data from peer: " << senderIP << "!\n";
        return;
    }

    data.erase(std::remove(data.begin(), data.end(), '\n'), data.end());
    data.erase(std::remove(data.begin(), data.end(), '\r'), data.end());

    std::cout << "[DEBUG] Incoming Data (" << senderIP << ") Length: " << data.length() << "\n";
    std::cout << "[DEBUG] First 200 bytes: " << data.substr(0, 200) << "\n";

    // 🔄 Sync request
    if (data == "REQUEST_BLOCKCHAIN") {
        std::cout << "📡 [INFO] REQUEST_BLOCKCHAIN received from " << senderIP << "\n";

        std::string matchedPeer;
        std::shared_ptr<tcp::socket> senderSocket = nullptr;
        {
            std::lock_guard<std::mutex> lock(peersMutex);
            for (const auto &[peerAddr, sock] : peerSockets) {
                if (peerAddr.find(senderIP) != std::string::npos) {
                    matchedPeer = peerAddr;
                    senderSocket = sock;
                    break;
                }
            }
        }

        if (senderSocket && blockchain) {
            std::string rawData;
            if (blockchain->serializeBlockchain(rawData)) {
                std::string base64EncodedData = Crypto::base64Encode(rawData);
                std::string response = "BLOCKCHAIN_DATA|" + base64EncodedData;
                sendMessage(senderSocket, response);
                std::cout << "✅ Sent blockchain data back to peer " << senderIP << "\n";
            } else {
                std::cerr << "❌ Failed to serialize blockchain for peer " << senderIP << "\n";
            }
        } else {
            std::cerr << "❌ [ERROR] Could not resolve peer socket for sender: " << senderIP << "\n";
        }
        return;
    }

    // ✅ Respond to height request
    if (data == R"({\"type\": \"height_request\"})") {
        Json::Value res;
        res["type"] = "height_response";
        res["data"] = blockchain->getHeight();
        Json::StreamWriterBuilder writer;
        sendData(senderIP, Json::writeString(writer, res));
        return;
    }

    // ✅ Respond to tip hash request
    if (data == R"({\"type\": \"tip_hash_request\"})") {
        Json::Value res;
        res["type"] = "tip_hash_response";
        res["data"] = blockchain->getLatestBlockHash();
        Json::StreamWriterBuilder writer;
        sendData(senderIP, Json::writeString(writer, res));
        return;
    }

    // ✅ Live Block Propagation
    const std::string blockPrefix = "BLOCK_DATA|";
    if (data.rfind(blockPrefix, 0) == 0) {
        std::string base64 = data.substr(blockPrefix.length());
        std::string serialized;

        if (base64.empty()) {
            std::cerr << "❌ [ERROR] Empty BLOCK_DATA payload from: " << senderIP << "\n";
            return;
        }

        try {
            serialized = Crypto::base64Decode(base64);
        } catch (const std::exception &e) {
            std::cerr << "❌ [ERROR] Exception during base64Decode for peer " << senderIP << ": " << e.what() << "\n";
            return;
        }

        if (serialized.empty()) {
            std::cerr << "❌ [ERROR] Base64 decode failed or returned empty for peer: " << senderIP << "\n";
            return;
        }

        alyncoin::BlockProto proto;
        if (!proto.ParseFromString(serialized)) {
            std::cerr << "❌ [ERROR] Failed to parse Protobuf Block from peer: " << senderIP << "\n";
            return;
        }

        std::cout << "[DEBUG] Parsed Protobuf Block from peer " << senderIP
                  << " | Index: " << proto.index()
                  << " | Miner: " << proto.miner_address()
                  << " | TXs: " << proto.transactions_size()
                  << " | zkLen: " << proto.zk_stark_proof().size() << "\n";

        try {
            Block newBlock = Block::fromProto(proto, true);
            std::cout << "📥 Received BLOCK_DATA from " << senderIP << ", attempting to validate...\n";
            handleNewBlock(newBlock);
        } catch (const std::exception &e) {
            std::cerr << "❌ [Exception] Error during block parse/validation: " << e.what() << "\n";
            return;
        }

        return;
    }

    // 🔄 Full sync response
    const std::string blockchainPrefix = "BLOCKCHAIN_DATA|";
    if (data.rfind(blockchainPrefix, 0) == 0) {
        std::string encodedData = data.substr(blockchainPrefix.length());
        Blockchain &mainChain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);
        mainChain.clear();

        if (!mainChain.deserializeBlockchainBase64(encodedData)) {
            std::cerr << "❌ [ERROR] Failed to parse blockchain data from peer: " << senderIP << "\n";
            return;
        }

        bool validChain = true;
        for (const auto &blk : mainChain.getChain()) {
            if (blk.getIndex() == 0) {
                std::cout << "⚠️ [WARNING] Genesis block zk-STARK check: zkProof size = " << blk.getZkProof().size() << "\n";
                if (blk.getZkProof().empty()) {
                    std::cerr << "❌ [ERROR] Genesis block has empty zkProof after sync!\n";
                    validChain = false;
                    break;
                }
                continue;
            }

            std::string proofStr(blk.getZkProof().begin(), blk.getZkProof().end());
            if (!WinterfellStark::verifyProof(proofStr, blk.getHash(), blk.getPreviousHash(), blk.getTransactionsHash())) {
                std::cerr << "[ERROR] Invalid zk-STARK proof in synced blockchain from " << senderIP << "\n";
                validChain = false;
                break;
            }

            std::vector<unsigned char> msgBytes = blk.getSignatureMessage();

            auto sigDil = Crypto::fromHex(blk.getDilithiumSignature());
            auto pubDil = std::vector<unsigned char>(blk.getPublicKeyDilithium().begin(), blk.getPublicKeyDilithium().end());
            if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
                std::cerr << "[ERROR] Invalid Dilithium signature in synced blockchain from " << senderIP << "\n";
                validChain = false;
                break;
            }

            auto sigFal = Crypto::fromHex(blk.getFalconSignature());
            auto pubFal = std::vector<unsigned char>(blk.getPublicKeyFalcon().begin(), blk.getPublicKeyFalcon().end());
            if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
                std::cerr << "[ERROR] Invalid Falcon signature in synced blockchain from " << senderIP << "\n";
                validChain = false;
                break;
            }
        }

        if (validChain) {
            std::lock_guard<std::mutex> lock(blockchainMutex);
            mainChain.saveToDB();
            std::cout << "[INFO] ✅ Blockchain sync complete from peer " << senderIP << "\n";
        } else {
            std::cerr << "[ERROR] ❌ Blockchain rejected due to verification failure.\n";
        }

        return;
    }

    // 📨 Fallback: transaction
    try {
        Transaction tx = Transaction::deserialize(data);
        if (tx.isValid(tx.getSenderPublicKeyDilithium(), tx.getSenderPublicKeyFalcon())) {
            blockchain->addTransaction(tx);
            blockchain->savePendingTransactionsToDB();
            std::cout << "[INFO] Transaction accepted from " << senderIP << "\n";
        } else {
            std::cerr << "[ERROR] Invalid transaction received from " << senderIP << "\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "[ERROR] Transaction parse failed from " << senderIP << ": " << e.what() << "\n";
    }
}

// ✅ **Broadcast a mined block to all peers*
void Network::broadcastBlock(const Block &block) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);
    std::string base64Block = Crypto::base64Encode(serializedBlock);
    std::string message = "BLOCK_DATA|" + base64Block;

    std::lock_guard<std::mutex> lock(peersMutex);
    for (const auto &peer : peerSockets) {
        auto socket = peer.second;
        if (socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(message + "\n"));
                std::cout << "📡 [LIVE BROADCAST] Block sent to: " << peer.first << "\n";
            } catch (const std::exception &e) {
                std::cerr << "❌ Failed to send block to " << peer.first << ": " << e.what() << "\n";
            }
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
// Handle new block
void Network::handleNewBlock(const Block &newBlock) {
    Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

    if (!newBlock.hasValidProofOfWork()) {
        std::cerr << "❌ [ERROR] Block PoW check failed!\n";
        return;
    }

    // ✅ Winterfell zk-STARK proof verification
    std::string proofStr(newBlock.getZkProof().begin(), newBlock.getZkProof().end());
    if (!WinterfellStark::verifyProof(
            proofStr,
            newBlock.getHash(),
            newBlock.getPreviousHash(),
            newBlock.getTransactionsHash())) {
        std::cerr << "❌ [ERROR] Invalid zk-STARK proof detected in new block!\n";
        return;
    }

    const int expectedIndex = blockchain.getLatestBlock().getIndex() + 1;

    if (newBlock.getIndex() < expectedIndex) {
        std::cerr << "⚠️ [Node] Ignoring duplicate or old block. Index: "
                  << newBlock.getIndex() << ", Tip Index: " << expectedIndex - 1 << "\n";
        return;
    }

    if (newBlock.getIndex() > expectedIndex) {
        std::cerr << "⚠️ [Node] Received future block. Index: "
                  << newBlock.getIndex() << ", Expected: " << expectedIndex
                  << ". Buffering not yet implemented.\n";
        return;
    }

    if (!blockchain.isValidNewBlock(newBlock)) {
        std::cerr << "❌ Invalid block received! Rejecting.\n";
        return;
    }

    // 🔍 Debug signatures and keys
    std::cout << "[DEBUG] Block hash: " << newBlock.getHash() << "\n";
    std::cout << "[DEBUG] Dilithium Signature Length: " << newBlock.getDilithiumSignature().size() << "\n";
    std::cout << "[DEBUG] Falcon Signature Length: " << newBlock.getFalconSignature().size() << "\n";
    std::cout << "[DEBUG] Public Key Dilithium Length: " << newBlock.getPublicKeyDilithium().size() << "\n";
    std::cout << "[DEBUG] Public Key Falcon Length: " << newBlock.getPublicKeyFalcon().size() << "\n";

    std::vector<unsigned char> msgBytes = newBlock.getSignatureMessage();

    std::vector<unsigned char> sigDil = Crypto::fromHex(newBlock.getDilithiumSignature());
    std::vector<unsigned char> pubDil(newBlock.getPublicKeyDilithium().begin(), newBlock.getPublicKeyDilithium().end());

    if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
        std::cerr << "❌ Dilithium signature verification failed!\n";
        return;
    }

    std::vector<unsigned char> sigFal = Crypto::fromHex(newBlock.getFalconSignature());
    std::vector<unsigned char> pubFal(newBlock.getPublicKeyFalcon().begin(), newBlock.getPublicKeyFalcon().end());

    if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
        std::cerr << "❌ Falcon signature verification failed!\n";
        return;
    }

    blockchain.addBlock(newBlock);
    blockchain.saveToDB();
    std::cout << "✅ Block successfully added to blockchain!\n";
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
        std::cerr << "❌ [ERROR] Peer socket not found or not open: " << peer << "\n";
        return false;
    }

    try {
        std::string message = data;
        if (message.back() != '\n') message += "\n";  // Ensure newline
        std::cout << "📡 [DEBUG] Sending message to " << peer << ": "
                  << message.substr(0, 200) << "...\n";
        boost::asio::write(*it->second, boost::asio::buffer(message));
        return true;
    } catch (const std::exception &e) {
        std::cerr << "❌ [ERROR] Failed to send data to " << peer << ": " << e.what() << "\n";
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

    std::string response = receiveData(peer);
    if (response.empty()) {
        std::cerr << "❌ [ERROR] No blockchain data received from " << peer << "!\n";
        return "";
    }

    std::cout << "📥 Received blockchain sync data from " << peer
              << " (Dilithium + Falcon signatures embedded).\n";

    const std::string prefix = "BLOCKCHAIN_DATA|";
    if (response.rfind(prefix, 0) == 0) {
        return response.substr(prefix.length());  // ✅ Return base64 only
    }

    std::cerr << "❌ [ERROR] Unexpected blockchain sync format from " << peer << "\n";
    return "";
}

// ✅ **Start Listening for Incoming Connections**
void Network::startServer() {
  try {
    std::cout << "🌐 Node is now listening for connections on port: " << port
              << "\n";
    listenForConnections();
    ioContext.run();
  } catch (const std::exception &e) {
    std::cerr << "❌ [ERROR] Server failed to start: " << e.what() << "\n";
    std::cerr << "⚠️ Try using a different port or checking if another instance "
                 "is running.\n";
  }
}

// ✅ **Receive Data from Peer (Blocking)**
std::string Network::receiveData(const std::string &peer) {
    try {
        auto it = peerSockets.find(peer);
        if (it == peerSockets.end()) {
            std::cerr << "❌ [ERROR] Peer not found: " << peer << std::endl;
            return "";
        }

        boost::asio::streambuf buf;
        boost::system::error_code error;
        boost::asio::read_until(*it->second, buf, "\n", error);

        if (error && error != boost::asio::error::eof) {
            std::cerr << "❌ [ERROR] Error reading data from " << peer << ": "
                      << error.message() << std::endl;
            return "";
        }

        std::istream is(&buf);
        std::string receivedData;
        std::getline(is, receivedData); // Reads until newline, strips newline
        std::cout << "📥 [DEBUG] Received Data from " << peer << ": "
                  << receivedData.substr(0, 200) << "...\n";
        return receivedData;
    } catch (const std::exception &e) {
        std::cerr << "❌ [EXCEPTION] Exception in receiveData: " << e.what() << std::endl;
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

// ✅ Placeholder for handlePeer (implement logic as needed)
void Network::handlePeer(std::shared_ptr<tcp::socket> socket) {
    try {
        boost::system::error_code error;
        std::string peerId = socket->remote_endpoint().address().to_string() + ":" +
                             std::to_string(socket->remote_endpoint().port());

        std::string buffer;

        while (isRunning) {
            char temp[1024];
            size_t bytesRead = socket->read_some(boost::asio::buffer(temp), error);
            if (error == boost::asio::error::eof || bytesRead == 0) {
                std::cout << "Peer disconnected: " << peerId << "\n";
                break;
            }

            buffer.append(temp, bytesRead);

            // Process full messages (delimited by \n)
            size_t pos;
            while ((pos = buffer.find('\n')) != std::string::npos) {
                std::string line = buffer.substr(0, pos);
                buffer.erase(0, pos + 1);
                handleIncomingData(peerId, line);
            }
        }

        std::lock_guard<std::mutex> lock(peersMutex);
        peerSockets.erase(peerId);
        std::cout << "🔌 Cleaned up peer socket: " << peerId << "\n";

    } catch (std::exception &e) {
        std::cerr << "⚠️ Exception in handlePeer: " << e.what() << "\n";
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
void Network::handleReceivedBlockIndex(const std::string &peerIP,
                                       int peerBlockIndex) {
  int localIndex = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true).getLatestBlock().getIndex();
  if (peerBlockIndex > localIndex) {
    std::cout << "📡 Peer " << peerIP
              << " has longer chain. Requesting sync (Dilithium + Falcon "
                 "supported)...\n";
    requestBlockchainSync(peerIP);
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

// ✅ **Send Latest Block to Peer (Optimized)**
void Network::sendLatestBlock(const std::string &peerIP) {
    Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

    if (blockchain.getChain().empty()) {
        std::cerr << "⚠️ Warning: Blockchain is empty! No block to send.\n";
        return;
    }

    Block latestBlock = blockchain.getLatestBlock();
    alyncoin::BlockProto protoBlock = latestBlock.toProtobuf();  // ✅ FIXED

    std::string serializedBlock;
    protoBlock.SerializeToString(&serializedBlock);

    sendData(peerIP, "BLOCK_DATA|" + serializedBlock);
    std::cout << "📡 Sent latest block to " << peerIP
              << " (Dilithium + Falcon signatures included)" << std::endl;
}

// ✅ **Send Full Blockchain to Peer (Binary Storage)**
void Network::sendFullChain(const std::string &peer) {
    Blockchain &blockchain = Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true);

    std::string serialized;
    if (!blockchain.serializeBlockchain(serialized)) {
        std::cerr << "❌ [ERROR] Failed to serialize blockchain for sync.\n";
        return;
    }

    std::string base64Encoded = Crypto::base64Encode(serialized);
    std::string message = "BLOCKCHAIN_DATA|" + base64Encoded;

    std::cout << "📡 Sending BLOCKCHAIN_DATA to " << peer
              << " (size: " << base64Encoded.length() << " chars)\n";

    sendData(peer, message);
}

// cleanup
void Network::cleanupPeers() {
  std::lock_guard<std::mutex> lock(
      peersMutex); // Always lock before iterating peerSockets
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

  std::vector<unsigned char> sigDil = Crypto::fromHex(blk.getDilithiumSignature());
  std::vector<unsigned char> sigFal = Crypto::fromHex(blk.getFalconSignature());

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

