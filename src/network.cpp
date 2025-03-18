#include "network.h"
#include "blockchain.h"
#include "transaction.h"
#include <json/json.h>
#include <iostream>
#include <thread>
#include <vector>
#include <sstream>
#include <array>
#include <unordered_set>
#include "syncing.h"
#include "generated/block_protos.pb.h"
#include "generated/transaction_protos.pb.h"
#include <filesystem>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>

#define ENABLE_DEBUG 0
namespace fs = std::filesystem;

// ✅ Correct Constructor:
Network::Network(unsigned short port, Blockchain* blockchain)
    : port(port),
      blockchain(blockchain),
      isRunning(false),
      syncing(true),
      ioContext(),
      acceptor(ioContext, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) 
{
    isRunning = true;
    listenerThread = std::thread(&Network::listenForConnections, this);
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
    } catch (const std::exception& e) {
        std::cerr << "❌ Error during Network destruction: " << e.what() << std::endl;
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

        if (peerSockets.find(peerAddr) == peerSockets.end()) {
            peerSockets[peerAddr] = socket;
            savePeers();
        }

        std::cout << "📡 New peer connected: " << peerAddr << std::endl;
        std::thread(&Network::handlePeer, this, socket).detach();
    }
}

//

void Network::start() {
    startServer(); // Start listening for connections
    syncWithPeers(); // Automatically sync with peers at startup ✅
}

// ✅ **Auto-Mining Background Thread**
void Network::autoMineBlock() {
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            Blockchain& blockchain = Blockchain::getInstance(8333);
            if (!blockchain.getPendingTransactions().empty()) {
                std::cout << "⛏️ New transactions detected. Starting mining..." << std::endl;
                Block minedBlock = blockchain.minePendingTransactions("Miner");
                
                if (blockchain.isValidNewBlock(minedBlock)) {  // 🔍 Validate before adding
                    blockchain.addBlock(minedBlock);
                    Blockchain::getInstance().saveToDB();
                    broadcastBlock(minedBlock);
                    std::cout << "✅ Mined & broadcasted block: " << minedBlock.getHash() << std::endl;
                }
            }
        }
    }).detach();
}

//
void Network::broadcastMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(peersMutex); // Thread safety
    for (const auto& peer : peerSockets) {
        sendMessageToPeer(peer.first, message);
    }
}

// ✅ **Getter function for syncing status**
bool Network::isSyncing() const {
    return syncing;
}
// ✅ **Connect to a peer and send a message**
void Network::sendMessage(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const std::string& message) {
    try {
        if (!socket || !socket->is_open()) {
            return;
        }

        boost::asio::write(*socket, boost::asio::buffer(message + "\n"));
        std::cout << "📡 Sent message: " << message << std::endl;
    } catch (const std::exception& e) {
    }
}
//
void Network::sendMessageToPeer(const std::string& peer, const std::string& message) {
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

        boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, port);
        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::connect(socket, endpoints);

        boost::asio::write(socket, boost::asio::buffer(message + "\n"));
        std::cout << "📡 Sent message to peer " << peer << ": " << message << std::endl;
    } catch (const std::exception& e) {
    }
}

// ✅ **Broadcast a transaction to all peers**

void Network::broadcastTransaction(const Transaction& tx) {
    std::string txData = tx.serialize();

    for (const auto& peer : peerSockets) {
        auto socket = peer.second;
        if (socket && socket->is_open()) {
            try {
                boost::asio::write(*socket, boost::asio::buffer(txData + "\n"));
                std::cout << "📡 Transaction broadcasted to peer: " << peer.first << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "❌ [ERROR] Failed to broadcast transaction to " << peer.first << ": " << e.what() << std::endl;
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

    Blockchain& blockchain = Blockchain::getInstance();  // ✅ Use Singleton

    for (const auto& [peer, socket] : peerSockets) {
        if (peer.empty()) continue;

        std::cout << "📡 [DEBUG] Requesting blockchain sync from " << peer << "...\n";
        std::string response = requestBlockchainSync(peer);

        if (response.empty()) {
            std::cerr << "❌ [ERROR] No data received from " << peer << "!\n";
            continue;
        }

        // Debugging: Print received blockchain data
        std::cout << "📡 [DEBUG] Raw Blockchain Data from Peer (" << peer << "): "
                  << response.substr(0, 500) << "...\n";

        Blockchain& tempChain = Blockchain::getInstance();  // ✅ Use Singleton

        if (!tempChain.deserializeBlockchain(response)) {
            std::cerr << "❌ [ERROR] Failed to parse Protobuf blockchain data from peer: " << peer << "\n";
            continue;
        }

        // ✅ Merge only if received blockchain is longer & valid
        if (tempChain.getBlockCount() > blockchain.getBlockCount()) {
            std::cout << "✅ [INFO] Longer blockchain detected! Merging...\n";
            blockchain.mergeWith(tempChain);
            blockchain.saveToDB();
        } else {
            std::cout << "✅ [INFO] Local blockchain is up-to-date. No merge needed.\n";
        }
    }
}
//
void Network::connectToPeer(const std::string& ip, short port) {
    try {
        boost::asio::ip::tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(ip, std::to_string(port));

        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::connect(*socket, endpoints);

        {
            std::lock_guard<std::mutex> lock(peersMutex);
            peerSockets[ip + ":" + std::to_string(port)] = socket;
        }

        std::cout << "✅ Connected to peer: " << ip << ":" << port << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "❌ Failed to connect to peer: " << ip << ":" << port << " | Error: " << e.what() << std::endl;
    }
}

// ✅ **Broadcast peer list to all connected nodes**
void Network::broadcastPeerList() {
    if (peerSockets.empty()) return;

    Json::Value peerListJson;
    peerListJson["type"] = "peer_list";

    for (const auto& [peerAddr, _] : peerSockets) {
        if (peerAddr.find(":") == std::string::npos) {
            continue;
        }
        peerListJson["data"].append(peerAddr);
    }

    Json::StreamWriterBuilder writer;
    std::string peerListMessage = Json::writeString(writer, peerListJson);

    for (const auto& [peerAddr, _] : peerSockets) {
        sendData(peerAddr, peerListMessage);
    }
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
for (const auto& [peerAddr, socket] : peerSockets) {
    sendData(peerAddr, R"({"type": "request_peers"})");

    }

    std::cout << "📡 Requesting peer list from all known peers..." << std::endl;
}
//
void Network::receiveFullChain(const std::string& senderIP, const std::string& data) {
    std::cout << "[INFO] Receiving full blockchain from " << senderIP << std::endl;

    std::lock_guard<std::mutex> lock(blockchainMutex);

    if (!Blockchain::getInstance().deserializeBlockchain(data)) {
        std::cerr << "[ERROR] Failed to deserialize blockchain data from " << senderIP << "!\n";
        return;
    }

    Blockchain::getInstance().saveToDB();
    std::cout << "[INFO] Blockchain successfully updated from " << senderIP << std::endl;
}
//network node
bool Network::connectToNode(const std::string& peerIP, int port) {
    try {
        if (peerIP == "127.0.0.1" && port == this->port) {
            std::cerr << "⚠️ Skipping self-connection attempt.\n";
            return false;  // Prevent connecting to own node
        }

        std::string fullPeer = peerIP;
        if (peerIP.find(":") == std::string::npos) {
            fullPeer += ":" + std::to_string(port);
        }

        if (peerSockets.find(fullPeer) != peerSockets.end()) {
            return false;
        }

        boost::asio::io_context ioContext;
        auto socketPtr = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        boost::asio::ip::tcp::resolver resolver(ioContext);
        auto endpoints = resolver.resolve(peerIP, std::to_string(port));

        boost::asio::connect(*socketPtr, endpoints);

        peerSockets.emplace(fullPeer, std::move(socketPtr));

        std::cout << "✅ Connected to new peer: " << fullPeer << std::endl;
        return true;
    } catch (std::exception& e) {
        std::cerr << "❌ Error connecting to node: " << e.what() << std::endl;
        return false;
    }
}

// ✅ **Run Network Thread**
void Network::run() {
    serverThread = std::thread([this]() { startServer(); });
    serverThread.detach();  // ✅ Keeps server running in background

    std::this_thread::sleep_for(std::chrono::seconds(2)); // ✅ Allow some time for initialization

    requestPeerList();       // 🔄 Request peers on startup
    scanForPeers();          // 🔄 Try discovering new peers
    requestBlockchainSync(peerSockets.begin()->first);
    autoMineBlock();         // ⛏️ Auto-mining thread
    periodicSync();          // 🔄 Keep syncing every few seconds
}
//
// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
    std::vector<std::string> peers;

    std::ifstream file("data/peers.list");
    if (!file) {
        std::cerr << "⚠️ [WARNING] No known peers found. Bootstrap required!" << std::endl;
        return peers;
    }

    std::string peer;
    while (std::getline(file, peer)) {
        if (!peer.empty()) peers.push_back(peer);
    }

    file.close();
    return peers;
}

void Network::connectToDiscoveredPeers() {
    std::vector<std::string> peers = discoverPeers();
    for (const std::string& peer : peers) {
        connectToNode(peer, DEFAULT_PORT);
    }
}

//
void Network::periodicSync() {
    for (const auto& peer : peerSockets) {
        if (peer.first.empty()) continue;  // ✅ Prevent empty peer errors

        std::cout << "📡 [DEBUG] Periodic sync request to " << peer.first << "\n";
        std::string response = requestBlockchainSync(peer.first);

        if (response.empty()) {
            std::cerr << "⚠️ [WARNING] Skipping peer " << peer.first << " due to empty response.\n";
            continue;
        }
    }
}

//
std::vector<std::string> Network::getPeers() {
    std::vector<std::string> peerList;
    for (const auto& peer : peerSockets) {
        peerList.push_back(peer.first);  // Extract peer addresses
    }
    return peerList;
}

// ✅ **Handle Incoming Data with Protobuf Validation**
void Network::handleIncomingData(const std::string& senderIP, const std::string& data) {
    if (data.empty()) {
        std::cerr << "❌ [ERROR] Received empty data from peer: " << senderIP << "!\n";
        return;
    }

    std::cout << "📡 [DEBUG] Incoming Data (" << senderIP << ") First 500 Chars:\n"
              << data.substr(0, std::min(size_t(500), data.size())) << "...\n";

    // === Handle Blockchain Sync ===
    if (data.rfind("BLOCKCHAIN_DATA|", 0) == 0) {
        std::string blockchainData = data.substr(std::string("BLOCKCHAIN_DATA|").length());

        if (blockchainData.empty()) {
            std::cerr << "❌ [ERROR] Empty blockchain data received!\n";
            return;
        }

        alyncoin::BlockchainProto protoChain;
        if (!protoChain.ParseFromString(blockchainData)) {
            std::cerr << "❌ [ERROR] Failed parsing BlockchainProto!\n";
            return;
        }

        Blockchain& blockchain = Blockchain::getInstance();
        if (!blockchain.deserializeBlockchain(blockchainData)) {
            std::cerr << "❌ Blockchain deserialization failed!\n";
            return;
        }

        blockchain.saveToDB();
        std::cout << "✅ Blockchain updated from " << senderIP << "\n";
        return;
    }

    // === Handle Block Data ===
    if (data.rfind("BLOCK_DATA|", 0) == 0) {
        std::string blockData = data.substr(std::string("BLOCK_DATA|").length());
        if (blockData.empty()) {
            std::cerr << "❌ [ERROR] Empty block data received!\n";
            return;
        }

        alyncoin::BlockProto protoBlock;
        if (!protoBlock.ParseFromString(blockData)) {
            std::cerr << "❌ [ERROR] BlockProto parsing failed!\n";
            return;
        }

        Block newBlock;
        if (!newBlock.deserializeFromProtobuf(protoBlock)) {
            std::cerr << "❌ [ERROR] Block deserialization failed!\n";
            return;
        }

        handleNewBlock(newBlock);
        return;
    }

    // === Handle Transaction Data ===
    try {
        Transaction tx = Transaction::deserialize(data);
        std::string senderPubKey = getPublicKeyPath(tx.getSender());

        if (tx.isValid(senderPubKey)) {
            blockchain->addTransaction(tx);
            blockchain->saveTransactionsToDB();
            std::cout << "✅ Valid transaction received from " << senderIP << "\n";
        } else {
            std::cerr << "❌ Invalid transaction from " << senderIP << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "⚠️ Exception while handling transaction from " << senderIP << ": " << e.what() << "\n";
    }
}

// ✅ **Broadcast a mined block to all peers*
void Network::broadcastBlock(const Block& block) {
    alyncoin::BlockProto blockProto = block.toProtobuf();
    std::string serializedBlock;
    blockProto.SerializeToString(&serializedBlock);

    std::string message = "BLOCK_DATA|" + serializedBlock;
    for (const auto& peer : getPeers()) {
        sendData(peer, message);
    }
    std::cout << "📡 Broadcasted mined block to peers!\n";
}

//
void Network::receiveTransaction(const Transaction& tx) {
    std::string txHash = tx.getHash();
    if (seenTxHashes.count(txHash) > 0) return; // Already processed
    seenTxHashes.insert(txHash);

    Blockchain::getInstance().addTransaction(tx);
    broadcastTransaction(tx); // Re-broadcast to peers
}

// Valid peer
bool Network::validatePeer(const std::string& peer) {
    if (peer.find(":") == std::string::npos) {  // ✅ Correct format check
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

//Handle new block
void Network::handleNewBlock(const Block& newBlock) {
    Blockchain& blockchain = Blockchain::getInstance();

    if (!newBlock.hasValidProofOfWork()) {
        std::cerr << "❌ [ERROR] Received block fails Proof-of-Work check! Rejecting...\n";
        return;
    }

    if (!blockchain.isValidNewBlock(newBlock)) {
        std::cerr << "❌ Invalid block received! Rejecting.\n";
        return;
    }

    std::string minerPublicKey = KEY_DIR + newBlock.getMinerAddress() + "_public.pem";
    if (!fs::exists(minerPublicKey)) {
        std::cerr << "⚠️ [WARNING] Miner public key missing. Generating...\n";
        Crypto::generateKeysForUser(newBlock.getMinerAddress());
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (!fs::exists(minerPublicKey)) {
            std::cerr << "❌ [ERROR] Miner public key generation failed!\n";
            return;
        }
    }

    if (!Crypto::verifyMessage(minerPublicKey, newBlock.getBlockSignature(), newBlock.getHash())) {
        std::cerr << "❌ Block signature verification failed! Rejecting block.\n";
        return;
    }

    blockchain.addBlock(newBlock);
    blockchain.saveToDB();
    std::cout << "✅ Block successfully added to blockchain!\n";
}

// Black list peer
void Network::blacklistPeer(const std::string& peer) {
    peerSockets.erase(peer);
    bannedPeers.insert(peer);
}

bool Network::isBlacklisted(const std::string& peer) {
    return bannedPeers.find(peer) != bannedPeers.end();
}

// ✅ **Send Data to Peer with Error Handling**
bool Network::sendData(const std::string& peer, const std::string& data) {
    auto it = peerSockets.find(peer);
    if (it == peerSockets.end() || !it->second || !it->second->is_open()) {
        std::cerr << "❌ [ERROR] Peer socket not found or not open: " << peer << "\n";
        return false;
    }

    try {
        std::cout << "📡 [DEBUG] Sending message to " << peer << ": " << data << "\n";
        boost::asio::write(*it->second, boost::asio::buffer(data + "\n"));
        return true;
    } catch (const std::exception& e) {
        std::cerr << "❌ [ERROR] Failed to send data to " << peer << ": " << e.what() << "\n";
        return false;
    }
}

// ✅ **Request Blockchain Sync from Peers**
std::string Network::requestBlockchainSync(const std::string& peer) {
    if (peerSockets.find(peer) == peerSockets.end()) {
        std::cerr << "❌ [ERROR] Peer not found: " << peer << "\n";
        return "";
    }

    std::cout << "📡 Requesting blockchain sync from: " << peer << "\n";

    // Prefix remains consistent
    if (!sendData(peer, "REQUEST_BLOCKCHAIN")) {
        std::cerr << "❌ Failed to send sync request to " << peer << "\n";
        return "";
    }

    // Fire-and-forget: we'll process received blockchain when the peer responds
    return "Sync request sent to " + peer;
}

// ✅ **Start Listening for Incoming Connections**
void Network::startServer() {
    try {
        std::cout << "🌐 Node is now listening for connections on port: " << port << "\n";
        acceptConnections();
        ioContext.run();
    } catch (const std::exception& e) {
        std::cerr << "❌ [ERROR] Server failed to start: " << e.what() << "\n";
        std::cerr << "⚠️ Try using a different port or checking if another instance is running.\n";
    }
}

// ✅ **Receive Data from Peer (Blocking)**
std::string Network::receiveData(const std::string& peer) {
    try {
        auto it = peerSockets.find(peer);
        if (it == peerSockets.end()) {
            std::cerr << "❌ [ERROR] Peer not found: " << peer << std::endl;
            return "";
        }

        std::vector<char> buffer(1024);
        boost::system::error_code error;
        size_t length = it->second->read_some(boost::asio::buffer(buffer), error);

        if (error && error != boost::asio::error::eof) {
            std::cerr << "❌ [ERROR] Error reading data from " << peer << ": " << error.message() << std::endl;
            return "";
        }

        std::string receivedData(buffer.data(), length);
        std::cout << "📥 [DEBUG] Received Data from " << peer << ": " 
                  << receivedData.substr(0, 200) << "...\n";
        return receivedData;
    } catch (const std::exception& e) {
        std::cerr << "❌ [EXCEPTION] Exception in receiveData: " << e.what() << std::endl;
        return "";
    }
}

// ✅ Accept connections
void Network::acceptConnections() {
    while (true) {
        auto socket = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
        acceptor.accept(*socket);

        std::string senderIP = socket->remote_endpoint().address().to_string();
        std::string peerAddr = senderIP + ":" + std::to_string(socket->remote_endpoint().port());

        {
            std::lock_guard<std::mutex> lock(peersMutex);
            if (peerSockets.find(peerAddr) == peerSockets.end()) {
                peerSockets[peerAddr] = socket;
                savePeers();
            }
        }

        std::cout << "📡 New peer connected: " << peerAddr << std::endl;
        std::thread(&Network::handlePeer, this, socket).detach();
    }
}

// ✅ Add peer
void Network::addPeer(const std::string& peer) {
    if (peerSockets.find(peer) != peerSockets.end()) {
        return;
    }

    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);
    peerSockets.emplace(peer, socket);

    std::cout << "📡 Peer added: " << peer << std::endl;
    savePeers();  // ✅ Save immediately
}

// ✅ Placeholder for handlePeer (implement logic as needed)
void Network::handlePeer(std::shared_ptr<tcp::socket> socket) {
    try {
        char buffer[1024];
        boost::system::error_code error;
        std::string peerId = socket->remote_endpoint().address().to_string();

        while (isRunning) {
            size_t bytesRead = socket->read_some(boost::asio::buffer(buffer), error);
            if (error == boost::asio::error::eof || bytesRead == 0) {
                std::cout << "Peer disconnected: " << peerId << "\n";
                break;
            }

            std::string data(buffer, bytesRead);
            handleIncomingData(peerId, data);
        }

        std::lock_guard<std::mutex> lock(peersMutex);
        peerSockets.erase(peerId);
        std::cout << "🔌 Cleaned up peer socket: " << peerId << "\n";

    } catch (std::exception& e) {
        std::cerr << "⚠️ Exception in handlePeer: " << e.what() << "\n";
    }
}

//
void Network::sendLatestBlockIndex(const std::string& peerIP) {
    Json::Value msg;
    msg["type"] = "latest_block_index";
    msg["data"] = Blockchain::getInstance().getLatestBlock().getIndex();
    Json::StreamWriterBuilder writer;
    sendData(peerIP, Json::writeString(writer, msg));
}

void Network::handleReceivedBlockIndex(const std::string& peerIP, int peerBlockIndex) {
    int localIndex = Blockchain::getInstance().getLatestBlock().getIndex();
    if (peerBlockIndex > localIndex) {
        std::cout << "📡 Peer " << peerIP << " has longer chain. Requesting sync...\n";
        requestBlockchainSync(peerIP);
    } else {
        std::cout << "✅ Local chain is up-to-date. No sync needed.\n";
    }
}

// ✅ **Fix Peer Saving & Loading**
void Network::loadPeers() {
    std::ifstream file("peers.txt");
    if (!file.is_open()) {
        std::cerr << "⚠️ [WARNING] peers.txt not found. Attempting auto-discovery...\n";
        scanForPeers();  
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line.find(":") == std::string::npos) continue;

        // ✅ Filter self-peer
        if (line == "127.0.0.1:" + std::to_string(port)) {
            std::cerr << "⚠️ Skipping self-peer: " << line << "\n";
            continue;
        }

        peerSockets.insert({line, nullptr});
        std::cout << "✅ Peer loaded & connected: " << line << "\n";

        // Auto-connect attempt
        if (!connectToNode(line.substr(0, line.find(":")), stoi(line.substr(line.find(":") + 1)))) {
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
        "127.0.0.1:8333",
        "192.168.1.1:8080",
        "192.168.1.2:8333"
    };

    std::cout << "🔍 Scanning for active AlynCoin nodes..." << std::endl;
    
    boost::asio::io_context ioContext;  // Declare io_context

    for (const auto& peer : potentialPeers) {
        if (connectToNode(peer.substr(0, peer.find(":")), std::stoi(peer.substr(peer.find(":") + 1)))) {
            std::cout << "✅ Found & connected to: " << peer << std::endl;
            peerSockets[peer] = std::make_shared<boost::asio::ip::tcp::socket>(ioContext);  // ✅ Corrected
            savePeers();
        }
    }

    if (peerSockets.empty()) {
        std::cout << "⚠️ No active peers found. Will retry periodically." << std::endl;
    }
}

// ✅ **Ensure Peers are Saved Correctly**
void Network::savePeers() {
    std::ofstream file("peers.txt", std::ios::trunc);
    if (!file) {
        std::cerr << "❌ Error: Unable to save peers.txt!" << std::endl;
        return;
    }

    for (const auto& [peer, _] : peerSockets) {
        if (!peer.empty() && peer.find(":") != std::string::npos) {
            file << peer << std::endl;
        }
    }
    file.close();
    std::cout << "✅ Peer list saved successfully." << std::endl;
}
// ✅ **Send Latest Block to Peer (Optimized)**
void Network::sendLatestBlock(const std::string& peerIP) {
    Blockchain& blockchain = Blockchain::getInstance();

    if (blockchain.getChain().empty()) {
        std::cerr << "⚠️ Warning: Blockchain is empty! No block to send.\n";
        return;
    }

    Block latestBlock = blockchain.getLatestBlock();
    
    alyncoin::BlockProto protoBlock;
    latestBlock.serializeToProtobuf(protoBlock);  // ✅ Convert to Protobuf

    std::string serializedBlock;
    protoBlock.SerializeToString(&serializedBlock);  // ✅ Serialize to string

    sendData(peerIP, "BLOCK_DATA|" + serializedBlock);  // ✅ Send Protobuf data
    std::cout << "📡 Sent latest block to " << peerIP << std::endl;
}

// ✅ **Send Full Blockchain to Peer (Binary Storage)**
void Network::sendFullChain(const std::string& peer) {
    std::cout << "[INFO] Sending full blockchain to " << peer << std::endl;

    std::string serializedData;
    if (!Blockchain::getInstance().serializeBlockchain(serializedData)) {
        std::cerr << "[ERROR] Failed to serialize blockchain data!\n";
        return;
    }

    sendData(peer, serializedData);
}
// ✅ **Process Incoming Data (Optimized)**
void Network::processReceivedData(const std::string& peer, const std::string& data) {
    Json::CharReaderBuilder reader;
    Json::Value jsonData;
    std::string errors;
    std::istringstream s(data);
    if (!Json::parseFromStream(reader, s, &jsonData, &errors)) return;

    std::string type = jsonData["type"].asString();
    
    if (type == "block") {
        alyncoin::BlockProto protoBlock;
        protoBlock.ParseFromString(jsonData["data"].asString()); // ✅ Parse Protobuf

        Block newBlock;
        if (newBlock.deserializeFromProtobuf(protoBlock)) {
            Blockchain::getInstance().addBlock(newBlock);
        }
    } else if (type == "transaction") {
        alyncoin::TransactionProto protoTx;
        protoTx.ParseFromString(jsonData["data"].asString()); // ✅ Parse Protobuf

        Transaction tx;
        tx.deserializeFromProtobuf(protoTx);
        Blockchain::getInstance().addTransaction(tx);
    }
}
// cleanup
void Network::cleanupPeers() {
    std::lock_guard<std::mutex> lock(peersMutex); // Always lock before iterating peerSockets
    std::vector<std::string> inactivePeers;

    for (const auto& peer : peerSockets) {
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
                std::cerr << "⚠️ Failed to ping peer: " << peer.first << " - Marking as inactive.\n";
                inactivePeers.push_back(peer.first);
            } else {
                std::cout << "✅ Peer active: " << peer.first << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "⚠️ Exception checking peer " << peer.first << ": " << e.what() << "\n";
            inactivePeers.push_back(peer.first);
        }
    }

    // Remove inactive peers
    for (const auto& peer : inactivePeers) {
        peerSockets.erase(peer);
        std::cout << "🗑️ Removed inactive peer: " << peer << "\n";
    }
}
