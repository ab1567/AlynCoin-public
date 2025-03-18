#ifndef NETWORK_H
#define NETWORK_H

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <boost/asio.hpp>
#include <atomic>
#include <mutex>
#include "transaction.h"
#include "blockchain.h"
#include "block.h"
#include "generated/block_protos.pb.h"
#include "generated/blockchain_protos.pb.h"
#include "generated/transaction_protos.pb.h"

using boost::asio::ip::tcp;

class Network {
public:
    inline static Network& getInstance(unsigned short port = 8333, Blockchain* blockchain = nullptr) {
        static Network instance(port, blockchain);
        return instance;
    }

    ~Network();

    void start();
    void startListening();
    void syncWithPeers();
    void connectToPeer(const std::string& host, short port);
    void broadcastTransaction(const Transaction& tx);
    void broadcastMessage(const std::string& message);
    void broadcastBlock(const Block& block);
    std::vector<std::string> discoverPeers();
    void connectToDiscoveredPeers();
    std::string requestBlockchainSync(const std::string& peer);
    std::string receiveData(const std::string& peer);
    void requestPeerList();
    void scanForPeers();
    void processReceivedData(const std::string& senderIP, const std::string& data);
    void startServer();
    void handleIncomingData(const std::string& sender, const std::string& data);
    void sendLatestBlock(const std::string& peerIP);
    void sendLatestBlockIndex(const std::string& peerIP);
    void handleReceivedBlockIndex(const std::string& peerIP, int peerBlockIndex);
    void sendFullChain(const std::string& peerIP);
    void loadPeers();
    void savePeers();
    void addPeer(const std::string& peer);
    void acceptConnections();
    void sendMessageToPeer(const std::string& peer, const std::string& message);
    void sendMessage(std::shared_ptr<tcp::socket> socket, const std::string& message);
    std::vector<std::string> getPeers();
    bool sendData(const std::string& peer, const std::string& data);
    void receiveTransaction(const Transaction& tx);
    void broadcastPeerList();
    void run();
    bool isSyncing() const;
    bool connectToNode(const std::string& ip, int port);
    void receiveFullChain(const std::string& sender, const std::string& serializedData);
    void autoMineBlock();
    void periodicSync();
    void listenForConnections();
    bool validatePeer(const std::string& peer);
    void handleNewBlock(const Block& newBlock);
    void blacklistPeer(const std::string& peer);
    bool isBlacklisted(const std::string& peer);
    void cleanupPeers();

private:
    unsigned short port;
    Blockchain* blockchain;

    std::atomic<bool> isRunning;
    std::atomic<bool> syncing;
    std::mutex peersMutex;

    boost::asio::io_context ioContext;
    boost::asio::ip::tcp::acceptor acceptor;
    std::thread listenerThread;
    std::thread serverThread;

    std::unordered_map<std::string, std::shared_ptr<boost::asio::ip::tcp::socket>> peerSockets;
    std::unordered_set<std::string> bannedPeers;

    explicit Network(unsigned short port, Blockchain* blockchain);

    void handlePeer(std::shared_ptr<tcp::socket> socket);
};

#endif // NETWORK_H
