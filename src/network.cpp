#include "network.h"
#include "transport/ssl_transport.h"
#include "tls_utils.h"
#include "config.h"
#include "blockchain.h"
#include "crypto_utils.h"
#include <generated/block_protos.pb.h>
#include <generated/sync_protos.pb.h>
#include <generated/transaction_protos.pb.h>
#include "proto_utils.h"
#include "rollup/proofs/proof_verifier.h"
#include "rollup/rollup_block.h"
#include "self_healing/self_healing_node.h"
#include "syncing/headers_sync.h"
#include "transaction.h"
#include "constants.h"
#include "crypto/sphinx.h"
#include "wire/varint.h"
#include "zk/winterfell_stark.h"
#include <sodium.h>
#include <algorithm>
#include <random>
#include <arpa/nameser.h>
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <generated/net_frame.pb.h>
#include "protocol_codes.h"
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <resolv.h>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <boost/lockfree/queue.hpp>
#include "httplib.h"
#ifdef HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif
#ifdef HAVE_LIBNATPMP
#include <arpa/inet.h>
#include <natpmp.h>
#include <sys/select.h>
#endif
#include "transport/pubsub_router.h"
#include "transport/tcp_transport.h"

using namespace alyncoin;

static std::string ipPrefix(const std::string &ip) {
  if (ip.find(':') == std::string::npos) {
    std::stringstream ss(ip);
    std::string seg;
    std::string out;
    int count = 0;
    while (std::getline(ss, seg, '.') && count < 3) {
      if (count)
        out += '.';
      out += seg;
      ++count;
    }
    return count == 3 ? out : std::string();
  }
  std::stringstream ss(ip);
  std::string seg;
  std::string out;
  int count = 0;
  while (std::getline(ss, seg, ':') && count < 3) {
    if (count)
      out += ':';
    out += seg;
    ++count;
  }
  return count == 3 ? out : std::string();
}

// ==== [Globals, Statics] ====
// Incoming FULL_CHAIN buffers were removed; per-peer state now tracks
// snapshot or header sync progress directly via peerTransports.
// Protocol frame revision. Bumped whenever the on-wire format or required
// capabilities change.
static constexpr uint32_t kFrameRevision = 4;
static_assert(alyncoin::net::Frame::kBlockBroadcast == 6,
              "Frame field-numbers changed \u2013 bump kFrameRevision !");
static_assert(alyncoin::net::Frame::kBlockRequest == 29 &&
              alyncoin::net::Frame::kBlockResponse == 30,
              "Frame field-numbers changed \u2013 bump kFrameRevision !");
static constexpr uint64_t FRAME_LIMIT_MIN = 200;
static constexpr uint64_t BYTE_LIMIT_MIN = 1 << 20;
static constexpr int MAX_REORG = 100;
// TRACE-level lock diagnostics can overwhelm logs on busy nodes. They are now
// compiled in only when ENABLE_LOCK_TRACING is defined at build time.
#ifdef ENABLE_LOCK_TRACING
struct ScopedLockTracer {
  std::string name;
  explicit ScopedLockTracer(const std::string &n) : name(n) {
    std::cerr << "[TRACE] Lock entered: " << name << std::endl;
  }
  ~ScopedLockTracer() {
    std::cerr << "[TRACE] Lock exited: " << name << std::endl;
  }
};
#else
struct ScopedLockTracer {
  explicit ScopedLockTracer(const std::string &) {}
};
#endif
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
Network *Network::instancePtr = nullptr;

// Queue item containing a frame and originating peer for worker threads
struct RxItem {
  alyncoin::net::Frame frame;
  std::string peer;
};
// Lock-free bounded queue for decoupling network I/O from processing
static boost::lockfree::queue<RxItem *, boost::lockfree::capacity<128>> rxQ;
// Thread pool used to process frames popped from the queue
static httplib::ThreadPool pool(std::max(1u, std::thread::hardware_concurrency()));
static bool workersStarted = [] {
  unsigned n = std::max(1u, std::thread::hardware_concurrency());
  for (unsigned i = 0; i < n; ++i) {
    pool.enqueue([] {
      for (;;) {
        RxItem *item = nullptr;
        while (!rxQ.pop(item)) {
          std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (item) {
          if (!Network::isUninitialized())
            Network::getInstance().processFrame(item->frame, item->peer);
          delete item;
        }
      }
    });
  }
  return true;
}();

static bool isPortAvailable(unsigned short port) {
  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor acceptor(io);
  boost::system::error_code ec;
  acceptor.open(boost::asio::ip::tcp::v4(), ec);
  if (ec)
    return false;
  acceptor.bind({boost::asio::ip::tcp::v4(), port}, ec);
  if (ec)
    return false;
  acceptor.close();
  return true;
}

unsigned short Network::findAvailablePort(unsigned short startPort,
                                          int maxTries) {
  for (int i = 0; i < maxTries; ++i) {
    unsigned short p = startPort + i;
    if (isPortAvailable(p))
      return p;
  }
  return 0;
}
//

bool Network::sendFrame(std::shared_ptr<Transport> tr,
                        const google::protobuf::Message &m,
                        bool immediate) {
  if (!tr || !tr->isOpen())
    return false;
  const alyncoin::net::Frame *fr =
      dynamic_cast<const alyncoin::net::Frame *>(&m);
  if (fr) {
    WireFrame tag = WireFrame::OTHER;
    if (fr->has_handshake())
      tag = WireFrame::HANDSHAKE;
    else if (fr->has_height_req() || fr->has_height_res())
      tag = WireFrame::HEIGHT;
    else if (fr->has_peer_list())
      tag = WireFrame::PEER_LIST;
    else if (fr->has_block_broadcast())
      tag = WireFrame::BLOCK;
    else if (fr->has_snapshot_meta())
      tag = WireFrame::SNAP_META;
    else if (fr->has_snapshot_chunk())
      tag = WireFrame::SNAP_CHUNK;
    else if (fr->has_snapshot_end())
      tag = WireFrame::SNAP_END;
    std::cerr << "[>>] Outgoing Frame Type=" << static_cast<int>(tag) << "\n";
  }
size_t sz = m.ByteSizeLong();
if (sz == 0) {
    std::cerr << "[sendFrame] ❌ Attempting to send empty protobuf message!" << '\n';
    return false;
}
if (sz > MAX_WIRE_PAYLOAD) {
    std::cerr << "[sendFrame] ❌ Payload too large: " << sz
              << " bytes (limit " << MAX_WIRE_PAYLOAD << ")" << '\n';
    return false;
}
std::vector<uint8_t> buf(sz);
if (!m.SerializeToArray(buf.data(), static_cast<int>(sz))) {
    std::cerr << "[sendFrame] ❌ SerializeToArray failed" << '\n';
    return false;
}
uint8_t var[10];
size_t n = encodeVarInt(sz, var);
std::string out(reinterpret_cast<char *>(var), n);
out.append(reinterpret_cast<const char *>(buf.data()), sz);
std::cerr << "[sendFrame] Sending frame, payload size: " << sz
          << " bytes" << '\n';
  if (immediate) {
    if (auto tcp = std::dynamic_pointer_cast<TcpTransport>(tr))
      return tcp->writeBinaryLocked(out);
    return tr->writeBinary(out);
  }
  tr->queueWrite(std::move(out), /*binary =*/true);
  return true;
}

void Network::broadcastFrame(const google::protobuf::Message &m) {
  std::unordered_map<std::string, PeerEntry> peersCopy;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    peersCopy = peerTransports;
  }
  for (const auto &kv : peersCopy) {
    const auto &peerId = kv.first;
    auto tr = kv.second.tx;
    if (!tr || !tr->isOpen())
      continue;
    if (!sendFrame(tr, m)) {
      std::cerr << "❌ failed to send frame to " << peerId
                << " – marking peer offline" << '\n';
      markPeerOffline(peerId);
    }
  }
}

void Network::sendPrivate(const std::string &peer,
                          const google::protobuf::Message &m) {
  std::vector<std::string> peers;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto &kv : peerTransports)
      if (kv.first != peer)
        peers.push_back(kv.first);
  }
  if (peers.empty()) {
    broadcastFrame(m);
    return;
  }
  std::shuffle(peers.begin(), peers.end(), std::mt19937{std::random_device{}()});
  size_t hops = std::min<size_t>(3, peers.size() + 1);
  std::vector<std::string> route;
  for (size_t i = 0; i + 1 < hops; ++i)
    route.push_back(peers[i]);
  route.push_back(peer);
  if (route.size() <= 1) {
    broadcastFrame(m);
    return;
  }

  std::vector<std::vector<uint8_t>> keys;
  for (const auto &hop : route) {
    auto it = peerTransports.find(hop);
    if (it == peerTransports.end())
      return;
    keys.emplace_back(it->second.state->linkKey.begin(), it->second.state->linkKey.end());
  }

  auto firstHop = route.front();
  std::string payload = m.SerializeAsString();
  auto pkt = crypto::createPacket(std::vector<uint8_t>(payload.begin(), payload.end()),
                                  route, keys);
  alyncoin::net::Frame fr;
  fr.mutable_whisper()->set_data(std::string(pkt.header.begin(), pkt.header.end()) +
                                 std::string(pkt.payload.begin(), pkt.payload.end()));
  std::this_thread::sleep_for(std::chrono::milliseconds(50 + rand() % 101));
  sendFrame(peerTransports[firstHop].tx, fr);
}

void Network::sendHeight(const std::string &peer) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  alyncoin::net::Frame fr;
  Blockchain &bc = Blockchain::getInstance();
  auto *hr = fr.mutable_height_res();
  hr->set_height(bc.getHeight());
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  uint64_t w64 = work.convert_to<uint64_t>();
  if (peerManager)
    peerManager->setLocalWork(w64);
  hr->set_total_work(w64);
  sendFrame(it->second.tx, fr);
}

void Network::sendHeightProbe(std::shared_ptr<Transport> tr) {
  if (!tr || !tr->isOpen())
    return;
  Blockchain &bc = Blockchain::getInstance();
  alyncoin::net::Frame fr;
  auto *hp = fr.mutable_height_probe();
  hp->set_height(bc.getHeight());
  hp->set_tip_hash(bc.getLatestBlockHash());
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  uint64_t w64 = work.convert_to<uint64_t>();
  if (peerManager)
    peerManager->setLocalWork(w64);
  hp->set_total_work(w64);
  sendFrame(tr, fr);
}

void Network::sendTipHash(const std::string &peer) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  alyncoin::net::Frame fr;
  fr.mutable_tip_hash_res()->set_hash(
      Blockchain::getInstance().getLatestBlockHash());
  sendFrame(it->second.tx, fr);
}

void Network::sendPeerList(const std::string &peer) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  alyncoin::net::Frame fr;
  auto *pl = fr.mutable_peer_list();
  std::lock_guard<std::timed_mutex> lk(peersMutex);
  for (const auto &kv : peerTransports)
    pl->add_peers(kv.first);
  sendFrame(it->second.tx, fr);
}

void Network::markPeerOffline(const std::string &peerId) {
  std::lock_guard<std::timed_mutex> lk(peersMutex);
  auto it = peerTransports.find(peerId);
  if (it != peerTransports.end()) {
    if (it->second.tx)
      it->second.tx->close();
    peerTransports.erase(it);
  }
  anchorPeers.erase(peerId);
  knownPeers.erase(peerId);
  if (peerManager)
    peerManager->disconnectPeer(peerId);
}

void Network::penalizePeer(const std::string &peer, int points) {
  std::lock_guard<std::timed_mutex> lk(peersMutex);
  auto it = peerTransports.find(peer);
  if (it != peerTransports.end()) {
    it->second.state->misScore += points;
    if (it->second.state->misScore >= 100)
      blacklistPeer(peer);
  }
}

// Build a handshake using the most up-to-date blockchain metadata so
// newly connected peers know our real tip height and capabilities.
alyncoin::net::Handshake Network::buildHandshake() const {
  alyncoin::net::Handshake hs;
  Blockchain &bc = Blockchain::getInstance();
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
  hs.add_capabilities("whisper_v1");
  hs.add_capabilities("tls_v1");
  hs.add_capabilities("ban_decay_v1");
  hs.set_frame_rev(kFrameRevision);
  return hs;
}
// Fallback peer(s) in case DNS discovery fails
static const std::vector<std::string> DEFAULT_DNS_PEERS = {
    "49.206.56.213:15672", // Known bootstrap peer
    "35.208.110.26:15671"};

// ==== [DNS Peer Discovery] ====
std::vector<std::string> fetchPeersFromDNS(const std::string &domain) {
  std::vector<std::string> peers;

  unsigned char response[NS_PACKETSZ];
  int len =
      res_query(domain.c_str(), ns_c_in, ns_t_txt, response, sizeof(response));
  if (len < 0) {
    std::cerr << "❌ [DNS] TXT query failed for domain: " << domain << "\n";
  } else {
    ns_msg handle;
    if (ns_initparse(response, len, &handle) == 0) {
      int count = ns_msg_count(handle, ns_s_an);
      for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0)
          continue;
        const unsigned char *rdata = ns_rr_rdata(rr);
        int rdlen = ns_rr_rdlen(rr);
        int pos = 0;
        while (pos < rdlen) {
          int txtLen = rdata[pos];
          ++pos;
          if (txtLen <= 0 || pos + txtLen > rdlen)
            break;
          std::string txt(reinterpret_cast<const char *>(rdata + pos), txtLen);
          pos += txtLen;
          if (txt.find(":") != std::string::npos &&
              txt.find(" ") == std::string::npos &&
              txt.find(",") == std::string::npos) {
            std::cout << "🌐 [DNS] Found peer TXT entry: " << txt << "\n";
            peers.push_back(txt);
          }
        }
      }
    } else {
      std::cerr << "❌ [DNS] Failed to parse DNS response for " << domain
                << "\n";
    }
  }

  if (peers.empty()) {
    std::cerr << "⚠️ [DNS] No valid TXT peer records found at " << domain
              << "\n";
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
    UPNPDev *devlist{nullptr};
    ~UPnPContext() {
      FreeUPNPUrls(&urls);
      if (devlist)
        freeUPNPDevlist(devlist);
    }
  } ctx;

  char lanAddr[64] = {0};
  ctx.devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, nullptr);
  if (!ctx.devlist) {
    std::cerr << "⚠️ [UPnP] upnpDiscover() failed or no devices found\n";
    return;
  }

  int igdStatus = UPNP_GetValidIGD(ctx.devlist, &ctx.urls, &ctx.data, lanAddr,
                                   sizeof(lanAddr));
  if (igdStatus != 1) {
    std::cerr << "⚠️ [UPnP] No valid IGD found\n";
    return;
  }

  char portStr[16];
  snprintf(portStr, sizeof(portStr), "%d", port);

  int ret = UPNP_AddPortMapping(ctx.urls.controlURL, ctx.data.first.servicetype,
                                portStr, portStr, lanAddr, "AlynCoin", "TCP",
                                nullptr, "0");

  if (ret == UPNPCOMMAND_SUCCESS) {
    std::cout << "✅ [UPnP] Port mapping added on port " << std::dec << port
              << "\n";
  } else {
    std::cerr << "⚠️ [UPnP] Failed to add port mapping: " << strupnperror(ret)
              << "\n";
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
    std::cout << "✅ [NAT-PMP] Port mapping added on port " << std::dec << port
              << "\n";
  } else {
    std::cerr << "⚠️ [NAT-PMP] Failed to add port mapping: " << r
              << " resp=" << response.resultcode << "\n";
  }
  closenatpmp(&natpmp);
}
#endif

Network::Network(unsigned short port, Blockchain *blockchain,
                 PeerBlacklist *blacklistPtr)
      : port(port), blockchain(blockchain), isRunning(false), syncing(true),
      ioContext(), tlsContext(nullptr), acceptor(ioContext), blacklist(blacklistPtr) {
  if (!blacklistPtr) {
    std::cerr
        << "❌ [FATAL] PeerBlacklist is null! Cannot initialize network.\n";
    throw std::runtime_error("PeerBlacklist is null");
  }

  if (getAppConfig().enable_tls) {
    tlsContext = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12);
    std::string cert, key;
    tls::ensure_self_signed_cert(getAppConfig().data_dir, cert, key);
    tlsContext->use_certificate_chain_file(cert);
    tlsContext->use_private_key_file(key, boost::asio::ssl::context::pem);
  }

  try {
    boost::asio::ip::tcp::acceptor::reuse_address reuseOpt(true);
    acceptor.open(boost::asio::ip::tcp::v4());

    boost::system::error_code ec;
    acceptor.set_option(reuseOpt, ec);
    if (ec) {
      std::cerr << "⚠️ [Network] Failed to set socket option: " << ec.message()
                << "\n";
    }

    // ✅ Bind to all interfaces (0.0.0.0)
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::make_address("0.0.0.0"), port);
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

    std::cout << "🌐 Network listener started on port: " << std::dec << port
              << "\n";
    peerManager = std::make_unique<PeerManager>(blacklistPtr, this);
    selfHealer = std::make_unique<SelfHealingNode>(blockchain, peerManager.get());
    isRunning = true;
    listenerThread = std::thread(&Network::listenForConnections, this);
    threads_.push_back(std::move(listenerThread));

  } catch (const std::exception &ex) {
    std::cerr << "❌ [Network Exception] " << ex.what() << "\n";
  }
}

// ✅ Correct Destructor:

Network::~Network() {
  try {
    ioContext.stop();
    acceptor.close();
    for (auto &t : threads_)
      if (t.joinable())
        t.join();
    std::cout << "✅ Network instance cleaned up safely." << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "❌ Error during Network destruction: " << e.what()
              << std::endl;
  }
}
//
void Network::listenForConnections() {
  std::cout << "🌐 Listening for connections on port: " << std::dec << port
            << std::endl;

  acceptor.async_accept(
      [this](boost::system::error_code ec, tcp::socket socket) {
        if (!ec) {
          std::cout << "🌐 [ACCEPTED] Incoming connection accepted.\n";
          std::shared_ptr<Transport> transport;
          if (getAppConfig().enable_tls && tlsContext) {
            auto stream = std::make_shared<boost::asio::ssl::stream<tcp::socket>>(std::move(socket), *tlsContext);
            transport = std::make_shared<SslTransport>(stream);
            boost::system::error_code ec2;
            stream->handshake(boost::asio::ssl::stream_base::server, ec2);
            if (ec2) {
              std::cerr << "❌ [TLS handshake] " << ec2.message() << "\n";
              return;
            }
          } else {
            auto sockPtr = std::make_shared<tcp::socket>(std::move(socket));
            transport = std::make_shared<TcpTransport>(sockPtr);
          }
          if (transport)
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
        std::cout << "⛏️ New transactions detected. Starting mining..."
                  << std::endl;

        // Use default miner address
        std::string minerAddress =
            "miner"; // Replace with actual configured address if needed
        std::vector<unsigned char> dilithiumPriv =
            Crypto::loadDilithiumKeys(minerAddress).privateKey;
        std::vector<unsigned char> falconPriv =
            Crypto::loadFalconKeys(minerAddress).privateKey;

        if (dilithiumPriv.empty() || falconPriv.empty()) {
          std::cerr << "❌ Miner private keys not found or invalid!"
                    << std::endl;
          continue;
        }

        Block minedBlock = blockchain.minePendingTransactions(
            minerAddress, dilithiumPriv, falconPriv);

        // Validate signatures using the same message that was signed
        std::vector<unsigned char> msgHash = minedBlock.getSignatureMessage();
        std::vector<unsigned char> sigDil = minedBlock.getDilithiumSignature();
        std::vector<unsigned char> pubDil =
            Crypto::getPublicKeyDilithium(minedBlock.getMinerAddress());

        std::vector<unsigned char> sigFal = minedBlock.getFalconSignature();
        std::vector<unsigned char> pubFal =
            Crypto::getPublicKeyFalcon(minedBlock.getMinerAddress());
        bool validSignatures =
            Crypto::verifyWithDilithium(msgHash, sigDil, pubDil) &&
            Crypto::verifyWithFalcon(msgHash, sigFal, pubFal);

        if (blockchain.isValidNewBlock(minedBlock) && validSignatures) {
          {
            std::lock_guard<std::mutex> lock(blockchainMutex);
            Blockchain::getInstance().saveToDB();
          }
          broadcastBlock(minedBlock);
          blockchain.broadcastNewTip();
          autoSyncIfBehind();
          std::cout << "✅ Mined & broadcasted block: " << minedBlock.getHash()
                    << std::endl;
        } else {
          std::cerr << "❌ Mined block failed validation or signature check!"
                    << std::endl;
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
  if (peerTransports.size() <= 1) {
    for (const auto &kv : peerTransports) {
      if (kv.second.tx && kv.second.tx->isOpen()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50 + rand() % 101));
        sendFrame(kv.second.tx, fr);
      }
    }
    return;
  }
  for (const auto &kv : peerTransports) {
    if (peerSupportsWhisper(kv.first))
      sendPrivate(kv.first, fr);
    else if (kv.second.tx && kv.second.tx->isOpen()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50 + rand() % 101));
      sendFrame(kv.second.tx, fr);
    }
  }
}

// Broadcast transaction to all peers except sender (to prevent echo storms)
void Network::broadcastTransactionToAllExcept(const Transaction &tx,
                                              const std::string &excludePeer) {
  alyncoin::TransactionProto proto = tx.toProto();
  alyncoin::net::Frame fr;
  *fr.mutable_tx_broadcast()->mutable_tx() = proto;
  for (const auto &kv : peerTransports) {
    if (kv.first == excludePeer)
      continue;
    if (peerSupportsWhisper(kv.first))
      sendPrivate(kv.first, fr);
    else if (kv.second.tx && kv.second.tx->isOpen()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50 + rand() % 101));
      sendFrame(kv.second.tx, fr);
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

  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto &kv : peerTransports) {
      auto tr = kv.second.tx;
      if (!tr || !tr->isOpen())
        continue;
      alyncoin::net::Frame req1;
      req1.mutable_height_req();
      sendFrame(tr, req1);
      alyncoin::net::Frame req2;
      req2.mutable_tip_hash_req();
      sendFrame(tr, req2);
    }
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  const int localHeight = blockchain->getHeight();
  const int networkHeight = peerManager->getMedianNetworkHeight();

  if (networkHeight <= localHeight) {
    std::cout
        << "✅ [Smart Sync] Local blockchain is up-to-date. No sync needed.\n";
    return;
  }

  std::cout << "📡 [Smart Sync] Local height: " << localHeight
            << ", Network height: " << networkHeight << ". Sync needed.\n";

  /* pick the first suitable peer that is ahead */
  for (const auto &[peer, entry] : peerTransports) {
    int ph = peerManager->getPeerHeight(peer);
    if (ph <= localHeight)
      continue;

    if (peerSupportsSnapshot(peer))
      requestSnapshotSync(peer);
    else if (peerSupportsAggProof(peer))
      requestEpochHeaders(peer);
    break; // one good peer is enough
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
    if (peerTransports.empty())
      return;
    for (const auto &[peerAddr, _] : peerTransports) {
      if (peerAddr.find(":") == std::string::npos)
        continue;
      peers.push_back(peerAddr);
    }
  }

  for (const auto &peerAddr : peers) {
    auto it = peerTransports.find(peerAddr);
    if (it == peerTransports.end() || !it->second.tx)
      continue;
    alyncoin::net::Frame fr;
    auto *pl = fr.mutable_peer_list();
    for (const auto &p : peers)
      pl->add_peers(p);
    sendFrame(it->second.tx, fr);
  }
}

//
PeerManager *Network::getPeerManager() { return peerManager.get(); }

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
  for (const auto &[peerAddr, entry] : peerTransports) {
    if (entry.tx && entry.tx->isOpen()) {
      alyncoin::net::Frame fr;
      fr.mutable_peer_list_req();
      sendFrame(entry.tx, fr);
    }
  }
  std::cout << "📡 Requesting peer list from all known peers..." << std::endl;
}
// Handle Peer (Transport version)
void Network::handlePeer(std::shared_ptr<Transport> transport) {
  std::string realPeerId, claimedPeerId;
  std::string claimedVersion, claimedNetwork;
  int remoteHeight = 0;
  uint32_t remoteRev = 0;
  bool remoteAgg = false;
  bool remoteSnap = false;
  bool remoteWhisper = false;
  bool remoteTls = false;
  bool remoteBanDecay = false;

  /* what *we* look like to the outside world */
  // Determine how peers see this node. We capture `this` so the lambda
  // always uses our own listening port rather than the remote port.
  const auto selfAddr = [this] {
    return publicPeerId.empty() ? "127.0.0.1:" + std::to_string(this->port)
                                : publicPeerId;
  };

  // ── 1. read + verify handshake ──────────────────────────────────────────
  std::array<uint8_t, 32> myPriv{};
  std::array<uint8_t, 32> myPub{};
  std::array<uint8_t, 32> shared{};
  try {
    std::string blob = transport->readBinaryBlocking();
    alyncoin::net::Frame fr;
    if (blob.empty() || !fr.ParseFromString(blob) || !fr.has_handshake())
      throw std::runtime_error("invalid handshake");

    const auto &hs = fr.handshake();

    randombytes_buf(myPriv.data(), myPriv.size());
    crypto_scalarmult_curve25519_base(myPub.data(), myPriv.data());
    if (hs.pub_key().size() == 32)
      (void)crypto_scalarmult_curve25519(
          shared.data(), myPriv.data(),
          reinterpret_cast<const unsigned char *>(hs.pub_key().data()));

    const std::string senderIP = transport->getRemoteIP();
    // The Handshake proto uses proto3 semantics so there is no
    // `has_listen_port()` accessor. Older nodes may omit this field, so
    // fall back to the remote port if zero.
    int finalPort = hs.listen_port();
    if (finalPort == 0)
      finalPort = transport->getRemotePort();
    realPeerId = senderIP + ':' + std::to_string(finalPort);

    claimedVersion = hs.version();
    claimedNetwork = hs.network_id();
    remoteHeight = static_cast<int>(hs.height());

    // ─── Compatibility gate ────────────────────
    remoteRev = hs.frame_rev();
    if (remoteRev != 0 && remoteRev != kFrameRevision) {
      std::cerr << "⚠️  [handshake] peer uses frame_rev=" << remoteRev
                << " but we need " << kFrameRevision
                << " – dropping for incompatibility.\n";
      return;
    }

    bool gotBinary = false;
    for (const auto &cap : hs.capabilities()) {
      if (cap == "agg_proof_v1")
        remoteAgg = true;
      if (cap == "snapshot_v1")
        remoteSnap = true;
      if (cap == "whisper_v1")
        remoteWhisper = true;
      if (cap == "tls_v1")
        remoteTls = true;
      if (cap == "ban_decay_v1")
        remoteBanDecay = true;
      if (cap == "binary_v1")
        gotBinary = true;
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

    std::cout << "🤝 Handshake from " << realPeerId << " | ver "
              << claimedVersion << " | net " << claimedNetwork << " | height "
              << remoteHeight << '\n';

    if (claimedNetwork != "mainnet") {
      std::cerr << "⚠️  [handlePeer] peer is on another network – dropped.\n";
      return;
    }

    std::string prefix = ipPrefix(senderIP);
    if (!prefix.empty()) {
      std::lock_guard<std::timed_mutex> g(peersMutex);
      int count = 0;
      for (const auto &kv : peerTransports) {
        std::string ip = kv.first.substr(0, kv.first.find(':'));
        if (ipPrefix(ip) == prefix)
          ++count;
      }
      if (count >= 2) {
        std::cerr << "⚠️  [handlePeer] prefix limit reached for " << senderIP
                  << " (" << prefix << " count=" << count << ")" << '\n';
        return;
      }
    }
  } catch (const std::exception &ex) {
    std::cerr << "❌ [handlePeer] invalid binary handshake (" << ex.what()
              << ")" << '\n';
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

    auto itExisting = peerTransports.find(claimedPeerId);
    if (itExisting != peerTransports.end() && itExisting->second.tx &&
        itExisting->second.tx->isOpen()) {
      bool keepExisting = true;
      bool newInitiated = false;
      if (itExisting->second.initiatedByUs != newInitiated) {
        // each side initiated one, choose lexicographically smaller id
        if (selfAddr() > claimedPeerId)
          keepExisting = false;
      }
      if (keepExisting) {
        std::cout << "🔁 duplicate connection from " << claimedPeerId
                  << " closed\n";
        if (transport)
          transport->closeGraceful();
        return;
      } else {
        std::cout << "🔁 replacing connection for " << claimedPeerId << "\n";
        if (itExisting->second.tx)
          itExisting->second.tx->closeGraceful();
        itExisting->second.tx = transport;
        itExisting->second.initiatedByUs = newInitiated;
      }
    }

    auto &entry = peerTransports[claimedPeerId];
    entry.tx = transport;
    entry.initiatedByUs = false;
    knownPeers.insert(claimedPeerId);
    if (!entry.state)
      entry.state = std::make_shared<PeerState>();
    entry.state->supportsAggProof = remoteAgg;
    entry.state->supportsSnapshot = remoteSnap;
    entry.state->supportsWhisper = remoteWhisper;
    entry.state->supportsTls = remoteTls;
    entry.state->supportsBanDecay = remoteBanDecay;
    entry.state->frameRev = remoteRev;
    entry.state->version = claimedVersion;
    std::copy(shared.begin(), shared.end(), entry.state->linkKey.begin());

    if (peerManager) {
      if (peerManager->registerPeer(claimedPeerId))
        peerManager->setPeerHeight(claimedPeerId, remoteHeight);
    }
  }

  std::cout << "✅ Registered peer: " << claimedPeerId << '\n';

  // ── 4. push our handshake back ──────────────────────────────────────────
  {
    alyncoin::net::Handshake hs = buildHandshake();
    hs.set_pub_key(std::string(reinterpret_cast<char *>(myPub.data()),
                               myPub.size()));
    alyncoin::net::Frame out;
    *out.mutable_handshake() = hs;
    sendFrameImmediate(transport, out);
    sendHeight(claimedPeerId);
  }

  // ── 5. arm read loop + initial requests ────────────────────────────────
  startBinaryReadLoop(claimedPeerId, transport);

  sendInitialRequests(claimedPeerId);

  // ── 6. immediate sync decision ─────────────────────────────────────────
  const size_t myHeight = Blockchain::getInstance().getHeight();
  if (remoteHeight > static_cast<int>(myHeight)) {
    if (remoteSnap)
      requestSnapshotSync(claimedPeerId);
    else if (remoteAgg)
      requestEpochHeaders(claimedPeerId);
  } else if (remoteHeight < static_cast<int>(myHeight) && remoteSnap)
    sendTailBlocks(transport, remoteHeight, claimedPeerId);

  autoSyncIfBehind();
  intelligentSync();

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
  for (const std::string &peer : dnsPeers) {
    size_t colonPos = peer.find(":");
    if (colonPos == std::string::npos)
      continue;
    std::string ip = peer.substr(0, colonPos);
    int p = std::stoi(peer.substr(colonPos + 1));
    if ((ip == "127.0.0.1" || ip == "localhost") && p == this->port)
      continue;
    if (ip == "127.0.0.1" || ip == "localhost")
      continue;
    if (isSelfPeer(ip + ":" + std::to_string(p)))
      continue;
    connectToNode(ip, p);
  }

  // Initial sync/gossip setup
  requestPeerList();
  if (autoMineEnabled)
    autoMineBlock();

  // Trigger a sync immediately after startup so the node isn't left waiting
  // for the periodic thread to run before catching up with peers.
  this->autoSyncIfBehind();

  // Give some additional time for peers to connect, then try again to ensure
  // we didn't miss any height updates.
  std::thread([this]() {
    std::this_thread::sleep_for(
        std::chrono::seconds(3)); // Let connectToNode finish
    this->autoSyncIfBehind();
  }).detach();

  // Periodic tasks (sync, cleanup, gossip mesh)
  std::thread([this]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(15));
      periodicSync();
      if (selfHealer)
        selfHealer->checkPeerHeights();
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

  // Periodically refresh handshake metadata so peers keep our latest height
  std::thread([this]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::minutes(5));
      this->broadcastHandshake();
    }
  }).detach();

  std::thread([this]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::minutes(1));
      std::lock_guard<std::timed_mutex> lk(peersMutex);
      for (auto &kv : peerTransports) {
        auto st = kv.second.state;
        if (!st)
          continue;
        if (st->frameCountMin > FRAME_LIMIT_MIN ||
            st->byteCountMin > BYTE_LIMIT_MIN) {
          st->limitStrikes++;
          if (st->limitStrikes >= 3) {
            blacklistPeer(kv.first);
            continue;
          }
        } else {
          st->limitStrikes = 0;
        }
        st->frameCountMin = 0;
        st->byteCountMin = 0;
      }

      auto now = std::time(nullptr);
      // purge expired temporary bans
      for (auto it = bannedPeers.begin(); it != bannedPeers.end();) {
        if (now >= it->second) {
          std::cerr << "ℹ️  [ban] temporary ban expired for " << it->first
                    << '\n';
          it = bannedPeers.erase(it);
        } else {
          ++it;
        }
      }
    }
  }).detach();

  std::cout << "✅ [Network] Network loop launched successfully.\n";
}

// Call this after all initial peers are connected
void Network::autoSyncIfBehind() {
  Blockchain &bc = Blockchain::getInstance();
  const size_t myHeight = bc.getHeight();
  const std::string myTip = bc.getLatestBlockHash();

  std::lock_guard<std::timed_mutex> lock(peersMutex);
  for (const auto &[peerAddr, entry] : peerTransports) {
    auto tr = entry.tx;
    if (!tr || !tr->isOpen())
      continue;

    alyncoin::net::Frame f1;
    f1.mutable_height_req();
    sendFrame(tr, f1);
    alyncoin::net::Frame f2;
    f2.mutable_tip_hash_req();
    sendFrame(tr, f2);
    // Advertise our own height information to avoid isolation
    sendHeightProbe(tr);

    if (!peerManager)
      continue;
    int peerHeight = peerManager->getPeerHeight(peerAddr);
    int gap = peerHeight - static_cast<int>(myHeight);
    if (gap > 10 && peerSupportsSnapshot(peerAddr)) {
      std::cout << "  → gap=" << gap << ", going straight to snapshot\n";
      requestSnapshotSync(peerAddr);
      continue;
    }
    std::string peerTip = peerManager->getPeerTipHash(peerAddr);

    std::cout << "[autoSync] peer=" << peerAddr << " height=" << peerHeight
              << " | local=" << myHeight << '\n';

    if (peerHeight > static_cast<int>(myHeight)) {
      if (peerSupportsSnapshot(peerAddr)) {
        std::cout << "  → requesting snapshot sync\n";
        requestSnapshotSync(peerAddr);
      } else if (peerSupportsAggProof(peerAddr)) {
        std::cout << "  → requesting epoch headers\n";
        requestEpochHeaders(peerAddr);
      }
    } else if (peerHeight == static_cast<int>(myHeight) && !peerTip.empty() &&
               peerTip != myTip) {
      if (peerSupportsSnapshot(peerAddr)) {
        std::cout << "  → tip mismatch, requesting snapshot sync\n";
        requestSnapshotSync(peerAddr);
      } else if (peerSupportsAggProof(peerAddr)) {
        std::cout << "  → tip mismatch, requesting epoch headers\n";
        requestEpochHeaders(peerAddr);
      }
    } else if (peerHeight < static_cast<int>(myHeight)) {
      if (peerSupportsSnapshot(peerAddr)) {
        std::cout << "  → sending tail blocks\n";
        sendTailBlocks(tr, peerHeight, peerAddr);
      }
    }
  }
}
void Network::waitForInitialSync(int timeoutSeconds) {
  auto start = std::chrono::steady_clock::now();
  while (true) {
    size_t localHeight = blockchain->getHeight();
    int networkHeight = peerManager ? peerManager->getMedianNetworkHeight() : 0;
    if (networkHeight > 0 &&
        localHeight >= static_cast<size_t>(networkHeight)) {
      syncing = false;
      break;
    }
    if (std::chrono::steady_clock::now() - start >
        std::chrono::seconds(timeoutSeconds)) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }
}

// ✅ Auto-Discover Peers Instead of Manually Adding Nodes
std::vector<std::string> Network::discoverPeers() {
  std::vector<std::string> peers;
  std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
  for (const auto &peer : dnsPeers) {
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
    if (pos == std::string::npos)
      continue;
    std::string ip = peer.substr(0, pos);
    int port = std::stoi(peer.substr(pos + 1));
    std::string peerKey = ip + ":" + std::to_string(port);
    if (isSelfPeer(peerKey)) {
      std::cout << "⚠️ Skipping self in discovered peers: " << peerKey << "\n";
      continue;
    }
    if (ip == "127.0.0.1" || ip == "localhost")
      continue;
    connectToNode(ip, port);
  }
}

//
void Network::periodicSync() {
  ScopedLockTracer tracer("periodicSync");
  std::lock_guard<std::timed_mutex> lock(peersMutex);

  for (const auto &peerId : knownPeers) {
    auto it = peerTransports.find(peerId);
    if (it == peerTransports.end() || !it->second.tx ||
        !it->second.tx->isOpen()) {
      size_t pos = peerId.find(':');
      if (pos != std::string::npos) {
        std::string ip = peerId.substr(0, pos);
        int port = std::stoi(peerId.substr(pos + 1));
        connectToNode(ip, port);
        auto it2 = peerTransports.find(peerId);
        if (it2 != peerTransports.end() && it2->second.tx &&
            it2->second.tx->isOpen()) {
          int ph = peerManager ? peerManager->getPeerHeight(peerId) : 0;
          sendTailBlocks(it2->second.tx, ph, peerId);
        }
      }
      continue;
    }

    alyncoin::net::Frame f;
    f.mutable_height_req();
    sendFrame(it->second.tx, f);

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
void Network::sendStateProof(std::shared_ptr<Transport> tr) {
  if (!tr || !tr->isOpen())
    return;

  Blockchain &bc = Blockchain::getInstance();
  const int h = bc.getHeight();
  const Block &tip = bc.getLatestBlock();

  // -- ❶ compute state root (pick the one you trust) --
  std::string stateRoot =
      bc.getLatestBlock().getMerkleRoot(); // or bc.getStateRoot()

  // -- ❷ generate proof bytes --
  std::string proof =
      WinterfellStark::generateProof(stateRoot,             // blockHash
                                     tip.getPreviousHash(), // prev
                                     tip.getTxRoot());      // tx_root

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
void Network::broadcastBlock(const Block &block, bool /*force*/) {
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
    std::cerr << "[BUG] EMPTY proto in broadcastBlock for idx="
              << block.getIndex() << " hash=" << block.getHash() << "\n";
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
  for (auto &[peerId, entry] : peersCopy) {
    auto transport = entry.tx;
    if (isSelfPeer(peerId) || !transport || !transport->isOpen())
      continue;
    if (!seen.insert(transport).second)
      continue;

    bool ok = sendFrameImmediate(transport, fr);
    if (!ok) {
      std::cerr << "❌ failed to send block " << block.getIndex() << " to "
                << peerId << " – marking peer offline" << '\n';
      markPeerOffline(peerId);
      continue;
    }
    std::cout << "✅ [broadcastBlock] Block " << block.getIndex() << " sent to "
              << peerId << '\n';
  }
}

// Broadcast a batch of blocks (legacy path removed)
void Network::broadcastBlocks(const std::vector<Block> &blocks) {
  if (blocks.empty())
    return;
  for (const auto &b : blocks)
    broadcastBlock(b);
}

void Network::broadcastINV(const std::vector<std::string> &hashes) {
  if (hashes.empty())
    return;
  std::unordered_map<std::string, PeerEntry> peersCopy;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    peersCopy = peerTransports;
  }
  alyncoin::net::Frame fr;
  auto *inv = fr.mutable_inv();
  for (const auto &h : hashes)
    inv->add_hashes(h);
  for (auto &kv : peersCopy) {
    auto tr = kv.second.tx;
    if (!tr || !tr->isOpen())
      continue;
    sendFrame(tr, fr);
  }
}

void Network::broadcastHeight(uint32_t height) {
  std::unordered_map<std::string, PeerEntry> peersCopy;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    peersCopy = peerTransports;
  }
  alyncoin::net::Frame fr;
  Blockchain &bc = Blockchain::getInstance();
  auto *hr = fr.mutable_height_res();
  hr->set_height(height);
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  uint64_t w64 = work.convert_to<uint64_t>();
  if (peerManager)
    peerManager->setLocalWork(w64);
  hr->set_total_work(w64);
  for (auto &kv : peersCopy) {
    auto tr = kv.second.tx;
    if (!tr || !tr->isOpen())
      continue;
    sendFrame(tr, fr);
  }
}

void Network::broadcastHandshake() {
  std::unordered_map<std::string, PeerEntry> peersCopy;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    peersCopy = peerTransports;
  }

  alyncoin::net::Handshake hs = buildHandshake();

  alyncoin::net::Frame fr;
  *fr.mutable_handshake() = hs;

  for (auto &kv : peersCopy) {
    auto tr = kv.second.tx;
    if (!tr || !tr->isOpen())
      continue;
    sendFrame(tr, fr);
  }
}

void Network::sendBlockToPeer(const std::string &peer, const Block &blk) {
  {
    std::lock_guard<std::mutex> lk(seenBlockMutex);
    if (seenBlockHashes.count(blk.getHash()))
      return;
    seenBlockHashes.insert(blk.getHash());
  }
  alyncoin::BlockProto proto = blk.toProtobuf();
  std::string raw;
  if (!proto.SerializeToString(&raw) || raw.empty())
    return;
  alyncoin::net::Frame fr;
  *fr.mutable_block_broadcast()->mutable_block() = proto;
  auto it = peerTransports.find(peer);
  if (it != peerTransports.end() && it->second.tx && it->second.tx->isOpen())
    sendFrame(it->second.tx, fr);
  if (it != peerTransports.end() && it->second.state)
    it->second.state->highestSeen = blk.getIndex();
}
//
bool Network::isSelfPeer(const std::string &p) const {
  if (!publicPeerId.empty() && p == publicPeerId)
    return true;
  if (p == "127.0.0.1:" + std::to_string(port))
    return true;
  return false;
}

std::string Network::getSelfAddressAndPort() const {
  // Prefer explicit publicPeerId if set
  if (!publicPeerId.empty())
    return publicPeerId;
  // Fallback: localhost + port
  return "127.0.0.1:" + std::to_string(this->port);
}

void Network::setPublicPeerId(const std::string &peerId) {
  publicPeerId = peerId;
}
//

void Network::handleGetData(const std::string &peer,
                            const std::vector<std::string> &hashes) {
  Blockchain &bc = Blockchain::getInstance();
  for (const auto &h : hashes) {
    for (const auto &blk : bc.getChain()) {
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
void Network::handleNewBlock(const Block &newBlock, const std::string &sender) {
  Blockchain &blockchain = Blockchain::getInstance();
  std::cerr << "[handleNewBlock] Attempting to add block idx="
            << newBlock.getIndex() << " hash=" << newBlock.getHash() << '\n';
  const int expectedIndex = blockchain.getLatestBlock().getIndex() + 1;
  auto punish = [&] {
    if (!sender.empty()) {
      auto it = peerTransports.find(sender);
      if (it != peerTransports.end()) {
        it->second.state->misScore += 100;
        if (it->second.state->misScore >= 100)
          blacklistPeer(sender);
      }
    }
  };

  // 1) PoW and zk-STARK check
  if (!newBlock.hasValidProofOfWork()) {
    std::cerr << "❌ [ERROR] Block PoW check failed!\n";
    punish();
    return;
  }

  const auto &zkVec = newBlock.getZkProof();
  if (zkVec.empty()) {
    std::cerr << "❌ [ERROR] Missing zkProof in incoming block!\n";
    punish();
    return;
  }

  std::string zkProofStr(zkVec.begin(), zkVec.end());
  if (!WinterfellStark::verifyProof(zkProofStr, newBlock.getHash(),
                                    newBlock.getPreviousHash(),
                                    newBlock.getTransactionsHash())) {
    std::cerr << "❌ [ERROR] Invalid zk-STARK proof detected in new block!\n";
    punish();
    return;
  }

  // 2) Fork detection
  if (!blockchain.getChain().empty()) {
    std::string localTipHash = blockchain.getLatestBlockHash();
    if (newBlock.getPreviousHash() != localTipHash) {
      std::cerr
          << "⚠️ [Fork Detected] Previous hash mismatch at incoming block.\n";

      blockchain.saveForkView({newBlock});

      bool added = blockchain.addBlock(newBlock);
      if (!added) {
        for (const auto &peer : peerTransports) {
          sendForkRecoveryRequest(peer.first, newBlock.getHash());
        }
        punish();
        return;
      }

      blockchain.saveToDB();
      broadcastBlock(newBlock);
      if (peerManager && !sender.empty()) {
        peerManager->setPeerHeight(sender, newBlock.getIndex());
        peerManager->setPeerTipHash(sender, newBlock.getHash());
      }
      blockchain.broadcastNewTip();
      autoSyncIfBehind();

      std::cout << "✅ Block added successfully (fork branch). Index: "
                << newBlock.getIndex() << "\n";
      return;
    }
  }

  // 3) Index ordering
  if (newBlock.getIndex() < expectedIndex) {
    std::cerr << "⚠️ [Node] Ignoring duplicate or old block (idx="
              << newBlock.getIndex() << ").\n";
    if (!blockchain.hasBlockHash(newBlock.getHash())) {
      std::cerr
          << "🧐 [Node] Unknown historical block. Requesting fork recovery.\n";
      blockchain.setPendingForkChain({newBlock});
      for (const auto &peer : peerTransports) {
        sendForkRecoveryRequest(peer.first, newBlock.getHash());
      }
    }
    punish();
    return;
  }
  if (newBlock.getIndex() > expectedIndex) {
    std::cerr << "⚠️ [Node] Received future block. Buffering (idx="
              << newBlock.getIndex() << ").\n";
    futureBlockBuffer[newBlock.getIndex()] = newBlock;

    if (newBlock.getIndex() > expectedIndex + 5) {
      for (const auto &peer : peerTransports) {
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
      punish();
      return;
    }

    auto sigFal = newBlock.getFalconSignature();
    auto pubFal = newBlock.getPublicKeyFalcon();

    if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
      std::cerr << "❌ Falcon signature verification failed!\n";
      punish();
      return;
    }

  } catch (const std::exception &e) {
    std::cerr << "❌ [Exception] Signature verification error: " << e.what()
              << "\n";
    punish();
    return;
  }

  // 5) Add and save
  try {
    if (!blockchain.addBlock(newBlock)) {
      std::cerr << "❌ [ERROR] Failed to add new block.\n";
      punish();
      return;
    }

    blockchain.saveToDB();
    broadcastBlock(newBlock);
    // Update cached height and tip hash for the sending peer if provided
    if (peerManager && !sender.empty()) {
      peerManager->setPeerHeight(sender, newBlock.getIndex());
      peerManager->setPeerTipHash(sender, newBlock.getHash());
      auto work = blockchain.computeCumulativeDifficulty(blockchain.getChain());
      peerManager->setPeerWork(sender, work.convert_to<uint64_t>());
      auto it = peerTransports.find(sender);
      if (it != peerTransports.end() && it->second.state)
        it->second.state->highestSeen = newBlock.getIndex();
    }
    blockchain.broadcastNewTip();
    autoSyncIfBehind();

    std::cout << "✅ Block added successfully! Index: " << newBlock.getIndex()
              << "\n";

  } catch (const std::exception &ex) {
    std::cerr << "❌ [EXCEPTION] Block add/save failed: " << ex.what() << "\n";
  }

  // 6) Process any buffered future blocks
  uint64_t nextIndex = blockchain.getLatestBlock().getIndex() + 1;
  while (futureBlockBuffer.count(nextIndex)) {
    auto nextBlk = futureBlockBuffer[nextIndex];
    futureBlockBuffer.erase(nextIndex);
    std::cout << "⏩ Processing buffered block: " << nextIndex << "\n";
    handleNewBlock(nextBlk, "");
    ++nextIndex;
  }
}

// Black list peer
void Network::blacklistPeer(const std::string &peer) {
  if (anchorPeers.count(peer)) {
    std::cerr << "ℹ️  [ban] skipping anchor/selfheal peer " << peer << '\n';
    return;
  }
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end()) {
      it->second.state->banUntil =
          std::chrono::steady_clock::now() + std::chrono::hours(24);
    }
    peerTransports.erase(peer);
  }
  // ban peer for 24 hours
  bannedPeers[peer] = std::time(nullptr) + 24 * 60 * 60;
}

bool Network::isBlacklisted(const std::string &peer) {
  auto it = bannedPeers.find(peer);
  if (it == bannedPeers.end())
    return false;
  // clear expired ban
  if (std::time(nullptr) >= it->second) {
    bannedPeers.erase(it);
    std::cerr << "ℹ️  [ban] unbanned peer " << peer << '\n';
    return false;
  }
  return true;
}

// ✅ **Send Data to Peer with Error Handling**

bool Network::sendData(std::shared_ptr<Transport> transport,
                       const std::string &data) {
  if (!transport || !transport->isOpen()) {
    std::cerr << "❌ [sendData] Transport is null or closed\n";
    return false;
  }
  try {
    std::string finalMessage = data;
    while (!finalMessage.empty() &&
           (finalMessage.back() == '\n' || finalMessage.back() == '\r')) {
      finalMessage.pop_back();
    }
    finalMessage += '\n';

    transport->queueWrite(finalMessage, false);
    std::cout << "📡 [DEBUG] Queued message to transport: "
              << finalMessage.substr(0, 100) << "...\n";
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

  if (peerSupportsSnapshot(peer))
    requestSnapshotSync(peer);
  else if (peerSupportsAggProof(peer))
    requestEpochHeaders(peer);
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

    ioContext.restart(); // Must come before async_accept
    listenForConnections();

    std::thread ioThread([this]() {
      std::cout << "🚀 IO context thread started for port " << std::dec << port
                << "\n";
      try {
        ioContext.run();
        std::cout << "✅ IO context exited normally for port " << std::dec
                  << port << "\n";
      } catch (const std::exception &e) {
        std::cerr << "❌ [IOContext] Exception: " << e.what() << "\n";
      }
    });

    ioThread.detach(); // Detach safely
  } catch (const std::exception &e) {
    std::cerr << "❌ [ERROR] Server failed to start: " << e.what() << "\n";
    std::cerr << "⚠️ Try using a different port or checking if another instance "
                 "is running.\n";
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
        std::cerr << "❌ [ERROR] Peer not found or transport null: " << peer
                  << std::endl;
        return "";
      }
      transport = it->second.tx;
    }
    return transport->readLineWithTimeout(
        3); // Assuming Transport has this method!
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

  peerTransports.emplace(peer,
                         PeerEntry{transport, std::make_shared<PeerState>(), false});
  std::cout << "📡 Peer added: " << peer << std::endl;
  savePeers(); // ✅ Save immediately
}

// ------------------------------------------------------------------
//  Helper: send our handshake right after connecting outbound
// ------------------------------------------------------------------
bool Network::finishOutboundHandshake(std::shared_ptr<Transport> tx,
                                      std::array<uint8_t, 32> &privOut) {
  if (!tx || !tx->isOpen())
    return false;
  alyncoin::net::Handshake hs = buildHandshake();
  std::array<uint8_t, 32> pub{};
  randombytes_buf(privOut.data(), privOut.size());
  crypto_scalarmult_curve25519_base(pub.data(), privOut.data());
  hs.set_pub_key(std::string(reinterpret_cast<char *>(pub.data()), pub.size()));
  alyncoin::net::Frame fr;
  *fr.mutable_handshake() = hs;
  if (!sendFrameImmediate(tx, fr))
    return false;
  // Provide our current height immediately after the handshake
  std::string peer = tx->getRemoteIP() + ':' + std::to_string(tx->getRemotePort());
  sendHeight(peer);
  return true;
}

// ------------------------------------------------------------------
//  Helper: send the three “kick-off” messages after a connection
// ------------------------------------------------------------------
void Network::sendInitialRequests(const std::string &peerId) {
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end() || !it->second.tx)
    return;

  alyncoin::net::Frame f1;
  f1.mutable_height_req();
  sendFrame(it->second.tx, f1);

  alyncoin::net::Frame f2;
  f2.mutable_tip_hash_req();
  sendFrame(it->second.tx, f2);

  alyncoin::net::Frame f3;
  f3.mutable_peer_list_req();
  sendFrame(it->second.tx, f3);

  // Only request a snapshot if the peer reports a higher height.
  int peerHeight = peerManager ? peerManager->getPeerHeight(peerId) : -1;
  int localHeight = Blockchain::getInstance().getHeight();
  if (peerHeight > localHeight) {
    if (peerSupportsSnapshot(peerId))
      requestSnapshotSync(peerId);
    else if (peerSupportsAggProof(peerId))
      requestEpochHeaders(peerId);
  }

  sendInventory(peerId);
}
// ------------------------------------------------------------------
//  Helper: set up an endless async-read loop for a socket
// ------------------------------------------------------------------
void Network::startBinaryReadLoop(const std::string &peerId,
                                  std::shared_ptr<Transport> transport) {
  if (!transport || !transport->isOpen())
    return;
  auto cb = [this, peerId](const boost::system::error_code &ec,
                           const std::string &blob) {
    if (ec) {
      std::cerr << "[readLoop] " << peerId << " closed (" << ec.message()
                << ")\n";
      markPeerOffline(peerId);
      return;
    }

    auto it = peerTransports.find(peerId);
    if (it != peerTransports.end()) {
      auto &st = *it->second.state;
      st.frameCountMin++;
      st.byteCountMin += blob.size();
      if (!anchorPeers.count(peerId)) {
        if (st.frameCountMin > FRAME_LIMIT_MIN ||
            st.byteCountMin > BYTE_LIMIT_MIN) {
          st.limitStrikes++;
          st.misScore += 5;
          if (st.limitStrikes >= 3)
            blacklistPeer(peerId);
        }
        if (st.misScore >= 100)
          blacklistPeer(peerId);
      }
    }

    alyncoin::net::Frame f;
    if (f.ParseFromString(blob)) {
      std::cerr << "[readLoop] ✅ Parsed frame successfully from peer: "
                << peerId << '\n';
      auto *item = new RxItem{f, peerId};
      while (!rxQ.push(item))
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else {
      std::cerr << "[readLoop] ❌ Failed to parse protobuf frame!" << '\n';
    }
  };
  transport->startReadBinaryLoop(cb);
  std::cout << "🔄 Binary read-loop armed for " << peerId << '\n';
}

void Network::processFrame(const alyncoin::net::Frame &f, const std::string &peer) {
  dispatch(f, peer);
}

void Network::dispatch(const alyncoin::net::Frame &f, const std::string &peer) {
  WireFrame tag = WireFrame::OTHER;
  if (f.has_handshake())
    tag = WireFrame::HANDSHAKE;
  else if (f.has_height_req() || f.has_height_res())
    tag = WireFrame::HEIGHT;
  else if (f.has_peer_list())
    tag = WireFrame::PEER_LIST;
  else if (f.has_block_broadcast())
    tag = WireFrame::BLOCK;
  else if (f.has_snapshot_meta())
    tag = WireFrame::SNAP_META;
  else if (f.has_snapshot_chunk())
    tag = WireFrame::SNAP_CHUNK;
  else if (f.has_snapshot_end())
    tag = WireFrame::SNAP_END;
  std::cerr << "[<<] Incoming Frame from " << peer << " Type=" << static_cast<int>(tag)
            << "\n";
  switch (f.kind_case()) {
  case alyncoin::net::Frame::kHandshake: {
    const auto &hs = f.handshake();
    if (peerManager)
      peerManager->setPeerHeight(peer, hs.height());
    break;
  }
  case alyncoin::net::Frame::kBlockBroadcast: {
    Block blk = Block::fromProto(f.block_broadcast().block());
    std::cerr << "[dispatch] kBlockBroadcast frame detected. idx="
              << blk.getIndex() << " hash=" << blk.getHash() << '\n';
    handleNewBlock(blk, peer);
    break;
  }
  case alyncoin::net::Frame::kBlockBatch: {
    penalizePeer(peer, 20);
    std::cerr << "[WARN] obsolete block_batch frame from " << peer << '\n';
    return;
  }
  case alyncoin::net::Frame::kBlockRequest: {
    uint64_t idx = f.block_request().index();
    Blockchain &bc = Blockchain::getInstance();
    if (idx < bc.getChain().size()) {
      alyncoin::net::Frame out;
      *out.mutable_block_response()->mutable_block() =
          bc.getChain()[static_cast<size_t>(idx)].toProtobuf();
      auto it = peerTransports.find(peer);
      if (it != peerTransports.end() && it->second.tx)
        sendFrame(it->second.tx, out);
    }
    break;
  }
  case alyncoin::net::Frame::kBlockResponse: {
    Block blk = Block::fromProto(f.block_response().block());
    handleNewBlock(blk, peer);
    break;
  }
  case alyncoin::net::Frame::kPing: {
    alyncoin::net::Frame out;
    out.mutable_pong();
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end())
      sendFrame(it->second.tx, out);
    break;
  }
  case alyncoin::net::Frame::kHeightReq:
    sendHeight(peer);
    break;
  case alyncoin::net::Frame::kHeightRes:
    if (peerManager) {
      peerManager->setPeerHeight(peer, f.height_res().height());
      peerManager->setPeerWork(peer, f.height_res().total_work());
    }
    {
      auto it = peerTransports.find(peer);
      if (it != peerTransports.end() && it->second.state)
        it->second.state->highestSeen = f.height_res().height();
    }
    if (f.height_res().height() > Blockchain::getInstance().getHeight() &&
        !isSyncing())
      requestTailBlocks(peer, Blockchain::getInstance().getHeight());
    break;
  case alyncoin::net::Frame::kHeightProbe:
    if (peerManager) {
      peerManager->setPeerHeight(peer, f.height_probe().height());
      peerManager->setPeerWork(peer, f.height_probe().total_work());
    }
    break;
  case alyncoin::net::Frame::kSnapshotMeta:
    handleSnapshotMeta(peer, f.snapshot_meta());
    break;
  case alyncoin::net::Frame::kSnapshotChunk:
    handleSnapshotChunk(peer, f.snapshot_chunk().data());
    break;
  case alyncoin::net::Frame::kSnapshotAck:
    handleSnapshotAck(peer, f.snapshot_ack().seq());
    break;
  case alyncoin::net::Frame::kSnapshotEnd:
    handleSnapshotEnd(peer);
    break;
  case alyncoin::net::Frame::kTailBlocks:
    handleTailBlocks(peer, f.tail_blocks().SerializeAsString());
    break;
  case alyncoin::net::Frame::kInv: {
    std::vector<std::string> hashes;
    for (const auto &h : f.inv().hashes())
      hashes.push_back(h);
    std::vector<std::string> missing;
    Blockchain &bc = Blockchain::getInstance();
    for (const auto &h : hashes)
      if (!bc.hasBlockHash(h))
        missing.push_back(h);
    if (!missing.empty()) {
      alyncoin::net::Frame req;
      auto *gd = req.mutable_get_data();
      for (const auto &h : missing)
        gd->add_hashes(h);
      auto it = peerTransports.find(peer);
      if (it != peerTransports.end())
        sendFrame(it->second.tx, req);
    }
    break;
  }
  case alyncoin::net::Frame::kGetData: {
    std::vector<std::string> hashes;
    for (const auto &h : f.get_data().hashes())
      hashes.push_back(h);
    handleGetData(peer, hashes);
    break;
  }
  case alyncoin::net::Frame::kGetHeaders: {
    std::string start = f.get_headers().from_hash();
    int startIdx = -1;
    const auto &ch = Blockchain::getInstance().getChain();
    for (size_t i = 0; i < ch.size(); ++i) {
      if (ch[i].getHash() == start) {
        startIdx = static_cast<int>(i) + 1;
        break;
      }
    }
    if (startIdx != -1) {
      alyncoin::net::Frame out;
      auto *hdr = out.mutable_headers();
      for (size_t i = startIdx; i < ch.size(); ++i)
        *hdr->add_headers() = ch[i].toProtobuf();
      auto it = peerTransports.find(peer);
      if (it != peerTransports.end() && it->second.tx)
        sendFrame(it->second.tx, out);
    }
    break;
  }
  case alyncoin::net::Frame::kHeaders: {
    HeadersSync::handleHeaders(peer, f.headers());
    break;
  }
  case alyncoin::net::Frame::kTipHashReq:
    sendTipHash(peer);
    break;
  case alyncoin::net::Frame::kTipHashRes:
    if (f.tip_hash_res().hash().size() != 64) {
      std::cerr << "⚠️  [dispatch] malformed tip hash from " << peer << "\n";
      if (peerManager)
        peerManager->disconnectPeer(peer);
      {
        auto it = peerTransports.find(peer);
        if (it != peerTransports.end()) {
          it->second.state->misScore += 100;
          if (it->second.state->misScore >= 100)
            blacklistPeer(peer);
        }
      }
      break;
    }
    if (peerManager)
      peerManager->recordTipHash(peer, f.tip_hash_res().hash());
    break;
  case alyncoin::net::Frame::kPeerListReq:
    sendPeerList(peer);
    break;
  case alyncoin::net::Frame::kPeerList: {
    for (const auto &p : f.peer_list().peers()) {
      size_t pos = p.find(':');
      if (pos == std::string::npos)
        continue;
      std::string ip = p.substr(0, pos);
      int port = std::stoi(p.substr(pos + 1));
      if ((ip == "127.0.0.1" || ip == "localhost") && port == this->port)
        continue;
      if (peerTransports.count(p))
        continue;
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
    const std::string &blob = f.agg_proof().data();
    if (blob.size() <= sizeof(int) + 64) {
      std::cerr << "❌ [agg_proof] malformed proof from " << peer << '\n';
      auto itBad = peerTransports.find(peer);
      if (itBad != peerTransports.end())
        itBad->second.state->misScore += 100;
      blacklistPeer(peer);
      break;
    }

    int epoch = 0;
    std::memcpy(&epoch, blob.data(), sizeof(int));
    std::string root = blob.substr(sizeof(int), 64);
    std::vector<uint8_t> proof(blob.begin() + sizeof(int) + 64, blob.end());

    {
      std::lock_guard<std::mutex> lk(epochProofMutex);
      receivedEpochProofs[epoch] = {root, proof};
    }
    std::cerr << "[agg_proof] stored proof for epoch " << epoch << '\n';
    break;
  }
  case alyncoin::net::Frame::kTxBroadcast: {
    Transaction tx = Transaction::fromProto(f.tx_broadcast().tx());
    receiveTransaction(tx);
    break;
  }
  case alyncoin::net::Frame::kWhisper: {
    if (f.whisper().data().size() < 25)
      break;
    crypto::SphinxPacket pkt;
    uint8_t len = static_cast<uint8_t>(f.whisper().data()[24]);
    size_t hdrSize = 25 + len;
    if (f.whisper().data().size() < hdrSize)
      break;
    pkt.header.assign(f.whisper().data().begin(),
                      f.whisper().data().begin() + hdrSize);
    pkt.payload.assign(f.whisper().data().begin() + hdrSize,
                       f.whisper().data().end());
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end())
      break;
    crypto::SphinxPacket inner;
    std::string nextHop;
    if (!crypto::peelPacket(pkt,
                            std::vector<uint8_t>(it->second.state->linkKey.begin(),
                                                 it->second.state->linkKey.end()),
                            &nextHop, &inner))
      break;
    if (!nextHop.empty()) {
      auto itF = peerTransports.find(nextHop);
      if (itF != peerTransports.end() && itF->second.tx && itF->second.tx->isOpen()) {
        alyncoin::net::Frame fr;
        fr.mutable_whisper()->set_data(std::string(inner.header.begin(), inner.header.end()) +
                                       std::string(inner.payload.begin(), inner.payload.end()));
        std::this_thread::sleep_for(std::chrono::milliseconds(50 + rand() % 101));
        sendFrame(itF->second.tx, fr);
      }
    } else {
      std::string blob(inner.header.begin(), inner.header.end());
      blob.append(inner.payload.begin(), inner.payload.end());
      alyncoin::net::Frame innerFr;
      if (innerFr.ParseFromString(blob))
        dispatch(innerFr, peer);
    }
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

bool Network::connectToNode(const std::string &host, int remotePort) {
  if (peerTransports.size() >= MAX_PEERS) {
    std::cerr << "⚠️ [connectToNode] peer cap reached, skip " << host << ':'
              << remotePort << '\n';
    return false;
  }

  const std::string peerKey = host + ':' + std::to_string(remotePort);
  // Use our own listening port to recognize self-connections.
  const auto selfAddr = [this] {
    return publicPeerId.empty() ? "127.0.0.1:" + std::to_string(this->port)
                                : publicPeerId;
  };
  if (isBlacklisted(peerKey)) {
    std::cerr << "⚠️ [connectToNode] " << peerKey << " is banned.\n";
    return false;
  }
  {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    auto it = peerTransports.find(peerKey);
    if (it != peerTransports.end() &&
        std::chrono::steady_clock::now() < it->second.state->banUntil) {
      std::cerr << "⚠️ [connectToNode] " << peerKey
                << " is temporarily banned." << '\n';
      return false;
    }
  }

  std::string prefix = ipPrefix(host);
  if (!prefix.empty()) {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    int count = 0;
    for (const auto &kv : peerTransports) {
      std::string ip = kv.first.substr(0, kv.first.find(':'));
      if (ipPrefix(ip) == prefix)
        ++count;
    }
    if (count >= 2) {
      std::cerr << "⚠️ [connectToNode] prefix limit reached for " << host
                << " (" << prefix << " count=" << count << ")" << '\n';
      return false;
    }
  }

  try {
    std::cout << "[PEER_CONNECT] → " << host << ':' << remotePort << '\n';

    std::shared_ptr<Transport> tx;
    if (getAppConfig().enable_tls && tlsContext) {
      auto sslTx = std::make_shared<SslTransport>(ioContext, *tlsContext);
      if (!sslTx->connect(host, remotePort)) {
        std::cerr << "❌ [connectToNode] Connection to " << host << ':' << remotePort
                  << " failed." << '\n';
        return false;
      }
      tx = sslTx;
    } else {
      auto plain = std::make_shared<TcpTransport>(ioContext);
      if (!plain->connect(host, remotePort)) {
      std::cerr << "❌ [connectToNode] Connection to " << host << ':' << remotePort
                << " failed." << '\n';
      return false;
      }
      tx = plain;
    }

    {
      ScopedLockTracer _t("connectToNode");
      std::lock_guard<std::timed_mutex> g(peersMutex);
      auto it = peerTransports.find(peerKey);
      if (it != peerTransports.end() && it->second.tx && it->second.tx->isOpen()) {
        bool keepNew = false;
        bool newInitiated = true;
        if (it->second.initiatedByUs == newInitiated) {
          keepNew = false; // same initiator -> keep existing
        } else {
          if (selfAddr() < peerKey)
            keepNew = newInitiated;
          else
            keepNew = !newInitiated;
        }
        if (!keepNew) {
          std::cout << "🔁 already connected to " << peerKey << '\n';
          if (tx)
            tx->closeGraceful();
          return false;
        } else {
          std::cout << "🔁 replacing connection to " << peerKey << '\n';
          if (it->second.tx)
            it->second.tx->closeGraceful();
          it->second.tx = tx;
          it->second.initiatedByUs = newInitiated;
        }
      }
    }

    /* our handshake */
    std::array<uint8_t, 32> myPriv{};
    if (!finishOutboundHandshake(tx, myPriv)) {
      std::cerr << "❌ [connectToNode] failed to send handshake to " << peerKey
                << '\n';
      return false;
    }

    /* read their handshake (30 s timeout) */
    std::string blob;
    if (auto tcp = std::dynamic_pointer_cast<TcpTransport>(tx)) {
      if (!tcp->waitReadable(30)) {
        std::cerr << "⚠️ [connectToNode] handshake timeout for " << peerKey
                  << '\n';
        std::lock_guard<std::timed_mutex> g(peersMutex);
        auto it = peerTransports.find(peerKey);
        if (it != peerTransports.end() && it->second.tx &&
            it->second.tx->isOpen()) {
          tcp->close();
        } else {
          peerTransports.erase(peerKey);
        }
        return false;
      }
      blob = tcp->readBinaryBlocking();
    } else if (auto ssl = std::dynamic_pointer_cast<SslTransport>(tx)) {
      if (!ssl->waitReadable(30)) {
        std::cerr << "⚠️ [connectToNode] handshake timeout for " << peerKey
                  << '\n';
        std::lock_guard<std::timed_mutex> g(peersMutex);
        auto it = peerTransports.find(peerKey);
        if (it != peerTransports.end() && it->second.tx &&
            it->second.tx->isOpen()) {
          ssl->close();
        } else {
          peerTransports.erase(peerKey);
        }
        return false;
      }
      blob = ssl->readBinaryBlocking();
    } else {
      blob = tx->readBinaryBlocking();
    }

    bool theirAgg = false;
    bool theirSnap = false;
    bool theirWhisper = false;
    bool theirTls = false;
    bool theirBanDecay = false;
    int theirHeight = 0;
    uint32_t remoteRev = 0;
    alyncoin::net::Frame fr;
    if (blob.empty() || !fr.ParseFromString(blob) || !fr.has_handshake()) {
      std::cerr << "⚠️ [connectToNode] invalid handshake from " << peerKey
                << '\n';
      std::lock_guard<std::timed_mutex> g(peersMutex);
      auto it = peerTransports.find(peerKey);
      if (it != peerTransports.end() && it->second.tx && it->second.tx->isOpen()) {
        if (auto tcp = std::dynamic_pointer_cast<TcpTransport>(tx))
          tcp->close();
        else if (auto ssl = std::dynamic_pointer_cast<SslTransport>(tx))
          ssl->close();
      } else {
        peerTransports.erase(peerKey);
      }
      return false;
    }
    const auto &rhs = fr.handshake();
    theirHeight = static_cast<int>(rhs.height());

    // ─── Compatibility gate ────────────────────────────
    remoteRev = rhs.frame_rev();
    if (remoteRev != 0 && remoteRev != kFrameRevision) {
      std::cerr << "⚠️ [handshake] peer uses frame_rev=" << remoteRev
                << " but we need " << kFrameRevision
                << " – dropping for incompatibility." << '\n';
      tx->close();
      return false;
    }
    for (const auto &c : rhs.capabilities()) {
      if (c == "agg_proof_v1")
        theirAgg = true;
      if (c == "snapshot_v1")
        theirSnap = true;
      if (c == "whisper_v1")
        theirWhisper = true;
      if (c == "tls_v1")
        theirTls = true;
      if (c == "ban_decay_v1")
        theirBanDecay = true;
    }

    std::array<uint8_t, 32> shared{};
    if (rhs.pub_key().size() == 32)
      (void)crypto_scalarmult_curve25519(
          shared.data(), myPriv.data(),
          reinterpret_cast<const unsigned char *>(rhs.pub_key().data()));

    {
      ScopedLockTracer t("connectToNode/register");
      std::lock_guard<std::timed_mutex> lk(peersMutex);
      if (peerTransports.count(peerKey)) {
        std::cout << "🔁 already connected to " << peerKey << '\n';
        // ensure pending handshake is cleaned up before returning
        if (tx)
          tx->close();
        return false;
      }
      int oldTail = -1;
      if (peerTransports.count(peerKey) && peerTransports[peerKey].state)
        oldTail = peerTransports[peerKey].state->lastTailHeight;
      peerTransports[peerKey] = {tx, std::make_shared<PeerState>(), true};
      knownPeers.insert(peerKey);
      if (anchorPeers.size() < 2)
        anchorPeers.insert(peerKey);
      auto st = peerTransports[peerKey].state;
        st->supportsAggProof = theirAgg;
        st->supportsSnapshot = theirSnap;
        st->supportsWhisper = theirWhisper;
        st->supportsTls = theirTls;
        st->supportsBanDecay = theirBanDecay;
        st->frameRev = remoteRev;
        st->version = rhs.version();
      if (oldTail >= 0)
        st->lastTailHeight = oldTail;
      else
        st->lastTailHeight = theirHeight;
        st->highestSeen = static_cast<uint32_t>(theirHeight);
      if (rhs.pub_key().size() == 32)
        std::copy(shared.begin(), shared.end(), st->linkKey.begin());
      if (peerManager) {
        if (peerManager->registerPeer(peerKey))
          peerManager->setPeerHeight(peerKey, theirHeight);
      }
    }

    /* pick correct sync action now */
    const int localHeight = Blockchain::getInstance().getHeight();
    if (theirHeight > localHeight) {
      if (theirSnap)
        requestSnapshotSync(peerKey);
      else if (theirAgg)
        requestEpochHeaders(peerKey);
    } else if (theirHeight < localHeight && theirSnap)
      sendTailBlocks(tx, theirHeight, peerKey);

    startBinaryReadLoop(peerKey, tx);
    sendInitialRequests(peerKey);

    autoSyncIfBehind();
    intelligentSync();
    return true;
  } catch (const std::exception &e) {
    std::cerr << "❌ [connectToNode] " << host << ':' << remotePort << " – "
              << e.what() << '\n';
    return false;
  }
}
//
void Network::handleReceivedBlockIndex(const std::string &peerIP,
                                       int peerBlockIndex) {
  int localIndex = Blockchain::getInstance().getLatestBlock().getIndex();

  if (localIndex <= 0) { // Only genesis present
    std::cout << "⚠️ [Node] Only Genesis block found locally. Requesting "
                 "snapshot from "
              << peerIP << "\n";
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
    std::cerr
        << "⚠️ [loadPeers] peers.txt not found, skipping manual mesh restore.\n";
    return;
  }

  std::string line;
  while (std::getline(file, line)) {
    if (line.empty())
      continue;
    std::istringstream iss(line);
    std::string addr;
    std::string keyB64;
    iss >> addr >> keyB64;
    if (addr.find(":") == std::string::npos)
      continue;
    std::string ip = addr.substr(0, addr.find(":"));
    int portVal = std::stoi(addr.substr(addr.find(":") + 1));
    std::string peerKey = ip + ":" + std::to_string(portVal);

    // Exclude self and local-only
    if (isSelfPeer(peerKey))
      continue;
    if (ip == "127.0.0.1" || ip == "localhost")
      continue;

    if (connectToNode(ip, portVal)) {
      std::cout << "✅ Peer loaded & connected: " << line << "\n";
      if (!keyB64.empty()) {
        std::string decoded = Crypto::base64Decode(keyB64, false);
        if (decoded.size() == 32) {
          std::lock_guard<std::timed_mutex> lk(peersMutex);
          auto it = peerTransports.find(peerKey);
          if (it != peerTransports.end() && it->second.state)
            std::copy(decoded.begin(), decoded.end(),
                      it->second.state->linkKey.begin());
        }
      }
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
  std::vector<std::string> potentialPeers =
      fetchPeersFromDNS("peers.alyncoin.com");
  std::cout << "🔍 [DNS] Scanning for AlynCoin nodes..." << std::endl;

  for (const auto &peer : potentialPeers) {
    std::string ip = peer.substr(0, peer.find(":"));
    int peerPort = std::stoi(peer.substr(peer.find(":") + 1));
    std::string peerKey = ip + ":" + std::to_string(peerPort);
    if (isSelfPeer(peerKey))
      continue;
    if (ip == "127.0.0.1" || ip == "localhost")
      continue;
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

  for (const auto &[peer, entry] : peerTransports) {
    if (!peer.empty() && peer.find(":") != std::string::npos) {
      std::string keyStr = Crypto::base64Encode(std::string(
          entry.state->linkKey.begin(), entry.state->linkKey.end()), false);
      file << peer << ' ' << keyStr << std::endl;
    }
  }

  file.close();
  std::cout << "✅ Peer list saved successfully. Total peers: "
            << peerTransports.size() << std::endl;
}

// ✅ **Broadcast Latest Block Correctly (Base64 Encoded)**
void Network::sendLatestBlock(const std::string &peerIP) {
  Blockchain &blockchain = Blockchain::getInstance();
  if (blockchain.getChain().empty())
    return;
  Block latestBlock = blockchain.getLatestBlock();
  sendBlockToPeer(peerIP, latestBlock);
}

void Network::sendInventory(const std::string &peer) {
  Blockchain &bc = Blockchain::getInstance();
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  uint32_t start = 0;
  if (it->second.state)
    start = it->second.state->highestSeen + 1;
  const auto &chain = bc.getChain();
  for (size_t i = start; i < chain.size(); i += MAX_INV_PER_MSG) {
    alyncoin::net::Frame fr;
    auto *inv = fr.mutable_inv();
    for (size_t j = i; j < chain.size() && j < i + MAX_INV_PER_MSG; ++j)
      inv->add_hashes(chain[j].getHash());
    sendFrame(it->second.tx, fr);
  }
}

// cleanup
void Network::cleanupPeers() {
  ScopedLockTracer tracer("cleanupPeers");
  static auto lastDecay = std::chrono::steady_clock::now();
  bool doDecay = false;
  auto nowSteady = std::chrono::steady_clock::now();
  if (nowSteady - lastDecay >= std::chrono::minutes(1)) {
    doDecay = true;
    lastDecay = nowSteady;
  }
  std::vector<std::string> inactivePeers;
  {
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    for (const auto &peer : peerTransports) {
      try {
        if (!peer.second.tx || !peer.second.tx->isOpen()) {
          std::cerr << "⚠️ Peer transport closed: " << peer.first << "\n";
          if (!anchorPeers.count(peer.first))
            inactivePeers.push_back(peer.first);
          continue;
        }

        auto st = peer.second.state;
        if (st && st->frameRev == kFrameRevision) {
          alyncoin::net::Frame f;
          f.mutable_ping();
          sendFrame(peer.second.tx, f);
        }

        std::cout << "✅ Peer active: " << peer.first << "\n";
      } catch (const std::exception &e) {
        std::cerr << "⚠️ Exception checking peer " << peer.first << ": "
                  << e.what() << "\n";
        if (!anchorPeers.count(peer.first))
          inactivePeers.push_back(peer.first);
      }
      if (doDecay) {
        auto st = peer.second.state;
        if (st && st->misScore > 0)
          st->misScore--;
        if (st && st->banUntil != std::chrono::steady_clock::time_point{} &&
            nowSteady >= st->banUntil) {
          st->banUntil = std::chrono::steady_clock::time_point{};
          std::cerr << "ℹ️  [ban] unbanned peer " << peer.first << '\n';
        }
      }
    }

    for (const auto &peer : inactivePeers) {
      peerTransports.erase(peer);
      anchorPeers.erase(peer);
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

  std::vector<unsigned char> pubDil =
      Crypto::getPublicKeyDilithium(blk.getMinerAddress());
  std::vector<unsigned char> pubFal =
      Crypto::getPublicKeyFalcon(blk.getMinerAddress());

  if (!Crypto::verifyWithDilithium(msgBytes, sigDil, pubDil)) {
    std::cerr << "Invalid Dilithium signature for block: " << blk.getHash()
              << std::endl;
    return false;
  }

  if (!Crypto::verifyWithFalcon(msgBytes, sigFal, pubFal)) {
    std::cerr << "Invalid Falcon signature for block: " << blk.getHash()
              << std::endl;
    return false;
  }

  return true;
}
//
void Network::broadcastRollupBlock(const RollupBlock &rollup) {
  ScopedLockTracer tracer("broadcastRollupBlock");
  std::lock_guard<std::timed_mutex> lock(peersMutex);
  for (const auto &[peerID, entry] : peerTransports) {
    auto transport = entry.tx;
    if (transport && transport->isOpen()) {
      alyncoin::net::Frame fr;
      fr.mutable_rollup_block()->set_data(rollup.serialize());
      sendFrame(transport, fr);
    }
  }
}
//
void Network::broadcastEpochProof(int epochIdx, const std::string &rootHash,
                                  const std::vector<uint8_t> &proofBytes) {
  ScopedLockTracer tracer("broadcastEpochProof");
  std::lock_guard<std::timed_mutex> lock(peersMutex);
  for (const auto &[peerID, entry] : peerTransports) {
    auto transport = entry.tx;
    if (transport && transport->isOpen()) {
      alyncoin::net::Frame fr;
      std::string blob;
      blob.reserve(sizeof(int) + rootHash.size() + proofBytes.size());
      blob.append(reinterpret_cast<const char *>(&epochIdx), sizeof(int));
      blob.append(rootHash);
      blob.append(proofBytes.begin(), proofBytes.end());
      fr.mutable_agg_proof()->set_data(blob);
      sendFrame(transport, fr);
    }
  }
}
//
bool Network::peerSupportsAggProof(const std::string &peerId) const {
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end())
    return false;
  auto st = it->second.state;
  return st ? st->supportsAggProof : false;
}
//
bool Network::peerSupportsSnapshot(const std::string &peerId) const {
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end())
    return false;
  auto st = it->second.state;
  return st ? st->supportsSnapshot : false;
}

bool Network::peerSupportsWhisper(const std::string &peerId) const {
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end())
    return false;
  auto st = it->second.state;
  return st ? st->supportsWhisper : false;
}

bool Network::peerSupportsTls(const std::string &peerId) const {
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end())
    return false;
  auto st = it->second.state;
  return st ? st->supportsTls : false;
}
//
void Network::sendSnapshot(std::shared_ptr<Transport> transport,
                           int upToHeight) {
  Blockchain &bc = Blockchain::getInstance();
  int height = upToHeight < 0 ? bc.getHeight() : upToHeight;
  std::vector<Block> blocks = bc.getChainUpTo(height); // Implement as needed
  SnapshotProto snap;
  snap.set_height(height);
  snap.set_merkle_root(bc.getHeaderMerkleRoot());
  for (const auto &blk : blocks)
    *snap.add_blocks() = blk.toProtobuf();

  std::string raw;
  if (!snap.SerializeToString(&raw))
    return;

  const size_t CHUNK_SIZE = MAX_SNAPSHOT_CHUNK_SIZE;
  // --- Send metadata first ---
  alyncoin::net::Frame meta;
  meta.mutable_snapshot_meta()->set_height(height);
  meta.mutable_snapshot_meta()->set_root_hash(bc.getHeaderMerkleRoot());
  meta.mutable_snapshot_meta()->set_total_bytes(raw.size());
  meta.mutable_snapshot_meta()->set_chunk_size(CHUNK_SIZE);
  sendFrame(transport, meta);

  // --- Stream snapshot in bounded chunks ---
  uint32_t seq = 0;
  for (size_t off = 0; off < raw.size(); off += CHUNK_SIZE) {
    size_t len = std::min(CHUNK_SIZE, raw.size() - off);
    alyncoin::net::Frame fr;
    fr.mutable_snapshot_chunk()->set_data(raw.substr(off, len));
    sendFrame(transport, fr);
    ++seq;
  }
  alyncoin::net::Frame end;
  end.mutable_snapshot_end();
  sendFrame(transport, end);
}
//

void Network::sendTailBlocks(std::shared_ptr<Transport> transport,
                             int fromHeight, const std::string &peerId) {
  Blockchain &bc = Blockchain::getInstance();
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end() || !it->second.state)
    return;
  auto ps = it->second.state;
  if (fromHeight < ps->lastTailHeight)
    fromHeight = ps->lastTailHeight;
  if (fromHeight < 0 || fromHeight >= bc.getHeight()) {
    std::cerr << "[sendTailBlocks] aborting: peer height >= local height\n";
    return;
  }
  constexpr std::size_t MSG_LIMIT = MAX_TAIL_PAYLOAD;
  int start = fromHeight + 1;
  int end = std::min(bc.getHeight(), start + MAX_TAIL_BLOCKS - 1);
  std::vector<Block> chainCopy = bc.snapshot();
  auto flushTail = [&](alyncoin::net::TailBlocks &tb) {
    if (tb.blocks_size() == 0)
      return;
    alyncoin::net::Frame f;
    *f.mutable_tail_blocks() = tb;
    sendFrame(transport, f);
  };

  alyncoin::net::TailBlocks proto;
  size_t current = 0;
  for (int i = start; i <= end && i < static_cast<int>(chainCopy.size()); ++i) {
    const auto &bp = chainCopy[i].toProtobuf();
    size_t add = bp.ByteSizeLong();
    if (current && current + add > MSG_LIMIT) {
      flushTail(proto);
      proto.clear_blocks();
      current = 0;
    }
    *proto.add_blocks() = bp;
    current += add;
  }
  flushTail(proto);
  ps->lastTailHeight = end;
  ps->highestSeen = static_cast<uint32_t>(end);
}

void Network::handleSnapshotMeta(const std::string &peer,
                                 const alyncoin::net::SnapshotMeta &meta) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.state)
    return;
  auto ps = it->second.state;
  ps->snapshotExpectBytes = meta.total_bytes();
  ps->snapshotRoot = meta.root_hash();
  ps->snapshotReceived = 0;
  ps->snapshotB64.clear();
  ps->snapState = PeerState::SnapState::WaitChunks;
}

void Network::handleSnapshotAck(const std::string &peer, uint32_t /*seq*/) {
  // Currently unused but reserved for future backpressure logic
}
//
void Network::handleSnapshotChunk(const std::string &peer,
                                  const std::string &chunk) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.state)
    return;
  auto ps = it->second.state;
  if (ps->snapState != PeerState::SnapState::WaitChunks) {
    std::cerr << "⚠️ [SNAPSHOT] Unexpected chunk from " << peer << '\n';
    return;
  }
  if (chunk.size() > MAX_SNAPSHOT_CHUNK_SIZE) {
    std::cerr << "⚠️ [SNAPSHOT] Oversized chunk, clearing buffer\n";
    ps->snapshotActive = false;
    ps->snapState = PeerState::SnapState::Idle;
    ps->snapshotB64.clear();
    return;
  }
  ps->snapshotB64 += chunk;
  ps->snapshotReceived += chunk.size();
  ps->snapshotActive = true;
  alyncoin::net::Frame ack;
  ack.mutable_snapshot_ack()->set_seq(ps->snapshotReceived);
  sendFrame(it->second.tx, ack);
}

//
void Network::handleTailRequest(const std::string &peer, int fromHeight) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  sendTailBlocks(it->second.tx, fromHeight, peer);
}
void Network::handleSnapshotEnd(const std::string &peer) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.state)
    return;
  auto ps = it->second.state;
  std::cerr << "[SNAPSHOT] 🔴 SnapshotEnd from " << peer
            << ", total buffered=" << ps->snapshotB64.size() << " bytes\n";

  if (ps->snapState != PeerState::SnapState::WaitChunks) {
    std::cerr << "⚠️ [SNAPSHOT] Unexpected end from " << peer << '\n';
    ps->snapshotB64.clear();
    ps->snapshotActive = false;
    ps->snapState = PeerState::SnapState::Idle;
    return;
  }
  if (ps->snapshotReceived != ps->snapshotExpectBytes) {
    std::cerr << "⚠️ [SNAPSHOT] Size mismatch: expected "
              << ps->snapshotExpectBytes << " got " << ps->snapshotReceived
              << '\n';
    ps->snapshotB64.clear();
    ps->snapshotActive = false;
    ps->snapState = PeerState::SnapState::Idle;
    return;
  }
  try {
    std::string raw = ps->snapshotB64;
    SnapshotProto snap;
    if (!snap.ParseFromString(raw))
      throw std::runtime_error("Bad snapshot");

    Blockchain &chain = Blockchain::getInstance();

    // --- Validate snapshot height and integrity ---
    // Accept a genesis-only snapshot (height can be 0)
    if (snap.height() < 0 || snap.blocks_size() == 0)
      throw std::runtime_error("Empty snapshot");
    if (static_cast<size_t>(snap.height()) != snap.blocks_size() - 1) {
      throw std::runtime_error("Snapshot height mismatch");
    }

    // --- Replace local chain up to snapshot height ---
    std::vector<Block> snapBlocks;
    for (const auto &pb : snap.blocks()) {
      snapBlocks.push_back(Block::fromProto(pb, false));
    }

    for (const auto &b : snapBlocks) {
      if (!b.isGenesisBlock() && !b.hasValidProofOfWork())
        throw std::runtime_error("Snapshot block failed PoW");
    }

    // --- Quick path: height == localHeight + 1 -> treat as tail push
    int localHeight = chain.getHeight();
    if (snap.height() == localHeight + 1 && snapBlocks.size() == 1) {
      const Block &b = snapBlocks.front();
      if (chain.addBlock(b)) {
        ps->snapshotActive = false;
        ps->snapshotB64.clear();
        ps->snapState = PeerState::SnapState::Idle;
        if (peerManager) {
          peerManager->setPeerHeight(peer, chain.getHeight());
          auto work = chain.computeCumulativeDifficulty(chain.getChain());
          peerManager->setPeerWork(peer, work.convert_to<uint64_t>());
        }
        chain.broadcastNewTip();
        return;
      } else {
        std::cerr << "⚠️ [SNAPSHOT] Tail push block failed validation\n";
        // fall through to regular snapshot logic
      }
    }

    // [Optional] Validate Merkle root if provided
    if (!snap.merkle_root().empty()) {
      if (!snapBlocks.empty()) {
        std::string localRoot = snapBlocks.back().getMerkleRoot();
        if (localRoot != snap.merkle_root())
          throw std::runtime_error("Merkle root mismatch in snapshot");
      }
    }

    // --- Fork choice: strict cumulative work rule ---
    auto localWork = chain.computeCumulativeDifficulty(chain.getChain());
    auto remoteWork = chain.computeCumulativeDifficulty(snapBlocks);
    uint64_t localW64 = localWork.convert_to<uint64_t>();
    uint64_t remoteW64 = remoteWork.convert_to<uint64_t>();
    std::string localTipHash = chain.getLatestBlockHash();
    std::string remoteTipHash = snapBlocks.empty() ? "" : snapBlocks.back().getHash();
    int reorgDepth = std::max(0, localHeight - snap.height());
    int chk = chain.getCheckpointHeight();
    int maxReorg = MAX_REORG;
    if (chk > 0)
        maxReorg = std::min(maxReorg, localHeight - (chk - 2));
    bool accept = remoteTipHash != localTipHash &&
                  remoteW64 > localW64 * 1.01 &&
                  reorgDepth <= maxReorg;

    if (!accept) {
      std::cerr << "⚠️ [SNAPSHOT] Rejected snapshot from " << peer << " (height "
                << snap.height() << ", work " << remoteW64
                << ") localHeight=" << localHeight << " localWork=" << localW64
                << " reorgDepth=" << reorgDepth << "\n";
      penalizePeer(peer, 50);
      ps->snapshotActive = false;
      ps->snapshotB64.clear();
      return;
    }

    // Actually apply: truncate and replace local chain
    chain.replaceChainUpTo(snapBlocks, snap.height());

    std::cout << "✅ [SNAPSHOT] Applied snapshot from peer " << peer
              << " at height " << snap.height() << "\n";
    ps->snapshotActive = false;
    ps->snapshotB64.clear();
    ps->snapState = PeerState::SnapState::Idle;

    if (peerManager) {
      peerManager->setPeerHeight(peer, snap.height());
      peerManager->setPeerWork(peer, remoteW64);
    }
    chain.broadcastNewTip();

    // Immediately request tail blocks for any missing blocks
    requestTailBlocks(peer, snap.height());

  } catch (const std::exception &ex) {
    std::cerr << "❌ [SNAPSHOT] Failed to apply snapshot from peer " << peer
              << ": " << ex.what() << "\n";
    {
      auto itBad = peerTransports.find(peer);
      if (itBad != peerTransports.end())
        itBad->second.state->misScore += 100;
    }
    blacklistPeer(peer);
    ps->snapshotActive = false;
    ps->snapshotB64.clear();
    ps->snapState = PeerState::SnapState::Idle;
  } catch (...) {
    std::cerr << "❌ [SNAPSHOT] Unknown error applying snapshot from peer "
              << peer << "\n";
    {
      auto itBad = peerTransports.find(peer);
      if (itBad != peerTransports.end())
        itBad->second.state->misScore += 100;
    }
    blacklistPeer(peer);
    ps->snapshotActive = false;
    ps->snapshotB64.clear();
    ps->snapState = PeerState::SnapState::Idle;
  }
}
//
void Network::handleTailBlocks(const std::string &peer,
                               const std::string &data) {
  try {
    alyncoin::net::TailBlocks proto;
    if (!proto.ParseFromString(data))
      throw std::runtime_error("Bad tailblocks");
    Blockchain &chain = Blockchain::getInstance();

    // Convert proto to vector of blocks
    std::vector<Block> blocks;
    blocks.reserve(proto.blocks_size());
    for (const auto &pb : proto.blocks()) {
      blocks.push_back(Block::fromProto(pb, false));
    }

    int tipIndex = chain.getHeight();
    const auto &localChain = chain.getChain();

    size_t pos = 0;
    while (pos < blocks.size() && blocks[pos].getIndex() <= tipIndex) {
      const Block &remote = blocks[pos];
      if (remote.getIndex() < chain.getBlockCount()) {
        const Block &local = localChain[remote.getIndex()];
        if (remote.getHash() != local.getHash()) {
          throw std::runtime_error("Fork mismatch in tail blocks");
        }
      }
      ++pos;
    }

    if (pos == blocks.size())
      return; // nothing new

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

    std::cout << "✅ [TAIL_BLOCKS] Appended " << appended << " of "
              << proto.blocks_size() << " tail blocks from peer " << peer
              << "\n";

    if (peerManager)
      peerManager->setPeerHeight(peer, chain.getHeight());
    chain.broadcastNewTip();
  } catch (const std::exception &ex) {
    std::cerr << "❌ [TAIL_BLOCKS] Failed to apply tail blocks from peer "
              << peer << ": " << ex.what() << "\n";
    {
      auto itBad = peerTransports.find(peer);
      if (itBad != peerTransports.end())
        itBad->second.state->misScore += 100;
    }
    blacklistPeer(peer);
  } catch (...) {
    std::cerr
        << "❌ [TAIL_BLOCKS] Unknown error applying tail blocks from peer "
        << peer << "\n";
    {
      auto itBad = peerTransports.find(peer);
      if (itBad != peerTransports.end())
        itBad->second.state->misScore += 100;
    }
    blacklistPeer(peer);
  }
}

//
void Network::requestSnapshotSync(const std::string &peer) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  auto ps = it->second.state;
  if (ps) {
    ps->snapState = PeerState::SnapState::WaitMeta;
    ps->snapshotB64.clear();
    ps->snapshotReceived = 0;
    ps->snapshotExpectBytes = 0;
  }
  alyncoin::net::Frame fr;
  fr.mutable_snapshot_req();
  sendFrame(it->second.tx, fr);
}

void Network::requestTailBlocks(const std::string &peer, int fromHeight) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  alyncoin::net::Frame fr;
  fr.mutable_tail_req()->set_from_height(fromHeight);
  sendFrame(it->second.tx, fr);
}
//
void Network::sendForkRecoveryRequest(const std::string &peer,
                                      const std::string &tip) {
  auto it = peerTransports.find(peer);
  if (it == peerTransports.end() || !it->second.tx)
    return;
  alyncoin::net::Frame fr;
  if (!tip.empty())
    fr.mutable_snapshot_req()->set_until_hash(tip);
  else
    fr.mutable_snapshot_req();
  sendFrame(it->second.tx, fr);
}

void Network::handleBlockchainSyncRequest(
    const std::string &peer, const alyncoin::BlockchainSyncProto &request) {
  std::cout << "📡 [SYNC REQUEST] Received from " << peer
            << " type: " << request.request_type() << "\n";

  if (request.request_type() == "snapshot") {
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end() && it->second.tx)
      sendSnapshot(it->second.tx, -1);
  } else if (request.request_type() == "epoch_headers") {
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end() && it->second.tx) {
      for (const auto &[epoch, entry] : receivedEpochProofs) {
        std::string blob;
        blob.append(reinterpret_cast<const char *>(&epoch), sizeof(int));
        blob.append(entry.root);
        blob.append(entry.proof.begin(), entry.proof.end());
        alyncoin::net::Frame fr;
        fr.mutable_agg_proof()->set_data(blob);
        sendFrame(it->second.tx, fr);
      }
    }
  } else if (request.request_type() == "latest_block") {
    sendLatestBlock(peer);
  } else {
    std::cerr << "⚠️ [SYNC REQUEST] Unknown request type: "
              << request.request_type() << "\n";
  }
}
