#include "network.h"
#include "blockchain.h"
#include "config.h"
#include "constants.h"
#include "crypto/sphinx.h"
#include "crypto_utils.h"
#include "httplib.h"
#include "proto_utils.h"
#include "protocol_codes.h"
#include "rollup/proofs/proof_verifier.h"
#include "rollup/rollup_block.h"
#include "self_healing/self_healing_node.h"
#include "syncing/headers_sync.h"
#include "tls_utils.h"
#include "transaction.h"
#include "transport/ssl_transport.h"
#include "wire/varint.h"
#include "zk/winterfell_stark.h"
#include <algorithm>
#include <array>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <condition_variable>
#include <queue>
#include <cctype>
#include <chrono>
#include <exception>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <generated/block_protos.pb.h>
#include <generated/net_frame.pb.h>
#include <generated/sync_protos.pb.h>
#include <generated/transaction_protos.pb.h>
#include <google/protobuf/message.h>
#include <google/protobuf/util/json_util.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#ifndef _WIN32
#include <arpa/nameser.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <resolv.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <set>
#include <sodium.h>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#ifdef HAVE_MINIUPNPC
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#ifndef MINIUPNPC_API_VERSION
#define MINIUPNPC_API_VERSION 0
#endif
#endif
#ifdef HAVE_LIBNATPMP
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/select.h>
#endif
#include <natpmp.h>
#endif
#include "transport/pubsub_router.h"
#include "transport/tcp_transport.h"

using namespace alyncoin;

namespace {

constexpr size_t MAX_TRACKED_ENDPOINTS = 1024;
constexpr size_t MAX_UNVERIFIED_ENDPOINTS = 256;

struct ConsensusHints {
  bool hasDifficulty{false};
  bool hasReward{false};
  int difficulty{0};
  double reward{0.0};
};

ConsensusHints parseConsensusHints(
    const ::google::protobuf::RepeatedPtrField<std::string> &capabilities) {
  static constexpr char kPrefix[] = "consensus:";
  ConsensusHints hints;

  for (const auto &cap : capabilities) {
    if (cap.rfind(kPrefix, 0) != 0)
      continue;

    std::string body = cap.substr(sizeof(kPrefix) - 1);
    std::stringstream ss(body);
    std::string token;
    while (std::getline(ss, token, ';')) {
      auto eqPos = token.find('=');
      if (eqPos == std::string::npos)
        continue;

      std::string key = token.substr(0, eqPos);
      std::string value = token.substr(eqPos + 1);

      if (key == "difficulty") {
        try {
          hints.difficulty = std::stoi(value);
          hints.hasDifficulty = true;
        } catch (const std::exception &) {
        }
      } else if (key == "reward") {
        try {
          hints.reward = std::stod(value);
          hints.hasReward = true;
        } catch (const std::exception &) {
        }
      }
    }
  }

  return hints;
}
} // namespace

constexpr auto SNAPSHOT_RESEND_COOLDOWN = std::chrono::seconds(45);

static size_t resolveSnapshotChunkSize(size_t preferred) {
  if (preferred == 0)
    return MAX_SNAPSHOT_CHUNK_SIZE;
  const size_t clamped = std::min(preferred, MAX_SNAPSHOT_CHUNK_SIZE);
  return std::max<size_t>(1, clamped);
}

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

static bool isNumericAddress(const std::string &ip) {
  if (ip.empty())
    return false;
  boost::system::error_code ec;
  boost::asio::ip::make_address(ip, ec);
  return !ec;
}

static bool isRoutableAddress(const std::string &ip) {
  try {
    const auto addr = boost::asio::ip::make_address(ip);
    if (addr.is_unspecified() || addr.is_loopback() || addr.is_multicast())
      return false;
    if (addr.is_v4()) {
      const auto bytes = addr.to_v4().to_bytes();
      if (bytes[0] == 0)
        return false;
      if (bytes[0] == 10)
        return false;
      if (bytes[0] == 127)
        return false;
      if (bytes[0] == 169 && bytes[1] == 254)
        return false; // 169.254.0.0/16 link-local
      if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
        return false;
      if (bytes[0] == 192 && bytes[1] == 168)
        return false;
      if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))
        return false; // benchmarking
      if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
        return false; // carrier-grade NAT
      return true;
    }
    const auto v6 = addr.to_v6();
    if (v6.is_loopback() || v6.is_link_local() || v6.is_site_local())
      return false;
    const auto bytes = v6.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC)
      return false; // fc00::/7 unique local
    return true;
  } catch (const std::exception &) {
    return false;
  }
}

static bool isBlockedServicePort(int port) {
  static const std::array<int, 11> blocked = {
      0, 1, 7, 19, 25, 53, 123, 135, 137, 161, 3389};
  return std::find(blocked.begin(), blocked.end(), port) != blocked.end();
}

static bool isShareableAddress(const std::string &ip) {
  if (ip.empty())
    return false;
  try {
    const auto addr = boost::asio::ip::make_address(ip);
    if (addr.is_unspecified() || addr.is_loopback() || addr.is_multicast())
      return false;
    if (addr.is_v4()) {
      const auto bytes = addr.to_v4().to_bytes();
      if (bytes[0] == 0)
        return false;
      if (bytes[0] == 10)
        return false;
      if (bytes[0] == 127)
        return false;
      if (bytes[0] == 169 && bytes[1] == 254)
        return false;
      if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
        return false;
      if (bytes[0] == 192 && bytes[1] == 168)
        return false;
      if (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))
        return false;
      if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
        return false;
      return true;
    }
    const auto v6 = addr.to_v6();
    if (v6.is_loopback() || v6.is_link_local() || v6.is_site_local())
      return false;
    const auto bytes = v6.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC)
      return false;
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80)
      return false;
    return true;
  } catch (const std::exception &) {
    std::string lower;
    lower.reserve(ip.size());
    for (char c : ip)
      lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower.size() >= 6 && lower.rfind(".local") == lower.size() - 6)
      return false;
    if (lower.size() >= 4 && lower.rfind(".lan") == lower.size() - 4)
      return false;
    if (lower.size() >= 5 && lower.rfind(".home") == lower.size() - 5)
      return false;
    if (lower.size() >= 9 && lower.rfind(".internal") == lower.size() - 9)
      return false;
    return lower.find(' ') == std::string::npos;
  }
}

static std::string toLowerCopy(const std::string &value) {
  std::string lowered;
  lowered.reserve(value.size());
  for (char c : value)
    lowered.push_back(static_cast<char>(
        std::tolower(static_cast<unsigned char>(c))));
  return lowered;
}

static std::string normalizeHostForLabel(const std::string &host) {
  if (host.empty())
    return host;

  std::string trimmed = host;
  if (trimmed.front() == '[' && trimmed.back() == ']' && trimmed.size() > 2)
    trimmed = trimmed.substr(1, trimmed.size() - 2);

  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address(trimmed, ec);
  if (!ec)
    return toLowerCopy(addr.to_string());

  return toLowerCopy(trimmed);
}

static std::string makeEndpointLabel(const std::string &host, int port) {
  return normalizeHostForLabel(host) + ':' + std::to_string(port);
}

static std::string formatEndpointForWire(const std::string &host, int port) {
  if (host.find(':') != std::string::npos && host.front() != '[')
    return '[' + host + "]:" + std::to_string(port);
  return host + ':' + std::to_string(port);
}

static std::mt19937 &threadLocalRng() {
  thread_local std::mt19937 rng{std::random_device{}()};
  return rng;
}

static std::chrono::milliseconds randomBroadcastDelay() {
  std::uniform_int_distribution<int> jitter(0, 100);
  return std::chrono::milliseconds(50 + jitter(threadLocalRng()));
}

static constexpr std::chrono::seconds MIN_DIAL_BACKOFF{5};
static constexpr std::chrono::seconds MAX_DIAL_BACKOFF{std::chrono::minutes(10)};

static std::chrono::seconds computeDialBackoff(int failures) {
  int capped = std::min(failures, 6);
  auto delay = MIN_DIAL_BACKOFF * (1u << capped);
  if (delay > MAX_DIAL_BACKOFF)
    delay = MAX_DIAL_BACKOFF;
  static thread_local std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<int> jitter(0, 5);
  delay += std::chrono::seconds(jitter(rng));
  return delay;
}

static std::pair<std::string, unsigned short>
parseEndpoint(const std::string &value, unsigned short defaultPort) {
  if (value.empty())
    return {std::string(), 0};
  std::string host = value;
  unsigned short port = defaultPort;

  try {
    if (value.front() == '[') {
      auto end = value.find(']');
      if (end != std::string::npos) {
        host = value.substr(1, end - 1);
        if (end + 1 < value.size() && value[end + 1] == ':') {
          int parsed = std::stoi(value.substr(end + 2));
          if (parsed > 0 && parsed <= std::numeric_limits<unsigned short>::max())
            port = static_cast<unsigned short>(parsed);
        }
      }
    } else {
      auto pos = value.rfind(':');
      if (pos != std::string::npos && value.find(':', pos + 1) == std::string::npos) {
        host = value.substr(0, pos);
        int parsed = std::stoi(value.substr(pos + 1));
        if (parsed > 0 && parsed <= std::numeric_limits<unsigned short>::max())
          port = static_cast<unsigned short>(parsed);
      } else {
        host = value;
      }
    }
  } catch (const std::exception &) {
    return {std::string(), 0};
  }
  if (host.empty())
    return {std::string(), 0};
  return {host, port};
}

static std::pair<std::string, int>
selectReachableEndpoint(const PeerEntry &entry) {
  auto choosePort = [&](int candidate) {
    if (candidate > 0)
      return candidate;
    if (entry.observedPort > 0)
      return entry.observedPort;
    return 0;
  };

  if (isRoutableAddress(entry.ip))
    return {entry.ip, choosePort(entry.port)};
  if (isRoutableAddress(entry.observedIp))
    return {entry.observedIp, choosePort(entry.observedPort)};
  if (!entry.ip.empty())
    return {entry.ip, choosePort(entry.port)};
  if (!entry.observedIp.empty())
    return {entry.observedIp, choosePort(entry.observedPort)};
  return {std::string(), 0};
}

namespace {
std::string dumpHex(const void *data, size_t len) {
  const uint8_t *b = static_cast<const uint8_t *>(data);
  std::ostringstream oss;
  for (size_t i = 0; i < len && i < 32; ++i) {
    if (i)
      oss << ' ';
    oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
        << static_cast<int>(b[i]);
  }
  return oss.str();
}
} // namespace

// ==== [Globals, Statics] ====
// Incoming FULL_CHAIN buffers were removed; per-peer state now tracks
// snapshot or header sync progress directly via peerTransports.
// Protocol frame revision. Bumped whenever the on-wire format or required
// capabilities change.
// Revision 5 adds header and block batch mini-protocols
static constexpr uint32_t kFrameRevision = 5;
static_assert(alyncoin::net::Frame::kBlockBroadcast == 6,
              "Frame field-numbers changed \u2013 bump kFrameRevision !");
static_assert(alyncoin::net::Frame::kBlockRequest == 29 &&
                  alyncoin::net::Frame::kBlockResponse == 30,
              "Frame field-numbers changed \u2013 bump kFrameRevision !");
static constexpr uint64_t FRAME_LIMIT_MIN = 200;
static constexpr uint64_t BYTE_LIMIT_MIN = 1 << 20;
static constexpr int MAX_REORG = 100;
static constexpr int BAN_THRESHOLD = 200;
static constexpr int SYNC_HEIGHT_TOLERANCE = 1;
// Allow more leniency before dropping a peer for corrupted frames. Temporary
// network hiccups can truncate protobuf messages. Such glitches should not
// immediately disconnect healthy peers, so PARSE_FAIL_LIMIT is set higher to
// allow retries while still disconnecting persistent offenders.
static constexpr int PARSE_FAIL_LIMIT = 5;
static constexpr std::chrono::seconds BAN_GRACE_BASE{60};
static constexpr std::chrono::milliseconds BAN_GRACE_PER_BLOCK{100};
static constexpr std::chrono::seconds BAN_GRACE_MAX{3600};
static constexpr size_t MIN_CONNECTED_PEERS = 2;
static constexpr std::chrono::minutes PEERLIST_INTERVAL{5};
static constexpr std::chrono::seconds PEERLIST_RATE_LIMIT{45};
static constexpr size_t MAX_GOSSIP_PEERS = 64;
static constexpr int MAX_PARALLEL_DIALS = 6;
static constexpr int MAX_CONNECTIONS_PER_IP = 2;
static constexpr std::chrono::hours ENDPOINT_TTL{std::chrono::hours(24 * 7)};
static constexpr std::chrono::minutes ENDPOINT_RECENT_SUCCESS{30};
#ifdef ENABLE_PEERLIST_LOGS
#define PEERLIST_LOG(x) std::cout << x << std::endl
#else
#define PEERLIST_LOG(x)
#endif

static uint64_t safeUint64(const boost::multiprecision::cpp_int &bi) {
  using boost::multiprecision::cpp_int;
  static const cpp_int max64 = cpp_int(std::numeric_limits<uint64_t>::max());
  if (bi > max64)
    return std::numeric_limits<uint64_t>::max();
  return bi.convert_to<uint64_t>();
}
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

namespace {
fs::path peerStorageDir() {
  fs::path dir = getAppConfig().data_dir;
  if (dir.empty())
    dir = ".";
  std::error_code ec;
  fs::create_directories(dir, ec);
  return dir;
}

fs::path peersFilePath() { return peerStorageDir() / "peers.txt"; }

fs::path peersBackupPath() { return peerStorageDir() / "peers_backup.txt"; }
} // namespace

// Queue item containing a frame and originating peer for worker threads
struct RxItem {
  alyncoin::net::Frame frame;
  std::string peer;
};
// Bounded queue for decoupling network I/O from processing. The original
// implementation relied on boost::lockfree::queue which is unavailable in
// some build environments (e.g. Windows). We now use a small wrapper around
// std::queue guarded by a mutex and condition variable. While not lock-free,
// it keeps the dependency footprint minimal and still provides the same
// bounded semantics as before.
static std::queue<RxItem *> rxQ;
static std::mutex rxQMutex;
static std::condition_variable rxQCv;
static constexpr std::size_t RXQ_CAPACITY = 128;
// Thread pool used to process frames popped from the queue
static httplib::ThreadPool pool(
    std::max(1u, std::thread::hardware_concurrency()));
static bool workersStarted = [] {
  unsigned n = std::max(1u, std::thread::hardware_concurrency());
  for (unsigned i = 0; i < n; ++i) {
    pool.enqueue([] {
      for (;;) {
        RxItem *item = nullptr;
        {
          std::unique_lock<std::mutex> lk(rxQMutex);
          rxQCv.wait(lk, [] { return !rxQ.empty(); });
          item = rxQ.front();
          rxQ.pop();
          rxQCv.notify_one(); // wake potential producers waiting on capacity
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
                        const google::protobuf::Message &m, bool immediate) {
  if (!tr || !tr->isOpen())
    return false;
  const alyncoin::net::Frame *fr =
      dynamic_cast<const alyncoin::net::Frame *>(&m);
  if (fr) {
    WireFrame tag = WireFrame::OTHER;
    if (fr->has_handshake())
      tag = WireFrame::HANDSHAKE;
    else if (fr->has_height_req() || fr->has_height_res() ||
             fr->has_height_probe())
      tag = WireFrame::HEIGHT;
    else if (fr->has_peer_list())
      tag = WireFrame::PEER_LIST;
    else if (fr->has_block_broadcast())
      tag = WireFrame::BLOCK;
    else if (fr->has_ping() || fr->has_pong())
      tag = WireFrame::PING;
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
    std::cerr << "[sendFrame] ❌ Attempting to send empty protobuf message!"
              << '\n';
    return false;
  }
  if (sz > MAX_WIRE_PAYLOAD) {
    std::cerr << "[sendFrame] ❌ Payload too large: " << sz << " bytes (limit "
              << MAX_WIRE_PAYLOAD << ")" << '\n';
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
  std::cerr << "[sendFrame] Sending frame, payload size: " << sz << " bytes"
            << '\n';
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
    for (const auto &kv : peerTransports) {
      if (kv.first == peer)
        continue;
      if (!kv.second.tx || !kv.second.tx->isOpen())
        continue;
      peers.push_back(kv.first);
    }
  }
  if (peers.empty()) {
    broadcastFrame(m);
    return;
  }
  auto &rng = threadLocalRng();
  std::shuffle(peers.begin(), peers.end(), rng);
  size_t hops = std::min<size_t>(3, peers.size() + 1);
  std::vector<std::string> route;
  route.reserve(hops);
  for (size_t i = 0; i + 1 < hops; ++i)
    route.push_back(peers[i]);
  route.push_back(peer);
  if (route.size() <= 1) {
    broadcastFrame(m);
    return;
  }

  std::vector<PeerSnapshot> snapshots;
  snapshots.reserve(route.size());
  for (const auto &hop : route) {
    auto snapshot = getPeerSnapshot(hop);
    if (!snapshot.state || !snapshot.transport ||
        !snapshot.transport->isOpen()) {
      broadcastFrame(m);
      return;
    }
    snapshots.push_back(std::move(snapshot));
  }

  std::vector<std::vector<uint8_t>> keys;
  keys.reserve(snapshots.size());
  for (const auto &snapshot : snapshots) {
    keys.emplace_back(snapshot.state->linkKey.begin(),
                      snapshot.state->linkKey.end());
  }

  auto firstHopTx = snapshots.front().transport;
  std::string payload = m.SerializeAsString();
  auto pkt = crypto::createPacket(
      std::vector<uint8_t>(payload.begin(), payload.end()), route, keys);
  alyncoin::net::Frame fr;
  fr.mutable_whisper()->set_data(
      std::string(pkt.header.begin(), pkt.header.end()) +
      std::string(pkt.payload.begin(), pkt.payload.end()));
  std::uniform_int_distribution<int> jitter(0, 100);
  std::this_thread::sleep_for(
      std::chrono::milliseconds(50 + jitter(rng)));
  sendFrame(firstHopTx, fr);
}

void Network::sendHeight(const std::string &peer) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  alyncoin::net::Frame fr;
  Blockchain &bc = Blockchain::getInstance();
  auto *hr = fr.mutable_height_res();
  hr->set_height(bc.getHeight());
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  uint64_t w64 = safeUint64(work);
  if (peerManager)
    peerManager->setLocalWork(w64);
  hr->set_total_work(w64);
  sendFrame(snapshot.transport, fr);
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
  uint64_t w64 = safeUint64(work);
  if (peerManager)
    peerManager->setLocalWork(w64);
  hp->set_total_work(w64);
  sendFrame(tr, fr);
}

void Network::sendTipHash(const std::string &peer) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  alyncoin::net::Frame fr;
  fr.mutable_tip_hash_res()->set_hash(
      Blockchain::getInstance().getLatestBlockHash());
  sendFrame(snapshot.transport, fr);
}

void Network::sendPeerList(const std::string &peer) {
  std::shared_ptr<Transport> targetTx;
  std::vector<std::pair<std::string, int>> livePeers;

  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peer);
    if (it == peerTransports.end() || !it->second.tx ||
        !it->second.tx->isOpen())
      return;
    targetTx = it->second.tx;
    for (const auto &kv : peerTransports) {
      const auto endpoint = selectReachableEndpoint(kv.second);
      if (endpoint.first.empty() || endpoint.second <= 0)
        continue;
      if (!isShareableAddress(endpoint.first))
        continue;
      if (isBlockedServicePort(endpoint.second))
        continue;
      livePeers.push_back(endpoint);
    }
  }

  if (!targetTx)
    return;

  auto now = std::chrono::steady_clock::now();
  std::vector<std::pair<std::string, int>> cachedPeers;
  {
    std::lock_guard<std::mutex> gossipLock(gossipMutex);
    auto itLast = peerListLastSent.find(peer);
    if (itLast != peerListLastSent.end() &&
        now - itLast->second < PEERLIST_RATE_LIMIT)
      return;
    peerListLastSent[peer] = now;

    for (auto it = knownPeerEndpoints.begin(); it != knownPeerEndpoints.end();) {
      auto &rec = it->second;
      if (rec.port <= 0 || rec.port > 65535 || isBlockedServicePort(rec.port)) {
        it = knownPeerEndpoints.erase(it);
        continue;
      }
      if (rec.lastSeen != std::chrono::steady_clock::time_point{} &&
          now - rec.lastSeen > ENDPOINT_TTL) {
        it = knownPeerEndpoints.erase(it);
        continue;
      }
      if (!rec.verified ||
          rec.lastSuccess == std::chrono::steady_clock::time_point{} ||
          now - rec.lastSuccess > ENDPOINT_RECENT_SUCCESS) {
        ++it;
        continue;
      }
      if (!isShareableAddress(rec.host)) {
        ++it;
        continue;
      }
      cachedPeers.emplace_back(rec.host, rec.port);
      ++it;
    }
  }

  std::unordered_set<std::string> seen;
  alyncoin::net::Frame peerListFrame;
  auto *pl = peerListFrame.mutable_peer_list();

  auto appendEndpoint = [&](const std::pair<std::string, int> &ep) {
    if (pl->peers_size() >= static_cast<int>(MAX_GOSSIP_PEERS))
      return false;
    const std::string label = makeEndpointLabel(ep.first, ep.second);
    if (!seen.insert(label).second)
      return true;
    pl->add_peers(formatEndpointForWire(ep.first, ep.second));
    return true;
  };

  for (const auto &ep : livePeers) {
    if (!appendEndpoint(ep))
      break;
  }
  for (const auto &ep : cachedPeers) {
    if (!appendEndpoint(ep))
      break;
  }

  auto announce = determineAnnounceEndpoint();
  if (!announce.first.empty() && announce.second > 0 &&
      isShareableAddress(announce.first) &&
      !isBlockedServicePort(announce.second) &&
      pl->peers_size() < static_cast<int>(MAX_GOSSIP_PEERS)) {
    const std::string label = makeEndpointLabel(announce.first, announce.second);
    if (seen.insert(label).second)
      pl->add_peers(formatEndpointForWire(announce.first, announce.second));
  }

  if (pl->peers_size() == 0)
    return;
  sendFrame(targetTx, peerListFrame);
}

void Network::markPeerOffline(const std::string &peerId) {
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peerId);
    if (it != peerTransports.end()) {
      if (it->second.tx)
        it->second.tx->close();
      peerTransports.erase(it);
    }
    anchorPeers.erase(peerId);
    knownPeers.erase(peerId);
  }
  if (peerManager)
    peerManager->disconnectPeer(peerId);
  {
    std::lock_guard<std::mutex> gossipLock(gossipMutex);
    peerListLastSent.erase(peerId);
  }
  // Allow the peer manager to reconcile naturally; removing a peer should not
  // trigger automatic connection churn that misreports the live peer count.
}

void Network::penalizePeer(const std::string &peer, int points) {
  std::lock_guard<std::timed_mutex> lk(peersMutex);
  auto it = peerTransports.find(peer);
  if (it != peerTransports.end()) {
    it->second.state->misScore += points;
    if (it->second.state->misScore >= BAN_THRESHOLD)
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
  auto announce = determineAnnounceEndpoint();
  if (announce.second == 0)
    announce.second = this->port;
  hs.set_listen_port(announce.second);
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
  {
    std::ostringstream consensus;
    consensus << std::fixed << std::setprecision(12)
              << "consensus:difficulty=" << bc.getCurrentDifficulty()
              << ";reward=" << bc.getCurrentBlockReward();
    hs.add_capabilities(consensus.str());
  }
  hs.set_frame_rev(kFrameRevision);
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  hs.set_total_work(safeUint64(work));
  hs.set_want_snapshot(false);
  hs.set_snapshot_size(static_cast<uint32_t>(MAX_SNAPSHOT_CHUNK_SIZE));
  hs.set_node_id(nodeId);
  hs.set_nonce(localHandshakeNonce);
  if (!announce.first.empty() && isShareableAddress(announce.first))
    hs.set_observed_ip(announce.first);
  return hs;
}
// Fallback peer in case DNS TXT lookup returns no peers.
// Uses the domain seed rather than a hard-coded IP so the
// network can migrate hosts without code changes.
static const std::vector<std::string> DEFAULT_DNS_PEERS = {
    "peers.alyncoin.com:15671"};

std::vector<std::string> fetchPeersFromDNS(const std::string &domain);

struct PeerFileEntry {
  std::string host;
  int port{0};
  std::string keyB64;
};

std::optional<PeerFileEntry> parsePeerFileEntry(const std::string &line) {
  std::istringstream iss(line);
  std::string endpoint;
  if (!(iss >> endpoint))
    return std::nullopt;

  auto colon = endpoint.find(':');
  if (colon == std::string::npos)
    return std::nullopt;

  PeerFileEntry entry;
  entry.host = endpoint.substr(0, colon);
  std::string portStr = endpoint.substr(colon + 1);
  try {
    entry.port = std::stoi(portStr);
  } catch (const std::exception &) {
    return std::nullopt;
  }
  if (entry.port <= 0 || entry.port > 65535)
    return std::nullopt;

  iss >> entry.keyB64;
  return entry;
}

std::vector<PeerFileEntry> gatherBootstrapPeers() {
  std::set<std::string> seen;
  std::vector<PeerFileEntry> peers;

  auto addCandidate = [&](const std::string &candidate) {
    auto parsed = parsePeerFileEntry(candidate);
    if (!parsed)
      return;
    if (!isNumericAddress(parsed->host))
      return;
    std::string key = parsed->host + ":" + std::to_string(parsed->port);
    if (seen.insert(key).second)
      peers.push_back(*parsed);
  };

  for (const auto &seed : DEFAULT_DNS_PEERS)
    addCandidate(seed);

  auto dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
  for (const auto &seed : dnsPeers)
    addCandidate(seed);

  return peers;
}

// ==== [DNS Peer Discovery] ====
#ifndef _WIN32
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
#else
std::vector<std::string> fetchPeersFromDNS(const std::string &domain) {
  std::cerr << "⚠️ [DNS] Peer discovery via TXT records not supported on Windows" << "\n";
  (void)domain;
  return DEFAULT_DNS_PEERS;
}
#endif

// ==== [Network Ctor/Dtor] ====
#if defined(ALYN_ENABLE_NAT_TRAVERSAL) && defined(HAVE_MINIUPNPC)
std::optional<std::string> tryUPnPPortMapping(int port) {
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
  int upnpErr = 0;
#if defined(MINIUPNPC_API_VERSION) && (MINIUPNPC_API_VERSION >= 18)
  // Newer miniupnpc (API >= 18) takes the TTL parameter before the error ptr
  ctx.devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, &upnpErr);
#else
  // Older miniupnpc releases expect the error pointer before the TTL
  ctx.devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, &upnpErr, 2);
#endif
  if (!ctx.devlist) {
    std::cerr << "⚠️ [UPnP] upnpDiscover() failed or no devices found\n";
    return std::nullopt;
  }

  int igdStatus = 0;
#if defined(ALYN_DISABLE_UPNP)
  // UPnP disabled; nothing to do.
#elif defined(MINIUPNPC_API_VERSION) && (MINIUPNPC_API_VERSION >= 18)
  // Newer miniupnpc uses a 7-arg version of UPNP_GetValidIGD.
  igdStatus =
      UPNP_GetValidIGD(ctx.devlist, &ctx.urls, &ctx.data, lanAddr,
                       sizeof(lanAddr), nullptr, 0);
#else
  // Older miniupnpc uses the 5-arg form.
  igdStatus =
      UPNP_GetValidIGD(ctx.devlist, &ctx.urls, &ctx.data, lanAddr,
                       sizeof(lanAddr));
#endif
  if (igdStatus != 1) {
    std::cerr << "⚠️ [UPnP] No valid IGD found\n";
    return std::nullopt;
  }

  char portStr[16];
  snprintf(portStr, sizeof(portStr), "%d", port);

  int ret = UPNP_AddPortMapping(ctx.urls.controlURL, ctx.data.first.servicetype,
                                portStr, portStr, lanAddr, "AlynCoin", "TCP",
                                nullptr, "0");

  if (ret == UPNPCOMMAND_SUCCESS) {
    std::cout << "✅ [UPnP] Port mapping added on port " << std::dec << port
              << "\n";
    char external[64] = {0};
    if (UPNP_GetExternalIPAddress(ctx.urls.controlURL,
                                  ctx.data.first.servicetype, external) ==
            UPNPCOMMAND_SUCCESS &&
        external[0] != '\0') {
      return std::string(external);
    }
  } else {
    std::cerr << "⚠️ [UPnP] Failed to add port mapping: " << strupnperror(ret)
              << "\n";
  }
  return std::nullopt;
}
#elif defined(ALYN_ENABLE_NAT_TRAVERSAL)
std::optional<std::string> tryUPnPPortMapping(int) { return std::nullopt; }
#endif
#if defined(ALYN_ENABLE_NAT_TRAVERSAL) && defined(HAVE_LIBNATPMP)
namespace {
std::optional<std::string> tryNATPMPPortMapping(int port, int max_wait_ms) {
  natpmp_t natpmp;
  natpmpresp_t response{};
  const int waitBudget = std::max(0, max_wait_ms);
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::milliseconds(waitBudget);

  const int initResult = initnatpmp(&natpmp, 0, 0);
  if (initResult < 0) {
    std::cerr << "⚠️ [NAT-PMP] initnatpmp failed: " << initResult << "\n";
    return std::nullopt;
  }

  struct NatpmpCloser {
    natpmp_t *handle;
    ~NatpmpCloser() {
      if (handle)
        closenatpmp(handle);
    }
  } closer{&natpmp};

  int r = sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_TCP, port, port, 3600);
  if (r < 0) {
    std::cerr << "⚠️ [NAT-PMP] send request failed: " << r << "\n";
    return std::nullopt;
  }

  auto waitForResponse = [&](natpmpresp_t &resp) -> int {
    int result = NATPMP_TRYAGAIN;
    while (result == NATPMP_TRYAGAIN &&
           std::chrono::steady_clock::now() < deadline) {
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(natpmp.s, &fds);
      const auto now = std::chrono::steady_clock::now();
      auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
      if (remaining.count() <= 0) {
        break;
      }

      const long slice = std::min<long>(remaining.count(), 100);
      timeval tv{};
      tv.tv_sec = slice / 1000;
      tv.tv_usec = (slice % 1000) * 1000;
      select(natpmp.s + 1, &fds, nullptr, nullptr, &tv);
      result = readnatpmpresponseorretry(&natpmp, &resp);
    }
    return result;
  };

  r = waitForResponse(response);

  if (r >= 0 && response.resultcode == 0) {
    std::cout << "✅ [NAT-PMP] Port mapping added on port " << std::dec << port
              << "\n";
    natpmpresp_t addrResp{};
    int addrReq = sendpublicaddressrequest(&natpmp);
    if (addrReq >= 0) {
      r = waitForResponse(addrResp);
      if (r >= 0 && addrResp.type == NATPMP_RESPTYPE_PUBLICADDRESS) {
        char buf[INET_ADDRSTRLEN] = {0};
        in_addr ia{};
        static_assert(sizeof(ia) >= sizeof(addrResp.pnu.publicaddress),
                      "Unexpected natpmp public address size");
        std::memcpy(&ia, &addrResp.pnu.publicaddress,
                    sizeof(addrResp.pnu.publicaddress));
        if (inet_ntop(AF_INET, &ia, buf, sizeof(buf))) {
          return std::string(buf);
        }
      }
    }
  } else if (r >= 0) {
    std::cerr << "⚠️ [NAT-PMP] Failed to add port mapping: " << r
              << " resp=" << response.resultcode << "\n";
  }

  return std::nullopt;
}

} // namespace

std::optional<std::string> tryNATPMPPortMapping(int port) {
  return tryNATPMPPortMapping(port, 2000);
}
#elif defined(ALYN_ENABLE_NAT_TRAVERSAL)
std::optional<std::string> tryNATPMPPortMapping(int) { return std::nullopt; }
#endif

Network::Network(unsigned short port, Blockchain *blockchain,
                 PeerBlacklist *blacklistPtr)
    : port(port), blockchain(blockchain), isRunning(false), syncing(true),
      ioContext(), tlsContext(nullptr), acceptor(ioContext),
      blacklist(blacklistPtr) {
  nodeId = Crypto::generateRandomHex(16);
  randombytes_buf(&localHandshakeNonce, sizeof(localHandshakeNonce));
  if (localHandshakeNonce == 0)
    localHandshakeNonce = 1; // reserve zero to denote "unknown"
  refreshLocalInterfaces();
  if (!blacklistPtr) {
    std::cerr
        << "❌ [FATAL] PeerBlacklist is null! Cannot initialize network.\n";
    throw std::runtime_error("PeerBlacklist is null");
  }

  if (getAppConfig().enable_tls) {
    tlsContext = std::make_unique<boost::asio::ssl::context>(
        boost::asio::ssl::context::tlsv12);
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
      std::ostringstream oss;
      oss << "bind failed on port " << port << ": " << ec.message();
      throw std::runtime_error(oss.str());
    }

    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
      std::ostringstream oss;
      oss << "listen failed on port " << port << ": " << ec.message();
      throw std::runtime_error(oss.str());
    }

    std::cout << "🌐 Network listener started on port: " << std::dec << port
              << "\n";
    peerManager = std::make_unique<PeerManager>(blacklistPtr, this);
    if (!configuredExternalAddress.empty()) {
      auto announce = determineAnnounceEndpoint();
      if (!announce.first.empty() && announce.second > 0)
        peerManager->setExternalAddress(announce.first + ':' +
                                        std::to_string(announce.second));
    }
    selfHealer =
        std::make_unique<SelfHealingNode>(blockchain, peerManager.get());
    isRunning = true;
    listenerThread = std::thread(&Network::listenForConnections, this);
    threads_.push_back(std::move(listenerThread));

  } catch (const std::exception &ex) {
    std::cerr << "❌ [Network Exception] " << ex.what() << "\n";
    throw;
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

  acceptor.async_accept([this](boost::system::error_code ec,
                               tcp::socket socket) {
    if (!ec) {
      std::cout << "🌐 [ACCEPTED] Incoming connection accepted.\n";
      std::shared_ptr<Transport> transport;
      if (getAppConfig().enable_tls && tlsContext) {
        auto stream = std::make_shared<boost::asio::ssl::stream<tcp::socket>>(
            std::move(socket), *tlsContext);
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
  if (peerManager) {
    auto endpoint = determineAnnounceEndpoint();
    if (!endpoint.first.empty() && endpoint.second > 0)
      peerManager->setExternalAddress(endpoint.first + ':' +
                                      std::to_string(endpoint.second));
  }
  requestPeerList();
  autoSyncIfBehind();
  intelligentSync();
}

// ✅ **Auto-Mining Background Thread**
void Network::autoMineBlock() {
  auto workerFunc = [this]() {
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(5));

      Blockchain &blockchain = *this->blockchain;
      if (!blockchain.shouldAutoMine()) {
        continue;
      }

      PeerManager *pm = peerManager.get();
      bool havePeers = pm && pm->getPeerCount() > 0;
      static bool warnedSolo = false;
      static bool warnedBehind = false;
      if (!havePeers) {
        if (!warnedSolo) {
          std::cerr << "⚠️ Auto-miner waiting for peer connections before "
                       "mining." << std::endl;
          warnedSolo = true;
        }
        continue;
      }
      warnedSolo = false;

      bool caughtUp = true;
      if (pm) {
        const int peerMax = pm->getMaxPeerHeight();
        if (peerMax > 0) {
          const int localHeight = blockchain.getHeight();
          if (peerMax > SYNC_HEIGHT_TOLERANCE &&
              localHeight < peerMax - SYNC_HEIGHT_TOLERANCE)
            caughtUp = false;
        }
        const uint64_t peerWork = pm->getMaxPeerWork();
        if (peerWork > 0 && blockchain.getTotalWork() < peerWork)
          caughtUp = false;
      }

      if (!caughtUp) {
        if (!warnedBehind) {
          std::cerr << "⚠️ Auto-miner pausing until local chain catches up." << std::endl;
          warnedBehind = true;
        }
        autoSyncIfBehind();
        continue;
      }
      warnedBehind = false;

      const Block &latestBlock = blockchain.getLatestBlock();
      double secondsSinceLast =
          std::difftime(std::time(nullptr), latestBlock.getTimestamp());
      if (secondsSinceLast < 60.0) {
        std::cout << "⏳ Auto-miner waiting. Last block is " << secondsSinceLast
                  << "s old (< 60s threshold)." << std::endl;
        continue;
      }
      std::cout << "⛏️ New transactions detected. Starting mining..."
                << std::endl;

      // Use default miner address
      std::string minerAddress =
          "miner"; // Replace with actual configured address if needed
      auto resolvedMiner = Crypto::resolveWalletKeyIdentifier(minerAddress);
      std::string minerKeyId = resolvedMiner.value_or(minerAddress);

      auto dilithiumKeys = Crypto::loadDilithiumKeys(minerKeyId);
      auto falconKeys = Crypto::loadFalconKeys(minerKeyId);

      if (dilithiumKeys.privateKey.empty() || falconKeys.privateKey.empty()) {
        std::cerr << "❌ Miner private keys not found or invalid for: "
                  << minerKeyId << std::endl;
        continue;
      }

      std::string canonicalMiner = minerAddress;
      if (!dilithiumKeys.publicKey.empty()) {
        canonicalMiner = Crypto::deriveAddressFromPub(dilithiumKeys.publicKey);
      } else if (!falconKeys.publicKey.empty()) {
        canonicalMiner = Crypto::deriveAddressFromPub(falconKeys.publicKey);
      }
      if (canonicalMiner.empty()) {
        canonicalMiner = minerKeyId;
      }

      blockchain.setAutoMiningRewardMode(true);
      struct AutoRewardReset {
        Blockchain &ref;
        ~AutoRewardReset() { ref.setAutoMiningRewardMode(false); }
      } autoRewardReset{blockchain};
      Block minedBlock = blockchain.minePendingTransactions(
          canonicalMiner, dilithiumKeys.privateKey, falconKeys.privateKey,
          /*forceAutoReward=*/true);

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
        Blockchain::getInstance().saveToDB();
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
    };
  std::thread worker(workerFunc);
  worker.detach();
}

//
// ✅ **Getter function for syncing status**
bool Network::isSyncing() const { return syncing; }

// ✅ **Broadcast a transaction to all peers**

void Network::broadcastTransaction(const Transaction &tx) {
  alyncoin::TransactionProto proto = tx.toProto();
  alyncoin::net::Frame fr;
  *fr.mutable_tx_broadcast()->mutable_tx() = proto;
  std::vector<std::pair<std::string, std::shared_ptr<Transport>>> targets;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto &kv : peerTransports) {
      if (kv.second.tx && kv.second.tx->isOpen())
        targets.emplace_back(kv.first, kv.second.tx);
    }
  }

  if (targets.empty())
    return;

  if (targets.size() <= 1) {
    for (const auto &kv : targets) {
      std::this_thread::sleep_for(randomBroadcastDelay());
      sendFrame(kv.second, fr);
    }
    return;
  }

  for (const auto &kv : targets) {
    if (peerSupportsWhisper(kv.first))
      sendPrivate(kv.first, fr);
    else {
      std::this_thread::sleep_for(randomBroadcastDelay());
      sendFrame(kv.second, fr);
    }
  }
}

// Broadcast transaction to all peers except sender (to prevent echo storms)
void Network::broadcastTransactionToAllExcept(const Transaction &tx,
                                              const std::string &excludePeer) {
  alyncoin::TransactionProto proto = tx.toProto();
  alyncoin::net::Frame fr;
  *fr.mutable_tx_broadcast()->mutable_tx() = proto;
  std::vector<std::pair<std::string, std::shared_ptr<Transport>>> targets;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto &kv : peerTransports) {
      if (kv.first == excludePeer)
        continue;
      if (kv.second.tx && kv.second.tx->isOpen())
        targets.emplace_back(kv.first, kv.second.tx);
    }
  }

  for (const auto &kv : targets) {
    if (peerSupportsWhisper(kv.first))
      sendPrivate(kv.first, fr);
    else {
      std::this_thread::sleep_for(randomBroadcastDelay());
      sendFrame(kv.second, fr);
    }
  }
}

// ✅ New smart sync method
void Network::intelligentSync() {
  std::cout << "🔄 [Smart Sync] Starting intelligent sync process...\n";

  if (!peerManager) {
    std::cerr << "⚠️ [Smart Sync] No PeerManager. Skipping sync.\n";
    return;
  }

  std::vector<std::pair<std::string, std::shared_ptr<Transport>>> livePeers;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    if (peerTransports.empty()) {
      std::cerr << "⚠️ [Smart Sync] No peers connected. Skipping sync.\n";
      return;
    }
    for (const auto &kv : peerTransports) {
      if (!kv.second.tx || !kv.second.tx->isOpen())
        continue;
      livePeers.emplace_back(kv.first, kv.second.tx);
    }
  }

  if (livePeers.empty()) {
    std::cerr << "⚠️ [Smart Sync] No live transports available. Skipping sync.\n";
    return;
  }

  for (const auto &[peerId, tr] : livePeers) {
    alyncoin::net::Frame req1;
    req1.mutable_height_req();
    sendFrame(tr, req1);
    alyncoin::net::Frame req2;
    req2.mutable_tip_hash_req();
    sendFrame(tr, req2);
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

  const std::string localTip = blockchain->getLatestBlockHash();

  /* pick the first suitable peer that is ahead */
  for (const auto &[peer, transport] : livePeers) {
    int ph = peerManager->getPeerHeight(peer);
    if (ph <= localHeight)
      continue;

    int gap = ph - localHeight;
    if (gap <= TAIL_SYNC_THRESHOLD) {
      requestTailBlocks(peer, localHeight, localTip);
    } else if (peerSupportsSnapshot(peer)) {
      requestSnapshotSync(peer);
    } else if (peerSupportsAggProof(peer)) {
      requestEpochHeaders(peer);
    }
    break; // one good peer is enough
  }
}
//
void Network::connectToPeer(const std::string &ip, short port) {
  std::string peerKey = ip;
  if (isSelfEndpoint(ip, port)) {
    std::cerr << "⚠️ [connectToPeer] Skipping self connect: " << peerKey
              << ':' << port << "\n";
    recordSelfEndpoint(ip, port);
    return;
  }
  if (connectToNode(ip, port))
    rememberPeerEndpoint(ip, port);
}

// ✅ **Broadcast peer list to all connected nodes**
void Network::broadcastPeerList(const std::string &excludePeer) {
  ScopedLockTracer tracer("broadcastPeerList");
  std::vector<std::pair<std::string, int>> livePeers;
  std::vector<std::pair<std::string, int>> cachedPeers;
  std::vector<std::shared_ptr<Transport>> sinks;
  {
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    if (peerTransports.empty())
      return;
    for (const auto &[peerId, entry] : peerTransports) {
      if (!excludePeer.empty() && peerId == excludePeer)
        continue;
      if (entry.tx && entry.tx->isOpen())
        sinks.push_back(entry.tx);
      auto endpoint = selectReachableEndpoint(entry);
      if (endpoint.first.empty() || endpoint.second <= 0)
        continue;
      if (!isShareableAddress(endpoint.first))
        continue;
      if (isBlockedServicePort(endpoint.second))
        continue;
      livePeers.push_back(std::move(endpoint));
    }
  }

  if (sinks.empty())
    return;

  auto now = std::chrono::steady_clock::now();
  {
    std::lock_guard<std::mutex> gossipLock(gossipMutex);
    for (auto it = knownPeerEndpoints.begin(); it != knownPeerEndpoints.end();) {
      auto &rec = it->second;
      if (rec.port <= 0 || rec.port > 65535 || isBlockedServicePort(rec.port)) {
        it = knownPeerEndpoints.erase(it);
        continue;
      }
      if (rec.lastSeen != std::chrono::steady_clock::time_point{} &&
          now - rec.lastSeen > ENDPOINT_TTL) {
        it = knownPeerEndpoints.erase(it);
        continue;
      }
      if (!rec.verified ||
          rec.lastSuccess == std::chrono::steady_clock::time_point{} ||
          now - rec.lastSuccess > ENDPOINT_RECENT_SUCCESS) {
        ++it;
        continue;
      }
      if (!isShareableAddress(rec.host)) {
        ++it;
        continue;
      }
      cachedPeers.emplace_back(rec.host, rec.port);
      ++it;
    }
  }

  std::unordered_set<std::string> seen;
  alyncoin::net::Frame peerListFrame;
  auto *pl = peerListFrame.mutable_peer_list();
  auto appendEndpoint = [&](const std::pair<std::string, int> &ep) {
    if (pl->peers_size() >= static_cast<int>(MAX_GOSSIP_PEERS))
      return false;
    const std::string label = makeEndpointLabel(ep.first, ep.second);
    if (!seen.insert(label).second)
      return true;
    pl->add_peers(formatEndpointForWire(ep.first, ep.second));
    return true;
  };

  for (const auto &ep : livePeers) {
    if (!appendEndpoint(ep))
      break;
  }
  for (const auto &ep : cachedPeers) {
    if (!appendEndpoint(ep))
      break;
  }

  auto announce = determineAnnounceEndpoint();
  if (!announce.first.empty() && announce.second > 0 &&
      isShareableAddress(announce.first) &&
      !isBlockedServicePort(announce.second) &&
      pl->peers_size() < static_cast<int>(MAX_GOSSIP_PEERS)) {
    const std::string label = makeEndpointLabel(announce.first, announce.second);
    if (seen.insert(label).second)
      pl->add_peers(formatEndpointForWire(announce.first, announce.second));
  }

  if (pl->peers_size() == 0)
    return;

  for (const auto &tx : sinks)
    sendFrame(tx, peerListFrame);
}

//
PeerManager *Network::getPeerManager() { return peerManager.get(); }

Network::PeerSnapshot Network::getPeerSnapshot(const std::string &peer) const {
  PeerSnapshot snapshot;
  std::lock_guard<std::timed_mutex> lk(peersMutex);
  auto it = peerTransports.find(peer);
  if (it != peerTransports.end()) {
    snapshot.transport = it->second.tx;
    snapshot.state = it->second.state;
  }
  return snapshot;
}

// ✅ **Request peer list from connected nodes**
void Network::requestPeerList() {
  std::vector<std::shared_ptr<Transport>> sinks;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    for (const auto &[peerAddr, entry] : peerTransports) {
      if (entry.tx && entry.tx->isOpen())
        sinks.push_back(entry.tx);
    }
  }

  if (sinks.empty())
    return;

  for (const auto &tx : sinks) {
    alyncoin::net::Frame fr;
    fr.mutable_peer_list_req();
    sendFrame(tx, fr);
  }
  PEERLIST_LOG("📡 Requesting peer list from all known peers...");
}
// Handle Peer (Transport version)
void Network::handlePeer(std::shared_ptr<Transport> transport) {
  std::string realPeerId, claimedPeerId;
  std::string claimedVersion, claimedNetwork;
  int remoteHeight = 0;
  uint64_t remoteWork = 0;
  uint32_t remoteRev = 0;
  bool remoteAgg = false;
  bool remoteSnap = false;
  bool remoteWantSnap = false;
  uint32_t remoteSnapSize = 0;
  bool remoteWhisper = false;
  bool remoteTls = false;
  bool remoteBanDecay = false;
  int finalPort = 0;
  uint64_t remoteNonce = 0;
  std::string senderIP;
  std::string canonicalIp;
  int observedPort = 0;

  /* what *we* look like to the outside world */
  const std::string selfIdentity = getSelfAddressAndPort();

  // ── 1. read + verify handshake ──────────────────────────────────────────
  std::array<uint8_t, 32> myPriv{};
  std::array<uint8_t, 32> myPub{};
  std::array<uint8_t, 32> shared{};
  try {
    std::string blob = transport->readBinaryBlocking();
    std::cerr << "[handlePeer] raw handshake bytes size=" << blob.size()
              << " first32=" << dumpHex(blob.data(), blob.size()) << '\n';
    alyncoin::net::Frame fr;
    if (blob.empty() || !fr.ParseFromString(blob) || !fr.has_handshake())
      throw std::runtime_error("invalid handshake");

    const auto &hs = fr.handshake();

    randombytes_buf(myPriv.data(), myPriv.size());
    crypto_scalarmult_curve25519_base(myPub.data(), myPriv.data());
    if (hs.pub_key().size() == 32) {
      if (crypto_scalarmult_curve25519(shared.data(), myPriv.data(),
                                       reinterpret_cast<const unsigned char *>(
                                           hs.pub_key().data())) != 0)
        throw std::runtime_error("invalid peer public key");
    }

    senderIP = transport->getRemoteIP();
    observedPort = transport->getRemotePort();
    // The Handshake proto uses proto3 semantics so there is no
    // `has_listen_port()` accessor. Older nodes may omit this field, so
    // fall back to the remote port if zero.
    finalPort = hs.listen_port();
    if (finalPort == 0)
      finalPort = transport->getRemotePort();
    realPeerId = senderIP;
    canonicalIp = senderIP;
    if (!hs.observed_ip().empty() && isRoutableAddress(hs.observed_ip()))
      canonicalIp = hs.observed_ip();

    claimedVersion = hs.version();
    claimedNetwork = hs.network_id();
    remoteHeight = static_cast<int>(hs.height());
    remoteWork = hs.total_work();
    remoteWantSnap = hs.want_snapshot();
    remoteSnapSize = hs.snapshot_size();

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
    if (auto hints = parseConsensusHints(hs.capabilities());
        hints.hasDifficulty || hints.hasReward) {
      Blockchain::getInstance().applyConsensusHints(
          remoteHeight, hints.hasDifficulty ? hints.difficulty : -1,
          hints.hasReward ? hints.reward : -1.0);
    }
    if (!gotBinary)
      throw std::runtime_error("legacy peer – no binary_v1");
    claimedPeerId = hs.node_id().empty() ? realPeerId : hs.node_id();
    remoteNonce = hs.nonce();
    if (isSelfNonce(remoteNonce)) {
      std::cout << "🛑 Self-connect ignored (nonce match) from " << realPeerId
                << '\n';
      recordSelfEndpoint(realPeerId, finalPort);
      recordSelfEndpoint(canonicalIp, finalPort);
      transport->closeGraceful();
      return;
    }

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

    if (!senderIP.empty()) {
      std::lock_guard<std::timed_mutex> g(peersMutex);
      int perIp = 0;
      for (const auto &kv : peerTransports) {
        if (kv.second.ip == senderIP)
          ++perIp;
      }
      if (perIp >= MAX_CONNECTIONS_PER_IP) {
        std::cerr << "⚠️  [handlePeer] per-IP limit reached for " << senderIP
                  << '\n';
        return;
      }
    }

    std::string prefix = ipPrefix(senderIP);
    if (!prefix.empty()) {
      std::lock_guard<std::timed_mutex> g(peersMutex);
      int count = 0;
      for (const auto &kv : peerTransports) {
        std::string ip = kv.second.ip;
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
  if (finalPort > 0) {
    auto rejectSelf = [&](const std::string &ip) {
      if (ip.empty())
        return false;
      if (!isSelfEndpoint(ip, finalPort))
        return false;
      std::cout << "🛑 Self-connect ignored (endpoint match) from " << ip
                << ':' << finalPort << '\n';
      recordSelfEndpoint(ip, finalPort);
      transport->closeGraceful();
      return true;
    };
    if (rejectSelf(canonicalIp) || rejectSelf(realPeerId))
      return;
  }

  if (claimedPeerId == selfIdentity || realPeerId == selfIdentity ||
      isSelfNodeId(claimedPeerId)) {
    std::cout << "🛑 Self-connect ignored: " << claimedPeerId << '\n';
    recordSelfEndpoint(realPeerId, finalPort);
    recordSelfEndpoint(canonicalIp, finalPort);
    return;
  }

  // ── 3. register / update transport entry ───────────────────────────────
  {
    ScopedLockTracer t("handlePeer/register");
    std::lock_guard<std::timed_mutex> lk(peersMutex);

    auto itExisting = peerTransports.find(claimedPeerId);
    if (itExisting != peerTransports.end() && itExisting->second.tx &&
        itExisting->second.tx->isOpen()) {
      uint64_t existingNonce =
          itExisting->second.state ? itExisting->second.state->remoteNonce : 0;
      bool replaceExisting = false;
      if (existingNonce == 0 && remoteNonce != 0) {
        replaceExisting = true;
      } else if (remoteNonce != 0 && existingNonce != 0 &&
                 remoteNonce < existingNonce) {
        replaceExisting = true;
      }
      if (replaceExisting) {
        std::cout << "🔁 replacing connection for " << claimedPeerId << "\n";
        if (itExisting->second.tx)
          itExisting->second.tx->closeGraceful();
        itExisting->second.tx = transport;
        itExisting->second.initiatedByUs = false;
        itExisting->second.port = finalPort;
        itExisting->second.ip = canonicalIp.empty() ? realPeerId : canonicalIp;
        itExisting->second.observedIp = senderIP;
        itExisting->second.observedPort = observedPort;
        if (itExisting->second.state)
          itExisting->second.state->remoteNonce = remoteNonce;
      } else {
        std::cout << "🔁 duplicate connection from " << claimedPeerId
                  << " closed\n";
        if (itExisting->second.state && existingNonce == 0 && remoteNonce != 0)
          itExisting->second.state->remoteNonce = remoteNonce;
        if (transport)
          transport->closeGraceful();
        return;
      }
    }

    auto &entry = peerTransports[claimedPeerId];
    entry.tx = transport;
    entry.initiatedByUs = false;
    entry.port = finalPort;
    entry.ip = canonicalIp.empty() ? realPeerId : canonicalIp;
    entry.observedIp = senderIP;
    entry.observedPort = observedPort;
    knownPeers.insert(claimedPeerId);
    if (!entry.state)
      entry.state = std::make_shared<PeerState>();
    entry.state->connectedAt = std::chrono::steady_clock::now();
    int localHeight = static_cast<int>(Blockchain::getInstance().getHeight());
    int heightDiff = std::max(0, remoteHeight - localHeight);
    auto extra = BAN_GRACE_PER_BLOCK * heightDiff;
    auto grace = BAN_GRACE_BASE +
                 std::chrono::duration_cast<std::chrono::seconds>(extra);
    if (grace > BAN_GRACE_MAX)
      grace = BAN_GRACE_MAX;
    entry.state->graceUntil = entry.state->connectedAt + grace;
    entry.state->supportsAggProof = remoteAgg;
    entry.state->supportsSnapshot = remoteSnap;
    entry.state->supportsWhisper = remoteWhisper;
    entry.state->supportsTls = remoteTls;
    entry.state->supportsBanDecay = remoteBanDecay;
    entry.state->frameRev = remoteRev;
    entry.state->version = claimedVersion;
    entry.state->snapshotChunkPreference =
        remoteSnap ? resolveSnapshotChunkSize(remoteSnapSize) : 0;
    std::copy(shared.begin(), shared.end(), entry.state->linkKey.begin());
    entry.state->remoteNonce = remoteNonce;
    entry.state->handshakeComplete = true;

    if (peerManager) {
      if (peerManager->registerPeer(claimedPeerId)) {
        peerManager->setPeerHeight(claimedPeerId, remoteHeight);
        peerManager->setPeerWork(claimedPeerId, remoteWork);
      }
    }
  }

  std::cout << "✅ Registered peer: " << claimedPeerId << '\n';

  const std::string shareHost = canonicalIp.empty() ? realPeerId : canonicalIp;
  noteShareableEndpoint(shareHost, finalPort, true, true, claimedPeerId);

  // ── 4. push our handshake back ──────────────────────────────────────────
  {
    alyncoin::net::Handshake hs_out = buildHandshake();
    hs_out.set_pub_key(
        std::string(reinterpret_cast<char *>(myPub.data()), myPub.size()));
    hs_out.set_snapshot_size(static_cast<uint32_t>(MAX_SNAPSHOT_CHUNK_SIZE));
    auto endpoint = determineAnnounceEndpoint();
    if (!endpoint.first.empty() && isShareableAddress(endpoint.first))
      hs_out.set_observed_ip(endpoint.first);
    else
      hs_out.set_observed_ip(realPeerId);
    if (remoteWantSnap)
      hs_out.set_want_snapshot(true);
    alyncoin::net::Frame out;
    *out.mutable_handshake() = hs_out;
    sendFrameImmediate(transport, out);
    sendHeight(claimedPeerId);
  }

  // ── 5. arm read loop + initial requests ────────────────────────────────
  startBinaryReadLoop(claimedPeerId, transport);

  sendInitialRequests(claimedPeerId);

  // ── 6. immediate sync decision ─────────────────────────────────────────
  const size_t myHeight = Blockchain::getInstance().getHeight();
  if (remoteHeight > static_cast<int>(myHeight)) {
    int gap = remoteHeight - static_cast<int>(myHeight);
    if (gap <= TAIL_SYNC_THRESHOLD) {
      requestTailBlocks(claimedPeerId, myHeight,
                        Blockchain::getInstance().getLatestBlockHash());
    } else if (remoteSnap) {
      requestSnapshotSync(claimedPeerId);
    } else if (remoteAgg) {
      requestEpochHeaders(claimedPeerId);
    }
  }

  autoSyncIfBehind();
  intelligentSync();

  // ── 7. optional reverse connect removed for binary protocol ──
}
// ✅ **Run Network Thread**
void Network::run() {
  std::cout << "🚀 [Network] Starting network stack for port " << port << "\n";
  // Start listener and IO thread
  startServer();
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  configureNatTraversal();

  loadPeers();

  bool shouldDialDns = false;
  {
    std::lock_guard<std::timed_mutex> lock(peersMutex);
    shouldDialDns = peerTransports.empty();
  }

  if (shouldDialDns) {
    std::vector<std::string> dnsPeers = fetchPeersFromDNS("peers.alyncoin.com");
    bool added = false;
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
      if (isSelfEndpoint(ip, p)) {
        recordSelfEndpoint(ip, p);
        continue;
      }
      if (noteShareableEndpoint(ip, p, false))
        added = true;
      connectToNode(ip, p);
    }
    if (added)
      broadcastPeerList();
  } else {
    std::cout << "ℹ️  [Network] Existing peers from peers.txt; DNS bootstrap skipped.\n";
  }
  // After dialing DNS peers, share them with connected nodes so the mesh can
  // survive even if DNS is unreachable later.
  std::thread([this]() {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    this->broadcastPeerList();
    this->requestPeerList();
  }).detach();
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
      std::this_thread::sleep_for(PEERLIST_INTERVAL);
      size_t active = 0;
      {
        std::lock_guard<std::timed_mutex> lk(peersMutex);
        for (const auto &kv : peerTransports) {
          if (kv.second.tx && kv.second.tx->isOpen())
            ++active;
        }
      }
      if (active < MIN_CONNECTED_PEERS)
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
      std::this_thread::sleep_for(std::chrono::seconds(30));
      std::vector<std::string> banList;
      {
        std::lock_guard<std::timed_mutex> lk(peersMutex);
        for (auto &kv : peerTransports) {
          auto st = kv.second.state;
          if (!st)
            continue;
          if (st->frameCountMin > FRAME_LIMIT_MIN ||
              st->byteCountMin > BYTE_LIMIT_MIN) {
            st->misScore += 5;
          } else if (st->misScore > 0) {
            st->misScore -= 2;
            if (st->misScore < 0)
              st->misScore = 0;
          }
          st->frameCountMin = 0;
          st->byteCountMin = 0;
          if (st->misScore >= 100)
            banList.push_back(kv.first);
        }
      }
      for (const auto &p : banList)
        blacklistPeer(p);

      auto now = std::time(nullptr);
      // purge expired temporary bans
      for (auto it = bannedPeers.begin(); it != bannedPeers.end();) {
        if (now >= it->second.until) {
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

void Network::configureNatTraversal() {
#if defined(ALYN_ENABLE_NAT_TRAVERSAL)
  AppConfig cfg = getAppConfig();
  if (!cfg.enable_upnp && !cfg.enable_natpmp) {
    if (!configuredExternalExplicit)
      std::cout << "ℹ️  [Network] NAT traversal disabled by config; advertising "
                   "bound interfaces only.\n";
    return;
  }

  std::thread([this, cfg]() {
    auto endpoint = determineAnnounceEndpoint();
    if (!endpoint.first.empty() && isRoutableAddress(endpoint.first))
      return;

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(1);
    std::optional<std::string> natAddress;

#if defined(HAVE_MINIUPNPC)
    if (cfg.enable_upnp)
      natAddress = tryUPnPPortMapping(this->port);
#endif
#if defined(HAVE_LIBNATPMP)
    if (cfg.enable_natpmp && (!natAddress || natAddress->empty()) &&
        std::chrono::steady_clock::now() < deadline) {
      auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - std::chrono::steady_clock::now());
      natAddress =
          tryNATPMPPortMapping(this->port, static_cast<int>(remaining.count()));
    }
#endif
    if (!configuredExternalExplicit && natAddress && !natAddress->empty()) {
      recordExternalAddress(*natAddress, this->port);
      runHairpinCheck();
    } else if ((!natAddress || natAddress->empty()) &&
               !configuredExternalExplicit) {
      std::cerr <<
          "⚠️ [Network] NAT traversal failed; set external_address in config or "
          "manually forward port." << std::endl;
    }
  }).detach();
#else
  if (!configuredExternalExplicit)
    std::cout << "ℹ️  [Network] NAT traversal disabled at compile time; "
                 "listening on bound interfaces only.\n";
#endif
}

// Call this after all initial peers are connected
void Network::autoSyncIfBehind() {
  Blockchain &bc = Blockchain::getInstance();
  const size_t myHeight = bc.getHeight();
  const std::string myTip = bc.getLatestBlockHash();
  auto work = bc.computeCumulativeDifficulty(bc.getChain());
  uint64_t myWork = safeUint64(work);

  PeerManager *pm = peerManager.get();
  if (pm)
    pm->setLocalWork(myWork);

  bool behind = false;

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

    if (!pm)
      continue;
    int peerHeight = pm->getPeerHeight(peerAddr);
    std::string peerTip = pm->getPeerTipHash(peerAddr);
    uint64_t peerWork = pm->getPeerWork(peerAddr);

    std::cout << "[autoSync] peer=" << peerAddr << " height=" << peerHeight
              << " | local=" << myHeight << '\n';

    if (peerWork > myWork) {
      behind = true;
      int gap = peerHeight - static_cast<int>(myHeight);
      if (gap <= TAIL_SYNC_THRESHOLD) {
        std::cout << "  → requesting tail blocks\n";
        requestTailBlocks(peerAddr, myHeight,
                          Blockchain::getInstance().getLatestBlockHash());
      } else if (peerSupportsSnapshot(peerAddr)) {
        std::cout << "  → requesting snapshot sync\n";
        requestSnapshotSync(peerAddr);
      } else if (peerSupportsAggProof(peerAddr)) {
        std::cout << "  → requesting epoch headers\n";
        requestEpochHeaders(peerAddr);
      }
    } else if (peerHeight == static_cast<int>(myHeight) && !peerTip.empty() &&
               peerTip != myTip && peerWork >= myWork) {
      behind = true;
      std::cout << "  → tip mismatch, requesting missing block\n";
      requestBlockByHash(peerAddr, peerTip);
    }
  }

  if (pm) {
    int medianHeight = pm->getMedianNetworkHeight();
    if (medianHeight > 0 &&
        static_cast<long long>(myHeight) + SYNC_HEIGHT_TOLERANCE <
            static_cast<long long>(medianHeight)) {
      behind = true;
    }
    if (pm->getMaxPeerWork() > myWork)
      behind = true;
  }

  syncing = behind;
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
    if (peer.empty())
      continue;
    auto parsed = parsePeerFileEntry(peer);
    if (!parsed)
      continue;
    if (!isNumericAddress(parsed->host))
      continue;
    std::cout << "🌐 [DNS] Found peer: " << peer << "\n";
    peers.push_back(peer);
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
    std::string peerKey = ip;
    if (!isNumericAddress(ip))
      continue;
    if (isSelfEndpoint(ip, port)) {
      std::cout << "⚠️ Skipping self in discovered peers: " << peerKey << ':'
                << port << "\n";
      recordSelfEndpoint(ip, port);
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
      int port = 0;
      std::string host = peerId;
      if (it != peerTransports.end()) {
        auto endpoint = selectReachableEndpoint(it->second);
        if (!endpoint.first.empty() && endpoint.second > 0) {
          host = endpoint.first;
          port = endpoint.second;
        } else if (!it->second.ip.empty() && it->second.port > 0) {
          host = it->second.ip;
          port = it->second.port;
        }
      }
      if (port > 0)
        connectToNode(host, port);
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
    if (!seenBlockHashes.insert(block.getHash()).second)
      return;
  }
  broadcastINV({block.getHash()});
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
  uint64_t w64 = safeUint64(work);
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

void Network::sendBlockToPeer(const std::string &peer, const Block &blk,
                              bool requireRequest) {
  std::string raw;
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  if (requireRequest) {
    bool allowed = false;
    if (snapshot.state) {
      std::lock_guard<std::mutex> guard(snapshot.state->m);
      auto &pending = snapshot.state->pendingBlockRequests;
      auto it = pending.find(blk.getHash());
      if (it != pending.end()) {
        pending.erase(it);
        allowed = true;
      }
    }
    if (!allowed) {
      std::cerr << "⚠️ [sendBlockToPeer] refusing unsolicited block "
                << blk.getIndex() << " to " << peer << '\n';
      return;
    }
  }
  alyncoin::BlockProto proto = blk.toProtobuf();
  if (!proto.SerializeToString(&raw) || raw.empty())
    return;
  alyncoin::net::Frame fr;
  *fr.mutable_block_broadcast()->mutable_block() = proto;
  sendFrame(snapshot.transport, fr);
  if (snapshot.state)
    snapshot.state->highestSeen = blk.getIndex();
}
//
bool Network::isSelfPeer(const std::string &p) const {
  if (p == nodeId)
    return true;
  if (!publicPeerId.empty() && p == publicPeerId)
    return true;

  std::string lowered = toLowerCopy(p);

  if (lowered == "127.0.0.1" || lowered == "localhost" || lowered == "::1")
    return true;

  {
    std::lock_guard<std::mutex> lock(selfFilterMutex);
    if (localInterfaceAddrs.count(lowered) || localInterfaceAddrs.count(p) ||
        selfObservedAddrs.count(lowered) || selfObservedAddrs.count(p))
      return true;
  }

  return false;
}

bool Network::isSelfEndpoint(const std::string &host, int remotePort) const {
  if (host.empty() || remotePort <= 0)
    return false;

  const int localPort = static_cast<int>(port);
  const std::string lowered = toLowerCopy(host);

  if (host == nodeId || lowered == nodeId)
    return true;

  if (!configuredExternalAddress.empty()) {
    auto parsed = parseEndpoint(configuredExternalAddress, port);
    if (!parsed.first.empty()) {
      std::string parsedLower = toLowerCopy(parsed.first);
      if (remotePort == parsed.second &&
          (lowered == parsedLower || host == parsed.first))
        return true;
    }
  }

  if (!publicPeerId.empty()) {
    std::string pubLower = toLowerCopy(publicPeerId);
    if (remotePort == localPort &&
        (lowered == pubLower || host == publicPeerId))
      return true;
  }

  if (remotePort == localPort) {
    if (lowered == "127.0.0.1" || lowered == "localhost" || lowered == "::1")
      return true;
  }

  {
    std::lock_guard<std::mutex> lock(selfFilterMutex);
    if (selfObservedEndpoints.count(makeEndpointLabel(lowered, remotePort)) ||
        selfObservedEndpoints.count(makeEndpointLabel(host, remotePort)) ||
        manualSelfEndpoints.count(makeEndpointLabel(lowered, remotePort)) ||
        manualSelfEndpoints.count(makeEndpointLabel(host, remotePort)))
      return true;
  }

  std::vector<std::string> candidates;
  candidates.push_back(host);
  candidates.push_back(lowered);

  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address(host, ec);
  if (!ec)
    candidates.push_back(addr.to_string());

  {
    std::lock_guard<std::mutex> lock(selfFilterMutex);
    for (const auto &candidate : candidates) {
      std::string candLower = toLowerCopy(candidate);
      if (localInterfaceAddrs.count(candLower) ||
          localInterfaceAddrs.count(candidate) ||
          selfObservedAddrs.count(candLower) ||
          selfObservedAddrs.count(candidate) ||
          manualSelfAddrs.count(candLower) ||
          manualSelfAddrs.count(candidate)) {
        if (remotePort == localPort)
          return true;
      }
      if (selfObservedEndpoints.count(
              makeEndpointLabel(candLower, remotePort)) ||
          selfObservedEndpoints.count(makeEndpointLabel(candidate, remotePort)) ||
          manualSelfEndpoints.count(makeEndpointLabel(candLower, remotePort)) ||
          manualSelfEndpoints.count(makeEndpointLabel(candidate, remotePort)))
        return true;
    }
  }

  return false;
}

std::string Network::getSelfAddressAndPort() const {
  // Prefer explicit publicPeerId if set
  if (!publicPeerId.empty())
    return publicPeerId;
  // Fallback: localhost
  return "127.0.0.1";
}

void Network::setPublicPeerId(const std::string &peerId) {
  if (configuredExternalExplicit) {
    auto parsed = parseEndpoint(configuredExternalAddress, port);
    if (!parsed.first.empty())
      publicPeerId = parsed.first;
  } else {
    publicPeerId = peerId;
  }
  if (peerManager) {
    auto endpoint = determineAnnounceEndpoint();
    if (!endpoint.first.empty() && endpoint.second > 0)
      peerManager->setExternalAddress(endpoint.first + ':' + std::to_string(endpoint.second));
  }
  if (!configuredExternalExplicit && getAppConfig().hairpin_probe)
    runHairpinCheck();
}

void Network::setConfiguredExternalAddress(const std::string &address) {
  if (address.empty())
    return;
  configuredExternalExplicit = true;
  auto parsed = parseEndpoint(address, port);
  if (parsed.first.empty() || parsed.second == 0) {
    std::cerr << "⚠️ [Network] Ignoring invalid external address: " << address
              << '\n';
    return;
  }
  configuredExternalAddress = parsed.first + ':' + std::to_string(parsed.second);
  recordExternalAddress(parsed.first, parsed.second);
  if (getAppConfig().hairpin_probe)
    runHairpinCheck();
}

std::pair<std::string, unsigned short> Network::determineAnnounceEndpoint() const {
  if (!configuredExternalAddress.empty()) {
    auto parsed = parseEndpoint(configuredExternalAddress, port);
    if (!parsed.first.empty() && parsed.second > 0)
      return parsed;
  }
  if (!publicPeerId.empty())
    return {publicPeerId, port};
  return {std::string(), 0};
}

void Network::recordExternalAddress(const std::string &ip, unsigned short portValue) {
  if (ip.empty() || portValue == 0)
    return;
  setExternalAddress(ip, static_cast<int>(portValue));
  if (!configuredExternalExplicit)
    configuredExternalAddress = ip + ':' + std::to_string(portValue);
  setPublicPeerId(ip);
  std::cout << "📣 [Network] Announcing reachable address " << ip << ':' << portValue
            << '\n';
}

namespace {

template <typename Timer>
auto cancelTimer(Timer &timer, int)
    -> decltype(timer.cancel(), void()) {
  timer.cancel();
}

template <typename Timer>
void cancelTimer(Timer &timer, long) {
  boost::system::error_code ignored;
  timer.cancel(ignored);
}

template <typename Timer>
void cancelTimer(Timer &timer) {
  cancelTimer(timer, 0);
}

} // namespace

void Network::runHairpinCheck() {
  if (!getAppConfig().hairpin_probe)
    return;
  bool expected = false;
  if (!hairpinCheckAttempted.compare_exchange_strong(expected, true))
    return;

  auto endpoint = determineAnnounceEndpoint();
  if (endpoint.first.empty() || endpoint.second == 0)
    return;
  if (!isRoutableAddress(endpoint.first))
    return;

  recordSelfEndpoint(endpoint.first, static_cast<int>(endpoint.second));

  std::thread([endpoint]() {
    try {
      boost::asio::io_context ctx;
      tcp::socket sock(ctx);
      tcp::endpoint target(boost::asio::ip::make_address(endpoint.first),
                           endpoint.second);
      boost::asio::steady_timer timer(ctx);
      boost::system::error_code connectEc;
      bool completed = false;
      bool timedOut = false;

      timer.expires_after(std::chrono::seconds(3));
      timer.async_wait([&](const boost::system::error_code &ec) {
        if (!ec && !completed) {
          timedOut = true;
          connectEc = boost::asio::error::make_error_code(
              boost::asio::error::timed_out);
          boost::system::error_code cancelEc;
          sock.cancel(cancelEc);
        }
      });

      sock.async_connect(target, [&](const boost::system::error_code &ec) {
        if (completed)
          return;
        completed = true;
        if (!timedOut)
          connectEc = ec;
        cancelTimer(timer);
      });

      ctx.run();

      if (timedOut || connectEc) {
        std::string reason =
            timedOut ? "connection timed out" : connectEc.message();
        std::cerr << "⚠️ [NAT] Hairpin test failed for " << endpoint.first << ':'
                  << endpoint.second << " — " << reason
                  << ". Will rely on DNS/bootstrap peers.\n";
      } else {
        std::cout << "✅ [NAT] Hairpin test succeeded for " << endpoint.first
                  << ':' << endpoint.second << '\n';
        boost::system::error_code closeEc;
        sock.close(closeEc);
      }
    } catch (const std::exception &ex) {
      std::cerr << "⚠️ [NAT] Hairpin test error: " << ex.what() << '\n';
    }
  }).detach();
}
//

void Network::noteBlockRequested(const std::string &peer,
                                 const std::string &hash) {
  if (peer.empty() || hash.empty())
    return;
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  std::lock_guard<std::mutex> guard(snapshot.state->m);
  snapshot.state->pendingBlockRequests.insert(hash);
}

void Network::handleGetData(const std::string &peer,
                            const std::vector<std::string> &hashes) {
  Blockchain &bc = Blockchain::getInstance();
  for (const auto &h : hashes) {
    noteBlockRequested(peer, h);
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
    if (sender.empty())
      return;

    bool ban = false;
    {
      std::lock_guard<std::timed_mutex> lk(peersMutex);
      auto it = peerTransports.find(sender);
      if (it != peerTransports.end() && it->second.state) {
        it->second.state->misScore += 100;
        ban = it->second.state->misScore >= BAN_THRESHOLD;
      }
    }

    if (ban)
      blacklistPeer(sender);
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

  // 2) Duplicate and side-chain detection
  if (blockchain.hasBlockHash(newBlock.getHash())) {
    std::cout << "ℹ️ [Node] Duplicate block received.\n";
    return;
  }

  if (!blockchain.getChain().empty()) {
    std::string localTipHash = blockchain.getLatestBlockHash();
    if (newBlock.getPreviousHash() != localTipHash) {
      if (blockchain.hasBlockHash(newBlock.getPreviousHash())) {
        std::cout << "↪️ [Node] Side-chain block stored.\n";
        blockchain.addBlock(newBlock);
        blockchain.saveToDB();
        return;
      }

      std::cerr
          << "⚠️ [Fork Detected] Previous hash mismatch at incoming block.\n";

      if (!sender.empty())
        beginHeaderBridge(sender);

      blockchain.saveForkView({newBlock});

      Blockchain::ValidationResult vr{};
      bool added = blockchain.tryAddBlock(newBlock, vr);
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
      if (!sender.empty())
        beginHeaderBridge(sender);
      blockchain.setPendingForkChain({newBlock});
      for (const auto &peer : peerTransports) {
        sendForkRecoveryRequest(peer.first, newBlock.getHash());
      }
    }
    // Stale blocks are valid but belong to a shorter chain. We initiate
    // fork recovery without penalizing the sender so honest peers are not
    // punished for being slightly behind. Fork recovery will determine
    // the heavier chain without raising the misbehavior score.
    return;
  }
  if (newBlock.getIndex() > expectedIndex) {
    std::cerr << "⚠️ [Node] Received future block. Buffering (idx="
              << newBlock.getIndex() << ").\n";
    futureBlockBuffer[newBlock.getIndex()] = newBlock;

    if (newBlock.getIndex() > expectedIndex + 5) {
      if (!sender.empty())
        beginHeaderBridge(sender);
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
    Blockchain::ValidationResult vr{};
    if (!blockchain.tryAddBlock(newBlock, vr)) {
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
      peerManager->setPeerWork(sender, safeUint64(work));
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
  int minutes = getAppConfig().ban_minutes;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end()) {
      auto now = std::chrono::steady_clock::now();
      if (it->second.state &&
          it->second.state->graceUntil !=
              std::chrono::steady_clock::time_point{} &&
          now < it->second.state->graceUntil) {
        std::cerr << "ℹ️  [ban] grace period active for " << peer << '\n';
        return;
      }

      it->second.state->banCount++;
      minutes = std::min(60 * 24, minutes << (it->second.state->banCount - 1));
      it->second.state->banUntil = now + std::chrono::minutes(minutes);
    }
    peerTransports.erase(peer);
  }
  auto &be = bannedPeers[peer];
  be.strikes++;
  int bh = std::min(60 * 24, minutes << (be.strikes - 1));
  be.until = std::time(nullptr) + bh * 60;
}

bool Network::isBlacklisted(const std::string &peer) {
  auto it = bannedPeers.find(peer);
  if (it == bannedPeers.end())
    return false;
  // clear expired ban
  if (std::time(nullptr) >= it->second.until) {
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

  int peerHeight = peerManager ? peerManager->getPeerHeight(peer) : -1;
  int localHeight = Blockchain::getInstance().getHeight();
  std::string peerTip = peerManager ? peerManager->getPeerTipHash(peer) : "";
  std::string localTip = Blockchain::getInstance().getLatestBlockHash();
  uint64_t peerWork = peerManager ? peerManager->getPeerWork(peer) : 0;
  uint64_t localWork = peerManager ? peerManager->getLocalWork() : 0;
  if (peerHeight > localHeight) {
    int gap = peerHeight - localHeight;
    if (gap <= TAIL_SYNC_THRESHOLD) {
      requestTailBlocks(peer, localHeight,
                        Blockchain::getInstance().getLatestBlockHash());
    } else if (peerSupportsSnapshot(peer)) {
      requestSnapshotSync(peer);
    } else if (peerSupportsAggProof(peer)) {
      requestEpochHeaders(peer);
    } else {
      std::cerr << "⚠️  Peer " << peer
                << " offers no modern sync capability. Skipping.\n";
    }
  } else if (peerHeight == localHeight && !peerTip.empty() &&
             peerTip != localTip) {
    if (peerWork >= localWork) {
      beginHeaderBridge(peer);
      std::cout << "📡 [SYNC] Tip mismatch with peer " << peer
                << ", requesting block " << peerTip.substr(0, 8) << "...\n";
      requestBlockByHash(peer, peerTip);
    } else {
      Block blk;
      if (Blockchain::getInstance().getBlockByHash(localTip, blk)) {
        std::cout << "📡 [SYNC] Advertising block " << localTip.substr(0, 8)
                  << " to peer " << peer << "\n";
        auto snapshot = getPeerSnapshot(peer);
        if (snapshot.transport && snapshot.transport->isOpen()) {
          alyncoin::net::Frame fr;
          fr.mutable_inv()->add_hashes(blk.getHash());
          sendFrame(snapshot.transport, fr);
        }
      }
    }
  }

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

  PeerEntry entry;
  entry.tx = transport;
  entry.state = std::make_shared<PeerState>();
  entry.initiatedByUs = false;
  entry.port = 0;
  entry.ip = peer;
  peerTransports.emplace(peer, std::move(entry));
  if (auto it = peerTransports.find(peer); it != peerTransports.end()) {
    it->second.state->connectedAt = std::chrono::steady_clock::now();
    it->second.state->graceUntil =
        it->second.state->connectedAt + BAN_GRACE_BASE;
  }
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
  hs.set_snapshot_size(static_cast<uint32_t>(MAX_SNAPSHOT_CHUNK_SIZE));
  alyncoin::net::Frame fr;
  *fr.mutable_handshake() = hs;
  std::string out;
  fr.SerializeToString(&out);
  std::cerr << "[finishOutboundHandshake] handshake bytes size=" << out.size()
            << " first32=" << dumpHex(out.data(), out.size()) << '\n';
  if (!sendFrameImmediate(tx, fr))
    return false;
  // Provide our current height immediately after the handshake
  std::string peer = tx->getRemoteIP();
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

  // Only request sync if the peer reports a higher height.
  int peerHeight = peerManager ? peerManager->getPeerHeight(peerId) : -1;
  int localHeight = Blockchain::getInstance().getHeight();
  if (peerHeight > localHeight) {
    int gap = peerHeight - localHeight;
    if (gap <= TAIL_SYNC_THRESHOLD) {
      requestTailBlocks(peerId, localHeight,
                        Blockchain::getInstance().getLatestBlockHash());
    } else if (peerSupportsSnapshot(peerId)) {
      requestSnapshotSync(peerId);
    } else if (peerSupportsAggProof(peerId)) {
      requestEpochHeaders(peerId);
    }
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

    {
      // Serialize access to peerTransports while updating per-peer counters
      std::lock_guard<std::timed_mutex> lk(peersMutex);
      auto it = peerTransports.find(peerId);
      if (it != peerTransports.end() && it->second.state) {
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
          if (st.misScore >= BAN_THRESHOLD)
            blacklistPeer(peerId);
        }
      }
    }

    alyncoin::net::Frame f;
    if (f.ParseFromString(blob)) {
      std::cerr << "[readLoop] ✅ Parsed frame successfully from peer: "
                << peerId << '\n';
      {
        std::lock_guard<std::timed_mutex> lk(peersMutex);
        auto it = peerTransports.find(peerId);
        if (it != peerTransports.end() && it->second.state) {
          auto &pf = it->second.state->parseFailCount;
          pf = static_cast<int>(pf * 0.9);
        }
      }
      auto *item = new RxItem{f, peerId};
      {
        std::unique_lock<std::mutex> lk(rxQMutex);
        rxQCv.wait(lk, [] { return rxQ.size() < RXQ_CAPACITY; });
        rxQ.push(item);
      }
      rxQCv.notify_one();
    } else {
      std::cerr << "[readLoop] ❌ Failed to parse protobuf frame!" << '\n';
      bool disconnect = false;
      int failCount = 0;
      {
        std::lock_guard<std::timed_mutex> lk(peersMutex);
        auto it = peerTransports.find(peerId);
        if (it != peerTransports.end() && it->second.state) {
          auto &st = *it->second.state;
          failCount = ++st.parseFailCount;
          st.misScore += 10;
          disconnect =
              failCount >= PARSE_FAIL_LIMIT || st.misScore >= BAN_THRESHOLD;
        }
      }
      if (disconnect) {
        std::cerr << "[readLoop] Too many parse failures from peer: " << peerId
                  << " (" << failCount << ")\n";
        markPeerOffline(peerId);
        return;
      } else {
        std::cerr << "[readLoop] Parse error count for " << peerId << " = "
                  << failCount << '\n';
        sendHeight(peerId);
      }
    }
  };
  transport->startReadBinaryLoop(cb);
  std::cout << "🔄 Binary read-loop armed for " << peerId << '\n';
}

void Network::processFrame(const alyncoin::net::Frame &f,
                           const std::string &peer) {
  if (!f.IsInitialized()) {
    std::cerr << "[net] Uninitialized frame from " << peer << '\n';
    return;
  }
  if (f.ByteSizeLong() == 0 || f.ByteSizeLong() > MAX_WIRE_PAYLOAD) {
    std::cerr << "[net] Invalid frame size from " << peer << '\n';
    return;
  }
  dispatch(f, peer);
}

void Network::dispatch(const alyncoin::net::Frame &f, const std::string &peer) {
  WireFrame tag = WireFrame::OTHER;
  if (f.has_handshake())
    tag = WireFrame::HANDSHAKE;
  else if (f.has_height_req() || f.has_height_res() || f.has_height_probe())
    tag = WireFrame::HEIGHT;
  else if (f.has_peer_list())
    tag = WireFrame::PEER_LIST;
  else if (f.has_block_broadcast())
    tag = WireFrame::BLOCK;
  else if (f.has_ping() || f.has_pong())
    tag = WireFrame::PING;
  else if (f.has_snapshot_meta())
    tag = WireFrame::SNAP_META;
  else if (f.has_snapshot_chunk())
    tag = WireFrame::SNAP_CHUNK;
  else if (f.has_snapshot_end())
    tag = WireFrame::SNAP_END;
  std::cerr << "[<<] Incoming Frame from " << peer
            << " Type=" << static_cast<int>(tag) << "\n";
  switch (f.kind_case()) {
  case alyncoin::net::Frame::kHandshake: {
    const auto &hs = f.handshake();
    if (peerManager) {
      peerManager->setPeerHeight(peer, hs.height());
      peerManager->setPeerWork(peer, hs.total_work());
    }
    if (auto snapshot = getPeerSnapshot(peer); snapshot.state) {
      auto st = snapshot.state;
      st->highestSeen = hs.height();
      bool remoteAgg = false;
      bool remoteSnap = false;
      bool remoteWhisper = false;
      bool remoteTls = false;
      bool remoteBanDecay = false;
      for (const auto &cap : hs.capabilities()) {
        if (cap == "agg_proof_v1")
          remoteAgg = true;
        else if (cap == "snapshot_v1")
          remoteSnap = true;
        else if (cap == "whisper_v1")
          remoteWhisper = true;
        else if (cap == "tls_v1")
          remoteTls = true;
        else if (cap == "ban_decay_v1")
          remoteBanDecay = true;
      }
      st->supportsAggProof = remoteAgg;
      st->supportsSnapshot = remoteSnap;
      st->supportsWhisper = remoteWhisper;
      st->supportsTls = remoteTls;
      st->supportsBanDecay = remoteBanDecay;
      st->snapshotChunkPreference =
          remoteSnap ? resolveSnapshotChunkSize(hs.snapshot_size()) : 0;
      st->frameRev = hs.frame_rev();
      st->version = hs.version();
      st->handshakeComplete = true;
    }
    if (auto hints = parseConsensusHints(hs.capabilities());
        hints.hasDifficulty || hints.hasReward) {
      Blockchain::getInstance().applyConsensusHints(
          static_cast<int>(hs.height()),
          hints.hasDifficulty ? hints.difficulty : -1,
          hints.hasReward ? hints.reward : -1.0);
    }
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
    handleBlockBatch(peer, f.block_batch());
    break;
  }
  case alyncoin::net::Frame::kBlockRequest: {
    uint64_t idx = f.block_request().index();
    Blockchain &bc = Blockchain::getInstance();
    if (idx < bc.getChain().size()) {
      alyncoin::net::Frame out;
      *out.mutable_block_response()->mutable_block() =
          bc.getChain()[static_cast<size_t>(idx)].toProtobuf();
      if (auto snapshot = getPeerSnapshot(peer); snapshot.transport)
        sendFrame(snapshot.transport, out);
    }
    break;
  }
  case alyncoin::net::Frame::kBlockResponse: {
    Block blk = Block::fromProto(f.block_response().block());
    if (peerManager)
      peerManager->handleBlockResponse(blk);
    handleNewBlock(blk, peer);
    break;
  }
  case alyncoin::net::Frame::kPing: {
    alyncoin::net::Frame out;
    out.mutable_pong();
    if (auto snapshot = getPeerSnapshot(peer); snapshot.transport) {
      if (snapshot.state)
        snapshot.state->graceUntil =
            std::chrono::steady_clock::now() + BAN_GRACE_BASE;
      sendFrame(snapshot.transport, out);
    }
    break;
  }
  case alyncoin::net::Frame::kPong: {
    if (auto snapshot = getPeerSnapshot(peer); snapshot.state)
      snapshot.state->graceUntil =
          std::chrono::steady_clock::now() + BAN_GRACE_BASE;
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
    if (auto snapshot = getPeerSnapshot(peer); snapshot.state)
      snapshot.state->highestSeen = f.height_res().height();
    if (f.height_res().height() > Blockchain::getInstance().getHeight() &&
        !isSyncing()) {
      Blockchain &bc = Blockchain::getInstance();
      requestTailBlocks(peer, bc.getHeight(), bc.getLatestBlockHash());
    }
    {
      Blockchain &bc = Blockchain::getInstance();
      uint64_t localWork =
          bc.computeCumulativeDifficulty(bc.getChain()).convert_to<uint64_t>();
      if (f.height_res().height() > bc.getHeight() &&
          f.height_res().total_work() <= localWork)
        penalizePeer(peer, 20);
    }
    break;
  case alyncoin::net::Frame::kHeightProbe: {
    const auto &hp = f.height_probe();
    if (peerManager) {
      peerManager->setPeerHeight(peer, hp.height());
      peerManager->setPeerWork(peer, hp.total_work());
      peerManager->setPeerTipHash(peer, hp.tip_hash());
    }
    if (auto snapshot = getPeerSnapshot(peer); snapshot.state)
      snapshot.state->highestSeen = hp.height();
    {
      Blockchain &bc = Blockchain::getInstance();
      uint64_t localWork =
          bc.computeCumulativeDifficulty(bc.getChain()).convert_to<uint64_t>();
      if (hp.height() > bc.getHeight() && hp.total_work() <= localWork)
        penalizePeer(peer, 20);
    }
    break;
  }
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
      if (auto snapshot = getPeerSnapshot(peer); snapshot.transport)
        sendFrame(snapshot.transport, req);
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
      if (auto snapshot = getPeerSnapshot(peer); snapshot.transport)
        sendFrame(snapshot.transport, out);
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
      if (auto snapshot = getPeerSnapshot(peer); snapshot.state) {
        snapshot.state->misScore += 100;
        if (snapshot.state->misScore >= BAN_THRESHOLD)
          blacklistPeer(peer);
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
    bool added = false;
    size_t processed = 0;
    for (const auto &p : f.peer_list().peers()) {
      if (processed++ >= MAX_GOSSIP_PEERS)
        break;
      size_t pos = p.find(':');
      if (pos == std::string::npos)
        continue;
      std::string ip = p.substr(0, pos);
      int port = 0;
      try {
        port = std::stoi(p.substr(pos + 1));
      } catch (const std::exception &) {
        continue;
      }
      if (ip.empty() || port <= 0 || port > 65535)
        continue;
      if (isBlockedServicePort(port))
        continue;
      if (!isShareableAddress(ip))
        continue;
      if ((ip == "127.0.0.1" || ip == "localhost") && port == this->port)
        continue;
      if (isSelfEndpoint(ip, port)) {
        recordSelfEndpoint(ip, port);
        continue;
      }
      if (noteShareableEndpoint(ip, port, false, false, peer))
        added = true;
      connectToNode(ip, port);
    }
    if (added) {
      auto now = std::chrono::steady_clock::now();
      bool canBroadcast = false;
      {
        std::lock_guard<std::mutex> lock(peerBroadcastMutex);
        if (lastPeerRebroadcast == std::chrono::steady_clock::time_point{} ||
            now - lastPeerRebroadcast >= PEERLIST_RATE_LIMIT) {
          lastPeerRebroadcast = now;
          canBroadcast = true;
        }
      }
      if (canBroadcast)
        broadcastPeerList(peer);
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
      if (auto snapshot = getPeerSnapshot(peer); snapshot.state)
        snapshot.state->misScore += 100;
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
    auto snapshot = getPeerSnapshot(peer);
    if (!snapshot.state)
      break;
    crypto::SphinxPacket inner;
    std::string nextHop;
    if (!crypto::peelPacket(
            pkt,
            std::vector<uint8_t>(snapshot.state->linkKey.begin(),
                                 snapshot.state->linkKey.end()),
            &nextHop, &inner))
      break;
    if (!nextHop.empty()) {
      if (auto relay = getPeerSnapshot(nextHop);
          relay.transport && relay.transport->isOpen() && relay.state) {
        alyncoin::net::Frame fr;
        fr.mutable_whisper()->set_data(
            std::string(inner.header.begin(), inner.header.end()) +
            std::string(inner.payload.begin(), inner.payload.end()));
        std::this_thread::sleep_for(randomBroadcastDelay());
        sendFrame(relay.transport, fr);
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
  case alyncoin::net::Frame::kSnapshotReq: {
    if (auto snapshot = getPeerSnapshot(peer);
        snapshot.transport && snapshot.transport->isOpen()) {
      size_t preferred =
          snapshot.state ? snapshot.state->snapshotChunkPreference : 0;
      sendSnapshot(peer, snapshot.transport, -1, preferred);
    } else
      std::cerr << "⚠️ [Snapshot] Received request from unknown peer " << peer
                << '\n';
    break;
  }
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
  if (remotePort <= 0 || remotePort > 65535) {
    std::cerr << "⚠️ [connectToNode] invalid port for " << host << ':' << remotePort
              << '\n';
    return false;
  }
  if (isBlockedServicePort(remotePort)) {
    std::cerr << "⚠️ [connectToNode] suspicious service port for " << host << ':'
              << remotePort << '\n';
    return false;
  }
  size_t currentPeers = 0;
  {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    currentPeers = peerTransports.size();
  }
  if (currentPeers >= MAX_PEERS) {
    std::cerr << "⚠️ [connectToNode] peer cap reached, skip " << host << ':'
              << remotePort << '\n';
    return false;
  }

  const std::string peerKey = host;
  if (isSelfEndpoint(host, remotePort)) {
    recordSelfEndpoint(host, remotePort);
    std::cout << "⚠️ [connectToNode] Skipping self endpoint " << host << ':'
              << remotePort
              << ". If other nodes fail to reach you, forward TCP port "
              << port << " or enable UPnP." << '\n';
    return false;
  }

  auto now = std::chrono::steady_clock::now();
  {
    std::lock_guard<std::mutex> gossipLock(gossipMutex);
    auto &rec = knownPeerEndpoints[makeEndpointLabel(host, remotePort)];
    if (rec.host.empty())
      rec.host = host;
    if (rec.port == 0)
      rec.port = remotePort;
    if (rec.nextDialAllowed != std::chrono::steady_clock::time_point{} &&
        now < rec.nextDialAllowed) {
      auto wait = std::chrono::duration_cast<std::chrono::seconds>(rec.nextDialAllowed - now);
      std::cerr << "⚠️ [connectToNode] backoff active for " << host << ':'
                << remotePort << " (" << wait.count() << "s)" << '\n';
      return false;
    }
    rec.lastSeen = now;
  }

  struct DialGuard {
    Network *net;
    explicit DialGuard(Network *n) : net(n) {}
    ~DialGuard() {
      if (net)
        net->activeOutboundDials.fetch_sub(1);
    }
  };

  struct DialAttemptGuard {
    Network *net;
    std::string host;
    int port;
    bool attempted{false};
    bool success{false};
    DialAttemptGuard(Network *n, std::string h, int p)
        : net(n), host(std::move(h)), port(p) {}
    ~DialAttemptGuard() {
      if (net && attempted && !success)
        net->recordEndpointFailure(host, port);
    }
  };
  {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    auto it = peerTransports.find(peerKey);
    if (it != peerTransports.end() && it->second.tx && it->second.tx->isOpen())
      return true;
  }
  if (isBlacklisted(peerKey)) {
    std::cerr << "⚠️ [connectToNode] " << peerKey << " is banned.\n";
    return false;
  }
  {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    auto it = peerTransports.find(peerKey);
    if (it != peerTransports.end() &&
        std::chrono::steady_clock::now() < it->second.state->banUntil) {
      std::cerr << "⚠️ [connectToNode] " << peerKey << " is temporarily banned."
                << '\n';
      return false;
    }
  }

  int previous = activeOutboundDials.fetch_add(1);
  if (previous >= MAX_PARALLEL_DIALS) {
    activeOutboundDials.fetch_sub(1);
    std::cerr << "⚠️ [connectToNode] dial concurrency limit reached ("
              << MAX_PARALLEL_DIALS << ")" << '\n';
    return false;
  }
  DialGuard dialGuard(this);
  DialAttemptGuard attemptGuard(this, host, remotePort);

  std::string prefix = ipPrefix(host);
  if (!prefix.empty()) {
    std::lock_guard<std::timed_mutex> g(peersMutex);
    int count = 0;
    for (const auto &kv : peerTransports) {
      std::string ip = kv.second.ip;
      if (ipPrefix(ip) == prefix)
        ++count;
    }
    if (count >= 2) {
      std::cerr << "⚠️ [connectToNode] prefix limit reached for " << host << " ("
                << prefix << " count=" << count << ")" << '\n';
      return false;
    }
  }

  try {
    std::cout << "[PEER_CONNECT] → " << host << ':' << remotePort << '\n';

    std::shared_ptr<Transport> tx;
    if (getAppConfig().enable_tls && tlsContext) {
      auto sslTx = std::make_shared<SslTransport>(ioContext, *tlsContext);
      attemptGuard.attempted = true;
      if (!sslTx->connect(host, remotePort)) {
        std::cerr << "❌ [connectToNode] Connection to " << host << ':'
                  << remotePort << " failed." << '\n';
        return false;
      }
      tx = sslTx;
    } else {
      auto plain = std::make_shared<TcpTransport>(ioContext);
      attemptGuard.attempted = true;
      if (!plain->connect(host, remotePort)) {
        std::cerr << "❌ [connectToNode] Connection to " << host << ':'
                  << remotePort << " failed." << '\n';
        return false;
      }
      tx = plain;
    }

    std::string socketIp = tx->getRemoteIP();
    int socketPort = tx->getRemotePort();

    {
      ScopedLockTracer _t("connectToNode");
      // no pre-handshake duplicate check since peers are keyed by node_id
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
    std::cerr << "[connectToNode] raw handshake bytes size=" << blob.size()
              << " first32=" << dumpHex(blob.data(), blob.size()) << '\n';

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
      if (it != peerTransports.end() && it->second.tx &&
          it->second.tx->isOpen()) {
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
    std::string theirNodeId = rhs.node_id();
    if (theirNodeId.empty())
      theirNodeId = peerKey;
    if (!theirNodeId.empty() && isSelfNodeId(theirNodeId)) {
      std::cerr << "🛑 [connectToNode] remote node id matches ours (" << theirNodeId
                << ")" << '\n';
      recordSelfEndpoint(host, remotePort);
      tx->close();
      return false;
    }
    int advertisedPort = remotePort;
    if (rhs.listen_port() > 0)
      advertisedPort = static_cast<int>(rhs.listen_port());
    std::string canonicalIp = socketIp.empty() ? host : socketIp;
    const uint64_t remoteNonce = rhs.nonce();
    if (isSelfNonce(remoteNonce)) {
      std::cout << "🛑 Self-connect ignored (nonce match) while dialing "
                << peerKey << '\n';
      recordSelfEndpoint(host, remotePort);
      if (!canonicalIp.empty())
        recordSelfEndpoint(canonicalIp, advertisedPort);
      tx->close();
      return false;
    }
    if (!rhs.observed_ip().empty() && isRoutableAddress(rhs.observed_ip())) {
      const std::string observed = rhs.observed_ip();
      setExternalAddress(observed, static_cast<int>(port));
      if (!configuredExternalExplicit &&
          (publicPeerId.empty() || publicPeerId == "127.0.0.1")) {
        setPublicPeerId(observed);
        std::cout << "🌐 [connectToNode] Detected external address "
                  << publicPeerId << " from peer " << theirNodeId << '\n';
      }
    }

    if (advertisedPort > 0) {
      auto rejectSelf = [&](const std::string &ip, const std::string &label) {
        if (ip.empty())
          return false;
        if (!isSelfEndpoint(ip, advertisedPort))
          return false;
        std::cout << "🛑 [connectToNode] self endpoint detected via " << label
                  << " => " << ip << ':' << advertisedPort << '\n';
        recordSelfEndpoint(ip, advertisedPort);
        tx->close();
        return true;
      };
      if (rejectSelf(canonicalIp, "canonical") ||
          rejectSelf(socketIp, "observed") || rejectSelf(host, "dialed"))
        return false;
    }
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
    if (rhs.pub_key().size() == 32) {
      if (crypto_scalarmult_curve25519(shared.data(), myPriv.data(),
                                       reinterpret_cast<const unsigned char *>(
                                           rhs.pub_key().data())) != 0) {
        tx->close();
        std::cerr << "⚠️ [connectToNode] invalid peer public key from "
                  << peerKey << '\n';
        return false;
      }
    }

    std::string finalKey = theirNodeId;
    {
      ScopedLockTracer t("connectToNode/register");
      std::lock_guard<std::timed_mutex> lk(peersMutex);
      auto itExisting = peerTransports.find(finalKey);
      if (itExisting != peerTransports.end() && itExisting->second.tx &&
          itExisting->second.tx->isOpen()) {
        uint64_t existingNonce =
            itExisting->second.state ? itExisting->second.state->remoteNonce : 0;
        bool replaceExisting = false;
        if (existingNonce == 0 && remoteNonce != 0) {
          replaceExisting = true;
        } else if (remoteNonce != 0 && existingNonce != 0 &&
                   remoteNonce < existingNonce) {
          replaceExisting = true;
        }
        if (replaceExisting) {
          std::cout << "🔁 replacing connection to " << finalKey << '\n';
          itExisting->second.tx->closeGraceful();
          itExisting->second.tx = tx;
          itExisting->second.initiatedByUs = true;
          itExisting->second.port = advertisedPort;
          itExisting->second.ip = canonicalIp;
          itExisting->second.observedIp = socketIp.empty() ? host : socketIp;
          itExisting->second.observedPort = socketPort;
          if (itExisting->second.state)
            itExisting->second.state->remoteNonce = remoteNonce;
        } else {
          std::cout << "🔁 already connected to " << finalKey << '\n';
          if (itExisting->second.state && existingNonce == 0 &&
              remoteNonce != 0)
            itExisting->second.state->remoteNonce = remoteNonce;
          if (tx)
            tx->closeGraceful();
          return false;
        }
      } else {
        PeerEntry entry;
        entry.tx = tx;
        entry.state = std::make_shared<PeerState>();
        entry.initiatedByUs = true;
        entry.port = advertisedPort;
        entry.ip = canonicalIp;
        entry.observedPort = socketPort;
        entry.observedIp = socketIp.empty() ? host : socketIp;
        peerTransports[finalKey] = std::move(entry);
      }
      knownPeers.insert(finalKey);
      if (anchorPeers.size() < 2)
        anchorPeers.insert(finalKey);
      auto st = peerTransports[finalKey].state;
      st->connectedAt = std::chrono::steady_clock::now();
      st->graceUntil = st->connectedAt + BAN_GRACE_BASE;
      st->supportsAggProof = theirAgg;
      st->supportsSnapshot = theirSnap;
      st->supportsWhisper = theirWhisper;
      st->supportsTls = theirTls;
      st->supportsBanDecay = theirBanDecay;
      st->frameRev = remoteRev;
      st->version = rhs.version();
      st->lastTailHeight = theirHeight;
      st->highestSeen = static_cast<uint32_t>(theirHeight);
      if (rhs.pub_key().size() == 32)
        std::copy(shared.begin(), shared.end(), st->linkKey.begin());
      st->remoteNonce = remoteNonce;
      st->handshakeComplete = true;
      if (peerManager) {
        if (peerManager->registerPeer(finalKey))
          peerManager->setPeerHeight(finalKey, theirHeight);
      }
    }

    const std::string shareHost = canonicalIp.empty() ? host : canonicalIp;
    {
      std::lock_guard<std::mutex> gossipLock(gossipMutex);
      auto itDial = knownPeerEndpoints.find(makeEndpointLabel(host, remotePort));
      if (itDial != knownPeerEndpoints.end()) {
        itDial->second.failureCount = 0;
        itDial->second.nextDialAllowed = std::chrono::steady_clock::now();
        itDial->second.lastSuccess = std::chrono::steady_clock::now();
      }
    }
    noteShareableEndpoint(shareHost, advertisedPort, true, true, finalKey);

    /* pick correct sync action now */
    const int localHeight = Blockchain::getInstance().getHeight();
    if (theirHeight > localHeight) {
      int gap = theirHeight - localHeight;
      if (gap <= TAIL_SYNC_THRESHOLD) {
        requestTailBlocks(finalKey, localHeight,
                          Blockchain::getInstance().getLatestBlockHash());
      } else if (theirSnap) {
        requestSnapshotSync(finalKey);
      } else if (theirAgg) {
        requestEpochHeaders(finalKey);
      }
    }

    startBinaryReadLoop(finalKey, tx);
    sendInitialRequests(finalKey);

    autoSyncIfBehind();
    intelligentSync();
    attemptGuard.success = true;
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
  std::vector<PeerFileEntry> manualPeers;
  {
    std::lock_guard<std::mutex> lock(fileIOMutex);
    const auto path = peersFilePath();
    std::ifstream file(path);
    if (!file.is_open()) {
      std::cerr << "⚠️ [loadPeers] " << path << " not found, using automatic bootstrap.\n";
    } else {
      std::string line;
      while (std::getline(file, line)) {
        if (line.empty())
          continue;
        auto parsed = parsePeerFileEntry(line);
        if (parsed)
          manualPeers.push_back(*parsed);
      }
      if (manualPeers.empty())
        std::cout << "ℹ️  [loadPeers] " << path
                  << " contained no usable peers; falling back to bootstrap list.\n";
    }
  }

  bool connected = false;
  bool manualAdded = false;
  for (const auto &entry : manualPeers) {
    if (!isNumericAddress(entry.host))
      continue;
    if (isSelfEndpoint(entry.host, entry.port)) {
      recordSelfEndpoint(entry.host, entry.port);
      continue;
    }
    if (entry.host == "127.0.0.1" || entry.host == "localhost")
      continue;
    if (noteShareableEndpoint(entry.host, entry.port, false))
      manualAdded = true;
    if (connectToNode(entry.host, entry.port)) {
      connected = true;
      if (!entry.keyB64.empty()) {
        std::string decoded = Crypto::base64Decode(entry.keyB64, false);
        if (decoded.size() == 32) {
          std::lock_guard<std::timed_mutex> lk(peersMutex);
          auto it = std::find_if(peerTransports.begin(), peerTransports.end(),
                                 [&](const auto &kv) {
                                   return kv.second.ip == entry.host;
                                 });
          if (it != peerTransports.end() && it->second.state)
            std::copy(decoded.begin(), decoded.end(),
                      it->second.state->linkKey.begin());
        }
      }
    }
  }

  if (manualAdded)
    broadcastPeerList();

  if (!connected) {
    auto bootstrap = gatherBootstrapPeers();
    if (!bootstrap.empty())
      std::cout << "ℹ️  [loadPeers] Using bootstrap peer list.\n";
    bool added = false;
    for (const auto &entry : bootstrap) {
      if (!isNumericAddress(entry.host))
        continue;
      if (isSelfEndpoint(entry.host, entry.port)) {
        recordSelfEndpoint(entry.host, entry.port);
        continue;
      }
      if (entry.host == "127.0.0.1" || entry.host == "localhost")
        continue;
      if (noteShareableEndpoint(entry.host, entry.port, false))
        added = true;
      if (connectToNode(entry.host, entry.port)) {
        connected = true;
        rememberPeerEndpoint(entry.host, entry.port);
      }
    }
    if (added)
      broadcastPeerList();
  }

  if (connected) {
    std::cout << "✅ [loadPeers] Peer bootstrap complete.\n";
  } else {
    std::cerr << "⚠️ [loadPeers] Unable to reach any peers from manual or bootstrap lists.\n";
  }
}

//
void Network::scanForPeers() {
  std::lock_guard<std::timed_mutex> lock(peersMutex);
  if (!peerTransports.empty()) {
    std::cout << "✅ [scanForPeers] Existing peer sockets present, skipping DNS scan.\n";
    return;
  }
  std::vector<std::string> potentialPeers =
      fetchPeersFromDNS("peers.alyncoin.com");
  std::cout << "🔍 [DNS] Scanning for AlynCoin nodes..." << std::endl;

  bool added = false;
  for (const auto &peer : potentialPeers) {
    std::string ip = peer.substr(0, peer.find(":"));
    int peerPort = std::stoi(peer.substr(peer.find(":") + 1));
    if (!isNumericAddress(ip))
      continue;
    if (isSelfEndpoint(ip, peerPort)) {
      recordSelfEndpoint(ip, peerPort);
      continue;
    }
    if (ip == "127.0.0.1" || ip == "localhost")
      continue;
    if (noteShareableEndpoint(ip, peerPort, false))
      added = true;
    connectToNode(ip, peerPort);
  }
  if (added)
    broadcastPeerList();
  if (peerTransports.empty()) {
    std::cout << "⚠️ No active peers found from DNS. Will retry if needed.\n";
  }
}

// ✅ **Ensure Peers are Saved Correctly & Safely**
void Network::savePeers() {
  std::lock_guard<std::mutex> lock(fileIOMutex); // 🔒 File IO Mutex lock

  // Optional: Backup current peers.txt before overwrite
  const auto path = peersFilePath();
  const auto backup = peersBackupPath();
  if (fs::exists(path)) {
    try {
      fs::copy_file(path, backup,
                    fs::copy_options::overwrite_existing);
      std::cout << "📋 Backup of peers.txt created at " << backup << "\n";
    } catch (const std::exception &e) {
      std::cerr << "⚠️ Warning: Failed to backup peers.txt: " << e.what()
                << "\n";
    }
  }

  std::ofstream file(path, std::ios::trunc);
  if (!file.is_open()) {
    std::cerr << "❌ Error: Unable to open " << path << " for saving!"
              << std::endl;
    return;
  }

  for (const auto &[peerId, entry] : peerTransports) {
    if (!entry.state)
      continue;
    auto endpoint = selectReachableEndpoint(entry);
    if (endpoint.first.empty() || endpoint.second <= 0)
      continue;
    if (!isShareableAddress(endpoint.first))
      continue;
    if (isBlockedServicePort(endpoint.second))
      continue;
    if (isSelfEndpoint(endpoint.first, endpoint.second))
      continue;
    file << endpoint.first << ':' << endpoint.second << std::endl;
  }

  file.close();
  std::cout << "✅ Peer list saved successfully. Total peers: "
            << peerTransports.size() << std::endl;
}

bool Network::noteShareableEndpoint(const std::string &host, int port,
                                    bool triggerBroadcast, bool markVerified,
                                    const std::string &originPeer) {
  if (host.empty() || port <= 0 || port > 65535)
    return false;
  if (isBlockedServicePort(port))
    return false;
  if (!isShareableAddress(host))
    return false;

  const std::string label = makeEndpointLabel(host, port);
  auto now = std::chrono::steady_clock::now();
  bool inserted = false;
  bool promoted = false;
  {
    std::lock_guard<std::mutex> gossipLock(gossipMutex);
    auto it = knownPeerEndpoints.find(label);
    if (it == knownPeerEndpoints.end()) {
      if (!ensureEndpointCapacityLocked(markVerified))
        return false;
      EndpointRecord rec;
      rec.host = host;
      rec.port = port;
      rec.lastSeen = now;
      rec.lastOrigin = originPeer;
      if (markVerified) {
        rec.verified = true;
        rec.successCount = 1;
        rec.lastSuccess = now;
        rec.failureCount = 0;
        rec.nextDialAllowed = now;
        promoted = true;
      }
      knownPeerEndpoints.emplace(label, std::move(rec));
      inserted = true;
    } else {
      auto &rec = it->second;
      rec.lastSeen = now;
      if (!originPeer.empty())
        rec.lastOrigin = originPeer;
      if (markVerified) {
        if (!rec.verified)
          promoted = true;
        rec.verified = true;
        rec.successCount = std::max(rec.successCount + 1, 1);
        rec.failureCount = 0;
        rec.lastSuccess = now;
        rec.nextDialAllowed = now;
      }
    }
  }

  if (triggerBroadcast && (inserted || promoted)) {
    if (!originPeer.empty())
      broadcastPeerList(originPeer);
    else
      broadcastPeerList();
  }

  return inserted || promoted;
}

bool Network::ensureEndpointCapacityLocked(bool incomingVerified) {
  auto dropOldestUnverified = [this]() -> bool {
    auto victim = knownPeerEndpoints.end();
    auto oldest = std::chrono::steady_clock::time_point::max();
    for (auto it = knownPeerEndpoints.begin(); it != knownPeerEndpoints.end();
         ++it) {
      const auto &rec = it->second;
      if (rec.verified)
        continue;
      if (!rec.lastOrigin.empty() && anchorPeers.count(rec.lastOrigin))
        continue;
      if (rec.lastSeen < oldest) {
        oldest = rec.lastSeen;
        victim = it;
      }
    }
    if (victim == knownPeerEndpoints.end())
      return false;
    knownPeerEndpoints.erase(victim);
    return true;
  };

  size_t unverifiedCount = 0;
  for (const auto &kv : knownPeerEndpoints) {
    if (!kv.second.verified)
      ++unverifiedCount;
  }

  if (!incomingVerified) {
    while (unverifiedCount >= MAX_UNVERIFIED_ENDPOINTS) {
      if (!dropOldestUnverified())
        break;
      --unverifiedCount;
    }
    if (unverifiedCount >= MAX_UNVERIFIED_ENDPOINTS)
      return false;
  }

  while (knownPeerEndpoints.size() >= MAX_TRACKED_ENDPOINTS) {
    if (dropOldestUnverified()) {
      if (unverifiedCount > 0)
        --unverifiedCount;
      continue;
    }
    if (!incomingVerified)
      return false;
    auto victim = knownPeerEndpoints.end();
    auto oldest = std::chrono::steady_clock::time_point::max();
    for (auto it = knownPeerEndpoints.begin(); it != knownPeerEndpoints.end();
         ++it) {
      if (!it->second.lastOrigin.empty() &&
          anchorPeers.count(it->second.lastOrigin))
        continue;
      if (it->second.lastSeen < oldest) {
        oldest = it->second.lastSeen;
        victim = it;
      }
    }
    if (victim == knownPeerEndpoints.end())
      return false;
    knownPeerEndpoints.erase(victim);
  }

  return true;
}

void Network::rememberPeerEndpoint(const std::string &ip, int port) {
  if (ip == "127.0.0.1" || ip == "localhost")
    return;
  if (isSelfEndpoint(ip, port)) {
    recordSelfEndpoint(ip, port);
    return;
  }

  std::string endpoint = ip + ":" + std::to_string(port);
  const auto path = peersFilePath();
  std::lock_guard<std::mutex> lock(fileIOMutex);

  {
    std::ifstream file(path);
    if (file.is_open()) {
      std::string line;
      while (std::getline(file, line)) {
        auto parsed = parsePeerFileEntry(line);
        if (parsed && parsed->host == ip && parsed->port == port)
          return; // Already persisted
      }
    }
  }

  std::ofstream out(path, std::ios::app);
  if (!out.is_open()) {
    std::cerr << "⚠️ [peers.txt] Unable to append peer " << endpoint
              << " to " << path << "\n";
    return;
  }
  out << endpoint << std::endl;
  std::cout << "📝 [peers.txt] Remembering peer " << endpoint << " in " << path
            << std::endl;
  noteShareableEndpoint(ip, port, false);
}

void Network::recordEndpointFailure(const std::string &host, int port) {
  if (host.empty() || port <= 0)
    return;
  const std::string label = makeEndpointLabel(host, port);
  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> gossipLock(gossipMutex);
  auto &rec = knownPeerEndpoints[label];
  if (rec.host.empty())
    rec.host = host;
  if (rec.port == 0)
    rec.port = port;
  rec.lastSeen = now;
  rec.failureCount = std::min(rec.failureCount + 1, 16);
  rec.nextDialAllowed = now + computeDialBackoff(rec.failureCount);
  if (rec.failureCount >= 3)
    rec.verified = false;
}

void Network::refreshLocalInterfaces() { refreshLocalInterfaceCache(); }

void Network::setExternalAddress(const std::string &host, int port) {
  if (host.empty() || port <= 0)
    return;
  std::string lowered = toLowerCopy(host);
  {
    std::lock_guard<std::mutex> lock(selfFilterMutex);
    manualSelfAddrs.insert(lowered);
    manualSelfAddrs.insert(host);
    manualSelfEndpoints.insert(makeEndpointLabel(lowered, port));
    manualSelfEndpoints.insert(makeEndpointLabel(host, port));
  }
  recordSelfEndpoint(host, port);
}

bool Network::isSelfNodeId(const std::string &peerId) const {
  if (peerId.empty())
    return false;
  if (peerId == nodeId)
    return true;
  if (!publicPeerId.empty() && peerId == publicPeerId)
    return true;
  return false;
}

bool Network::isSelfNonce(uint64_t nonce) const {
  return nonce != 0 && nonce == localHandshakeNonce;
}

void Network::recordSelfEndpoint(const std::string &host, int port) {
  if (host.empty() || port <= 0)
    return;

  std::string lowered = toLowerCopy(host);
  std::lock_guard<std::mutex> lock(selfFilterMutex);
  selfObservedAddrs.insert(lowered);
  selfObservedAddrs.insert(host);
  selfObservedEndpoints.insert(makeEndpointLabel(lowered, port));
  selfObservedEndpoints.insert(makeEndpointLabel(host, port));
}

void Network::refreshLocalInterfaceCache() {
  std::unordered_set<std::string> discovered;

#ifndef _WIN32
  struct ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) == 0) {
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (!ifa->ifa_addr)
        continue;
      int family = ifa->ifa_addr->sa_family;
      if (family != AF_INET && family != AF_INET6)
        continue;
      char hostBuf[NI_MAXHOST];
      if (getnameinfo(ifa->ifa_addr,
                      family == AF_INET ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6),
                      hostBuf, sizeof(hostBuf), nullptr, 0, NI_NUMERICHOST) ==
          0) {
        discovered.insert(toLowerCopy(hostBuf));
      }
    }
  }
  if (ifaddr)
    freeifaddrs(ifaddr);
#else
  WSADATA wsaData;
  bool wsaReady = WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
  char hostName[256];
  if (gethostname(hostName, sizeof(hostName)) == 0) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *info = nullptr;
    if (getaddrinfo(hostName, nullptr, &hints, &info) == 0) {
      for (addrinfo *p = info; p != nullptr; p = p->ai_next) {
        char buf[NI_MAXHOST];
        if (getnameinfo(p->ai_addr, static_cast<socklen_t>(p->ai_addrlen), buf,
                        sizeof(buf), nullptr, 0, NI_NUMERICHOST) == 0) {
          discovered.insert(toLowerCopy(buf));
        }
      }
      freeaddrinfo(info);
    }
  }
  if (wsaReady)
    WSACleanup();
#endif

  discovered.insert("127.0.0.1");
  discovered.insert("localhost");
  discovered.insert("::1");

  std::lock_guard<std::mutex> lock(selfFilterMutex);
  localInterfaceAddrs = std::move(discovered);
}

bool Network::shouldServeHeavyData(const std::string &peerId,
                                   int remoteHeightHint) {
  if (peerId.empty())
    return false;

  if (isSelfPeer(peerId))
    return false;

  auto snapshot = getPeerSnapshot(peerId);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return false;

  auto state = snapshot.state;
  if (!state)
    return false;

  if (!state->handshakeComplete)
    return false;

  std::string host;
  int portValue = 0;
  {
    std::lock_guard<std::timed_mutex> lk(peersMutex);
    auto it = peerTransports.find(peerId);
    if (it != peerTransports.end()) {
      host = !it->second.observedIp.empty() ? it->second.observedIp
                                            : it->second.ip;
      portValue = it->second.observedPort > 0 ? it->second.observedPort
                                              : it->second.port;
    }
  }

  if (!host.empty() && portValue > 0 && isSelfEndpoint(host, portValue)) {
    recordSelfEndpoint(host, portValue);
    return false;
  }

  const int localHeight = Blockchain::getInstance().getHeight();
  int remoteHeight = remoteHeightHint;
  if (remoteHeight < 0 && peerManager)
    remoteHeight = peerManager->getPeerHeight(peerId);

  bool heightBehind = false;
  if (remoteHeight >= 0)
    heightBehind = remoteHeight < localHeight;

  uint64_t localWork = 0;
  uint64_t remoteWork = 0;
  if (peerManager) {
    localWork = peerManager->getLocalWork();
    remoteWork = peerManager->getPeerWork(peerId);
  }

  bool workBehind = remoteWork < localWork;

  if (!heightBehind) {
    if (remoteHeight >= localHeight && localHeight >= 0 && !workBehind)
      return false;
    if (remoteHeight < 0 && localWork > 0 && !workBehind)
      return false;
  }

  return true;
}

void Network::beginHeaderBridge(const std::string &peer) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  auto ps = snapshot.state;

  const auto &chain = Blockchain::getInstance().getChain();
  if (chain.empty())
    return;

  int localHeight = static_cast<int>(chain.size()) - 1;
  std::vector<int> targets;
  targets.reserve(10);
  targets.push_back(localHeight);
  static const std::array<int, 7> kWindows{32, 64, 128, 256, 512, 1024, 2048};
  for (int depth : kWindows) {
    int target = std::max(0, localHeight - depth);
    targets.push_back(target);
  }

  if (ps->headerBestCommonHeight >= 0 &&
      localHeight - ps->headerBestCommonHeight > 1) {
    int mid = ps->headerBestCommonHeight +
              (localHeight - ps->headerBestCommonHeight) / 2;
    if (mid > ps->headerBestCommonHeight)
      targets.push_back(mid);
  }

  std::vector<std::string> anchors;
  anchors.reserve(targets.size());
  {
    std::lock_guard<std::mutex> lk(ps->m);
    if (ps->headerBridgeActive && !ps->headerAnchorsRequested.empty())
      return;
    ps->headerBridgeActive = true;
    for (int targetHeight : targets) {
      if (targetHeight < 0 || targetHeight >= static_cast<int>(chain.size()))
        continue;
      const std::string &hash =
          chain[static_cast<size_t>(targetHeight)].getHash();
      if (ps->headerAnchorsRequested.insert(hash).second)
        anchors.push_back(hash);
    }
  }

  if (anchors.empty()) {
    std::lock_guard<std::mutex> lk(ps->m);
    if (ps->headerAnchorsRequested.empty())
      ps->headerBridgeActive = false;
    return;
  }

  for (const auto &hash : anchors)
    HeadersSync::requestHeaders(peer, hash);
}

void Network::handleHeaderResponse(
    const std::string &peer,
    const std::vector<HeadersSync::HeaderRecord> &headers) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  auto ps = snapshot.state;

  const auto &chain = Blockchain::getInstance().getChain();
  if (chain.empty())
    return;

  int localHeight = static_cast<int>(chain.size()) - 1;
  int bestHeight = ps->headerBestCommonHeight;
  std::string bestHash = ps->headerBestCommonHash;
  bool divergenceDetected = false;

  if (!headers.empty()) {
    const std::string &anchorHash = headers.front().previousHash;
    if (!anchorHash.empty()) {
      std::lock_guard<std::mutex> lk(ps->m);
      ps->headerAnchorsRequested.erase(anchorHash);
    }
  }

  for (const auto &hdr : headers) {
    const std::string &hash = hdr.hash;
    Block local{};
    if (Blockchain::getInstance().getBlockByHash(hash, local)) {
      int idx = local.getIndex();
      if (idx > bestHeight) {
        bestHeight = idx;
        bestHash = local.getHash();
      }
      continue;
    }
    const std::string &prev = hdr.previousHash;
    Block prevLocal{};
    if (Blockchain::getInstance().getBlockByHash(prev, prevLocal)) {
      int idx = prevLocal.getIndex();
      if (idx > bestHeight) {
        bestHeight = idx;
        bestHash = prevLocal.getHash();
      }
      divergenceDetected = true;
    }
  }

  if (bestHeight > ps->headerBestCommonHeight && !bestHash.empty()) {
    {
      std::lock_guard<std::mutex> lk(ps->m);
      ps->headerBestCommonHeight = bestHeight;
      ps->headerBestCommonHash = bestHash;
    }
    if (peerManager)
      peerManager->recordCommonAncestor(peer, bestHash, bestHeight);
  }

  if (divergenceDetected && bestHeight >= 0 &&
      bestHeight < static_cast<int>(chain.size())) {
    const std::string &anchor = chain[static_cast<size_t>(bestHeight)].getHash();
    requestTailBlocks(peer, bestHeight, anchor);
    {
      std::lock_guard<std::mutex> lk(ps->m);
      ps->headerBridgeActive = false;
      ps->headerAnchorsRequested.clear();
      ps->headerLastBinaryProbe = -1;
    }
  }

  if (bestHeight >= 0 && localHeight - bestHeight > 1) {
    int mid = bestHeight + (localHeight - bestHeight) / 2;
    if (mid > bestHeight && mid < localHeight) {
      std::string midHash = chain[static_cast<size_t>(mid)].getHash();
      bool shouldRequest = false;
      {
        std::lock_guard<std::mutex> lk(ps->m);
        if (ps->headerAnchorsRequested.insert(midHash).second) {
          shouldRequest = true;
          ps->headerLastBinaryProbe = mid;
        }
      }
      if (shouldRequest)
        HeadersSync::requestHeaders(peer, midHash);
    }
  }

  {
    std::lock_guard<std::mutex> lk(ps->m);
    if (ps->headerAnchorsRequested.empty() && !divergenceDetected)
      ps->headerBridgeActive = false;
  }
}

// ✅ **Broadcast Latest Block Correctly (Base64 Encoded)**
void Network::sendLatestBlock(const std::string &peerIP) {
  Blockchain &blockchain = Blockchain::getInstance();
  if (blockchain.getChain().empty())
    return;
  Block latestBlock = blockchain.getLatestBlock();
  noteBlockRequested(peerIP, latestBlock.getHash());
  sendBlockToPeer(peerIP, latestBlock, true);
}

void Network::sendInventory(const std::string &peer) {
  Blockchain &bc = Blockchain::getInstance();
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  uint32_t start = 0;
  if (snapshot.state)
    start = snapshot.state->highestSeen + 1;
  const auto &chain = bc.getChain();
  for (size_t i = start; i < chain.size(); i += MAX_INV_PER_MSG) {
    alyncoin::net::Frame fr;
    auto *inv = fr.mutable_inv();
    for (size_t j = i; j < chain.size() && j < i + MAX_INV_PER_MSG; ++j)
      inv->add_hashes(chain[j].getHash());
    sendFrame(snapshot.transport, fr);
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
  // Leaving reconnection decisions to manual discovery avoids inflating the
  // reported peer count when the network is limited by external routing.
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
  if (auto snapshot = getPeerSnapshot(peerId); snapshot.state)
    return snapshot.state->supportsAggProof;
  return false;
}
//
bool Network::peerSupportsSnapshot(const std::string &peerId) const {
  if (auto snapshot = getPeerSnapshot(peerId); snapshot.state)
    return snapshot.state->supportsSnapshot;
  return false;
}

bool Network::peerSupportsWhisper(const std::string &peerId) const {
  if (auto snapshot = getPeerSnapshot(peerId); snapshot.state)
    return snapshot.state->supportsWhisper;
  return false;
}

bool Network::peerSupportsTls(const std::string &peerId) const {
  if (auto snapshot = getPeerSnapshot(peerId); snapshot.state)
    return snapshot.state->supportsTls;
  return false;
}
//
void Network::sendSnapshot(const std::string &peerId,
                           std::shared_ptr<Transport> transport,
                           int upToHeight, size_t preferredChunk) {
  if (!transport || !transport->isOpen())
    return;

  auto ps = getPeerSnapshot(peerId).state;

  if (!shouldServeHeavyData(peerId, upToHeight)) {
    std::cerr << "⚠️ [Snapshot] Skipping serve to " << peerId
              << " (endpoint not eligible)\n";
    return;
  }

  if (preferredChunk == 0 && ps)
    preferredChunk = ps->snapshotChunkPreference;

  const auto now = std::chrono::steady_clock::now();
  if (ps) {
    if (ps->snapshotServing) {
      std::cerr << "⚠️ [Snapshot] Ignoring duplicate request from " << peerId
                << " (snapshot already in flight)\n";
      return;
    }
    if (ps->lastSnapshotServed != std::chrono::steady_clock::time_point{} &&
        now - ps->lastSnapshotServed < SNAPSHOT_RESEND_COOLDOWN) {
      std::cerr << "⚠️ [Snapshot] Request from " << peerId
                << " throttled – last snapshot sent "
                << std::chrono::duration_cast<std::chrono::seconds>(
                       now - ps->lastSnapshotServed)
                       .count()
                << "s ago\n";
      return;
    }
    ps->snapshotServing = true;
  }

  bool completed = false;
  auto previousLast = ps ? ps->lastSnapshotServed
                         : std::chrono::steady_clock::time_point{};
  struct SnapshotGuard {
    std::shared_ptr<PeerState> state;
    std::chrono::steady_clock::time_point prev;
    bool &done;
    SnapshotGuard(std::shared_ptr<PeerState> st,
                  std::chrono::steady_clock::time_point p, bool &d)
        : state(std::move(st)), prev(p), done(d) {}
    ~SnapshotGuard() {
      if (!state)
        return;
      state->snapshotServing = false;
      if (!done)
        state->lastSnapshotServed = prev;
    }
  } guard(ps, previousLast, completed);

  Blockchain &bc = Blockchain::getInstance();
  int height = upToHeight < 0 ? bc.getHeight() : upToHeight;
  if (height > bc.getHeight())
    height = bc.getHeight();
  if (height < 0)
    height = 0;
  int start =
      height >= MAX_SNAPSHOT_BLOCKS ? height - MAX_SNAPSHOT_BLOCKS + 1 : 0;
  if (ps && ps->frameRev != kFrameRevision) {
    if (ps->frameRev == 0)
      std::cerr << "ℹ️  [Snapshot] Peer " << peerId
                << " uses legacy frame_rev=0; using block_batch fallback.\n";
    else
      std::cerr << "⚠️ [Snapshot] Peer " << peerId
                << " advertises frame_rev=" << ps->frameRev
                << "; using block_batch fallback.\n";
    if (sendLegacySnapshot(peerId, transport, height)) {
      if (ps)
        ps->lastSnapshotServed = std::chrono::steady_clock::now();
      completed = true;
    }
    return;
  }
  std::vector<Block> blocks = bc.getChainSlice(start, height);
  SnapshotProto snap;
  snap.set_height(height);
  snap.set_merkle_root(bc.getHeaderMerkleRoot());
  for (const auto &blk : blocks)
    *snap.add_blocks() = blk.toProtobuf();

  std::string raw;
  if (!snap.SerializeToString(&raw))
    return;

  const size_t CHUNK_SIZE = resolveSnapshotChunkSize(preferredChunk);
  // --- Send metadata first ---
  alyncoin::net::Frame meta;
  meta.mutable_snapshot_meta()->set_height(height);
  meta.mutable_snapshot_meta()->set_root_hash(bc.getHeaderMerkleRoot());
  meta.mutable_snapshot_meta()->set_total_bytes(raw.size());
  meta.mutable_snapshot_meta()->set_chunk_size(
      static_cast<uint32_t>(CHUNK_SIZE));
  if (!sendFrame(transport, meta)) {
    std::cerr << "❌ [Snapshot] Failed to queue metadata for " << peerId
              << '\n';
    return;
  }

  // --- Stream snapshot in bounded chunks ---
  uint32_t seq = 0;
  for (size_t off = 0; off < raw.size(); off += CHUNK_SIZE) {
    size_t len = std::min(CHUNK_SIZE, raw.size() - off);
    alyncoin::net::Frame fr;
    fr.mutable_snapshot_chunk()->set_data(raw.substr(off, len));
    if (!sendFrame(transport, fr)) {
      std::cerr << "❌ [Snapshot] Failed to queue chunk " << seq
                << " for peer " << peerId << '\n';
      return;
    }
    ++seq;
  }
  alyncoin::net::Frame end;
  end.mutable_snapshot_end();
  if (!sendFrame(transport, end)) {
    std::cerr << "❌ [Snapshot] Failed to queue completion signal for "
              << peerId << '\n';
    return;
  }

  if (ps)
    ps->lastSnapshotServed = std::chrono::steady_clock::now();
  completed = true;
}
//

void Network::sendTailBlocks(std::shared_ptr<Transport> transport,
                             int fromHeight, const std::string &peerId) {
  if (!transport || !transport->isOpen())
    return;

  if (!shouldServeHeavyData(peerId, fromHeight)) {
    std::cerr << "⚠️ [Tail] Skipping serve to " << peerId
              << " (endpoint not eligible)\n";
    return;
  }

  Blockchain &bc = Blockchain::getInstance();
  const int myHeight = bc.getHeight();
  if (fromHeight < 0 || fromHeight >= myHeight)
    return;
  auto it = peerTransports.find(peerId);
  if (it == peerTransports.end() || !it->second.state)
    return;
  auto ps = it->second.state;
  int effectiveFrom = fromHeight;
  if (effectiveFrom < ps->lastTailHeight)
    effectiveFrom = ps->lastTailHeight;
  if (effectiveFrom >= myHeight) {
    std::cerr << "[sendTailBlocks] aborting: peer height >= local height\n";
    return;
  }

  constexpr std::size_t MSG_LIMIT = MAX_TAIL_PAYLOAD;
  std::vector<Block> chainCopy = bc.snapshot();
  auto flushTail = [&](alyncoin::net::TailBlocks &tb) {
    if (tb.blocks_size() == 0)
      return;
    alyncoin::net::Frame f;
    *f.mutable_tail_blocks() = tb;
    sendFrame(transport, f);
  };

  auto sendRange = [&](int rangeStart, int rangeEnd, bool updateTailState) {
    if (rangeStart > rangeEnd)
      return;
    rangeStart = std::max(rangeStart, 0);
    rangeEnd = std::min(rangeEnd, static_cast<int>(chainCopy.size()) - 1);
    if (rangeStart > rangeEnd)
      return;

    alyncoin::net::TailBlocks proto;
    size_t current = 0;
    for (int i = rangeStart; i <= rangeEnd; ++i) {
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
    if (!ps)
      return;
    ps->highestSeen = std::max(ps->highestSeen, static_cast<uint32_t>(rangeEnd));
    if (updateTailState)
      ps->lastTailHeight = rangeEnd;
  };

  const int gap = myHeight - effectiveFrom;
  if (ps && !ps->sentFastCatchup && gap > FAST_SYNC_TRIGGER_GAP && myHeight > 0) {
    int previewEnd = myHeight;
    int previewStart = std::max(effectiveFrom + 1,
                                previewEnd - FAST_SYNC_RECENT_BLOCKS + 1);
    if (previewStart <= previewEnd) {
      sendRange(previewStart, previewEnd, false);
      ps->sentFastCatchup = true;
    }
  }

  const int start = effectiveFrom + 1;
  const int end =
      std::min(myHeight, start + MAX_TAIL_BLOCKS - 1);
  sendRange(start, end, true);
}

void Network::handleSnapshotMeta(const std::string &peer,
                                 const alyncoin::net::SnapshotMeta &meta) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  auto ps = snapshot.state;
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
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  auto ps = snapshot.state;
  if (chunk.empty()) {
    std::cerr << "[SNAPSHOT] empty chunk from " << peer << '\n';
    return;
  }
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
  if (snapshot.transport && snapshot.transport->isOpen())
    sendFrame(snapshot.transport, ack);
}

//
void Network::handleTailRequest(const std::string &peer, int fromHeight) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  sendTailBlocks(snapshot.transport, fromHeight, peer);
}
void Network::handleSnapshotEnd(const std::string &peer) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.state)
    return;
  auto ps = snapshot.state;
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
          peerManager->setPeerWork(peer, safeUint64(work));
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
    uint64_t localW64 = safeUint64(localWork);
    uint64_t remoteW64 = safeUint64(remoteWork);
    std::string localTipHash = chain.getLatestBlockHash();
    std::string remoteTipHash =
        snapBlocks.empty() ? "" : snapBlocks.back().getHash();
    int reorgDepth = std::max(0, localHeight - snap.height());
    int chk = chain.getCheckpointHeight();
    int maxReorg = MAX_REORG;
    if (chk > 0)
      maxReorg = std::min(maxReorg, localHeight - (chk - 2));
    bool accept = remoteTipHash != localTipHash &&
                  remoteW64 > localW64 * 1.01 && reorgDepth <= maxReorg;

    if (!accept) {
      std::cerr << "⚠️ [SNAPSHOT] Rejected snapshot from " << peer << " (height "
                << snap.height() << ", work " << remoteW64
                << ") localHeight=" << localHeight << " localWork=" << localW64
                << " reorgDepth=" << reorgDepth << "\n";
      // No penalty for an honest peer whose chain simply has less work
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
    requestTailBlocks(peer, snap.height(), chain.getLatestBlockHash());

  } catch (const std::exception &ex) {
    std::cerr << "❌ [SNAPSHOT] Failed to apply snapshot from peer " << peer
              << ": " << ex.what() << "\n";
    penalizePeer(peer, 20);
    // Do not immediately ban the peer; allow for resync attempts
    ps->snapshotActive = false;
    ps->snapshotB64.clear();
    ps->snapState = PeerState::SnapState::Idle;
  } catch (...) {
    std::cerr << "❌ [SNAPSHOT] Unknown error applying snapshot from peer "
              << peer << "\n";
    penalizePeer(peer, 20);
    // Allow the peer another chance before any ban action
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
    std::string anchor;
    if (auto state = getPeerSnapshot(peer).state)
      anchor = state->lastTailAnchor;
    if (!anchor.empty() && chain.getLatestBlockHash() != anchor) {
      requestTailBlocks(peer, chain.getHeight(), chain.getLatestBlockHash());
      return;
    }

    // Convert proto to vector of blocks
    std::vector<Block> blocks;
    blocks.reserve(proto.blocks_size());
    for (const auto &pb : proto.blocks()) {
      blocks.push_back(Block::fromProto(pb, false));
    }

    size_t pos = 0;
    const std::string localTip = chain.getLatestBlockHash();
    while (pos < blocks.size() && blocks[pos].getPreviousHash() != localTip) {
      ++pos;
    }
    if (pos == blocks.size()) {
      std::cerr << "⚠️ [TAIL_BLOCKS] No connector from peer " << peer
                << "; requesting headers to bridge gap.\n";
      beginHeaderBridge(peer);
      syncing = true;
      return;
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

    // Reset any snapshot sync state now that tail sync succeeded
    if (auto state = getPeerSnapshot(peer).state) {
      state->snapshotActive = false;
      state->snapState = PeerState::SnapState::Idle;
      state->snapshotB64.clear();
      state->snapshotReceived = 0;
      state->snapshotExpectBytes = 0;
      {
        std::lock_guard<std::mutex> lk(state->m);
        state->headerBridgeActive = false;
        state->headerAnchorsRequested.clear();
        state->headerLastBinaryProbe = -1;
      }
    }

    if (peerManager)
      peerManager->setPeerHeight(peer, chain.getHeight());
    chain.broadcastNewTip();
    syncing = false;

    if (peerManager) {
      int remoteH = peerManager->getPeerHeight(peer);
      if (remoteH > static_cast<int>(chain.getHeight()))
        requestTailBlocks(peer, chain.getHeight(), chain.getLatestBlockHash());
    }
  } catch (const std::exception &ex) {
    std::cerr << "❌ [TAIL_BLOCKS] Failed to apply tail blocks from peer "
              << peer << ": " << ex.what() << "\n";
    penalizePeer(peer, 2); // small strike, peer may simply be out of sync
    {
      Blockchain &chain = Blockchain::getInstance();
      requestTailBlocks(peer, chain.getHeight(), chain.getLatestBlockHash());
    }
    syncing = true;
  } catch (...) {
    std::cerr
        << "❌ [TAIL_BLOCKS] Unknown error applying tail blocks from peer "
        << peer << "\n";
    penalizePeer(peer, 2); // allow retry before escalating
    {
      Blockchain &chain = Blockchain::getInstance();
      requestTailBlocks(peer, chain.getHeight(), chain.getLatestBlockHash());
    }
    syncing = true;
  }
}

//
void Network::handleHeaderBatch(const std::string &peer,
                                const alyncoin::net::Headers &hdrs) {
  HeadersSync::handleHeaders(peer, hdrs);
}

//
void Network::handleBlockBatch(const std::string &peer,
                               const alyncoin::net::BlockBatch &batch) {
  Blockchain &chain = Blockchain::getInstance();
  const auto &protoChain = batch.chain();
  for (const auto &pb : protoChain.blocks()) {
    try {
      Block blk = Block::fromProto(pb, false);
      chain.addBlock(blk);
    } catch (const std::exception &ex) {
      std::cerr << "⚠️  [BlockBatch] Failed to add block from peer " << peer
                << ": " << ex.what() << "\n";
    }
  }
  chain.broadcastNewTip();
}

//
void Network::requestSnapshotSync(const std::string &peer) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  auto ps = snapshot.state;
  if (ps) {
    ps->snapState = PeerState::SnapState::WaitMeta;
    ps->snapshotB64.clear();
    ps->snapshotReceived = 0;
    ps->snapshotExpectBytes = 0;
  }
  alyncoin::net::Frame fr;
  fr.mutable_snapshot_req();
  sendFrame(snapshot.transport, fr);
}

void Network::requestTailBlocks(const std::string &peer, int fromHeight,
                                const std::string &anchorHash) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  alyncoin::net::Frame fr;
  auto *req = fr.mutable_tail_req();
  req->set_from_height(fromHeight);
  req->set_anchor_hash(anchorHash);
  if (snapshot.state)
    snapshot.state->lastTailAnchor = anchorHash;
  sendFrame(snapshot.transport, fr);
}

void Network::requestBlockByHash(const std::string &peer,
                                 const std::string &hash) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  alyncoin::net::Frame fr;
  fr.mutable_get_data()->add_hashes(hash);
  sendFrame(snapshot.transport, fr);
}
//
void Network::sendForkRecoveryRequest(const std::string &peer,
                                      const std::string &tip) {
  auto snapshot = getPeerSnapshot(peer);
  if (!snapshot.transport || !snapshot.transport->isOpen())
    return;
  alyncoin::net::Frame fr;
  if (!tip.empty())
    fr.mutable_snapshot_req()->set_until_hash(tip);
  else
    fr.mutable_snapshot_req();
  sendFrame(snapshot.transport, fr);
}

bool Network::sendLegacySnapshot(const std::string &peerId,
                                 std::shared_ptr<Transport> transport,
                                 int upToHeight) {
  if (!transport || !transport->isOpen())
    return false;

  Blockchain &bc = Blockchain::getInstance();
  int height = upToHeight < 0 ? bc.getHeight() : upToHeight;
  if (height > bc.getHeight())
    height = bc.getHeight();
  if (height < 0)
    height = 0;

  int start =
      height >= MAX_SNAPSHOT_BLOCKS ? height - MAX_SNAPSHOT_BLOCKS + 1 : 0;
  std::vector<Block> blocks = bc.getChainSlice(start, height);
  if (blocks.empty()) {
    std::cerr << "⚠️ [SnapshotLegacy] No blocks to stream to " << peerId << '\n';
    return false;
  }

  constexpr std::size_t LEGACY_BATCH_LIMIT = MAX_WIRE_PAYLOAD - 4096;
  alyncoin::net::BlockBatch batch;
  auto *chainProto = batch.mutable_chain();
  chainProto->clear_blocks();
  std::size_t currentBytes = 0;
  auto flush = [&]() -> bool {
    if (chainProto->blocks_size() == 0)
      return true;
    alyncoin::net::Frame fr;
    *fr.mutable_block_batch() = batch;
    if (!sendFrame(transport, fr)) {
      std::cerr << "❌ [SnapshotLegacy] Failed to queue block batch for "
                << peerId << '\n';
      return false;
    }
    chainProto->clear_blocks();
    currentBytes = 0;
    return true;
  };

  std::size_t streamed = 0;
  for (const auto &blk : blocks) {
    alyncoin::BlockProto proto = blk.toProtobuf();
    const std::size_t blockBytes = proto.ByteSizeLong();
    if (blockBytes > MAX_WIRE_PAYLOAD) {
      std::cerr << "⚠️ [SnapshotLegacy] Block " << blk.getIndex()
                << " too large for legacy frame (" << blockBytes << " bytes)\n";
      continue;
    }
    if (currentBytes && currentBytes + blockBytes > LEGACY_BATCH_LIMIT) {
      if (!flush())
        return false;
    }
    *chainProto->add_blocks() = std::move(proto);
    currentBytes += blockBytes;
    ++streamed;
  }

  if (!flush())
    return false;

  std::cerr << "ℹ️  [SnapshotLegacy] Streamed " << streamed
            << " blocks to " << peerId << '\n';
  return true;
}

void Network::handleBlockchainSyncRequest(
    const std::string &peer, const alyncoin::BlockchainSyncProto &request) {
  std::cout << "📡 [SYNC REQUEST] Received from " << peer
            << " type: " << request.request_type() << "\n";

  if (request.request_type() == "snapshot") {
    auto it = peerTransports.find(peer);
    if (it != peerTransports.end() && it->second.tx) {
      size_t preferred =
          it->second.state ? it->second.state->snapshotChunkPreference : 0;
      sendSnapshot(peer, it->second.tx, -1, preferred);
    }
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
