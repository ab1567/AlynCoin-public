#include "transport/tcp_transport.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <deque>
#include <mutex>
#include <iostream>
#include <cstring>

TcpTransport::TcpTransport(boost::asio::io_context& ctx)
    : socket(std::make_shared<boost::asio::ip::tcp::socket>(ctx)) {}

TcpTransport::TcpTransport(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    : socket(std::move(sock)) {}

std::string TcpTransport::remoteId() const
{
    try {
        auto ep = socket->remote_endpoint();
        return ep.address().to_string() + ':' + std::to_string(ep.port());
    } catch (...) {
        return "unknown";
    }
}

bool TcpTransport::isOpen() const
{
    return socket && socket->is_open();
}

bool TcpTransport::write(const std::string& data)
{
    if (!isOpen()) return false;
    try {
        std::string msg = data;
        if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
        boost::asio::write(*socket, boost::asio::buffer(msg));
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[TcpTransport::write] " << ex.what() << '\n';
        return false;
    }
}

// === BINARY WRITE: 4-byte length + raw payload ===
bool TcpTransport::writeBinary(const std::string& data)
{
    if (!isOpen()) return false;
    try {
        uint32_t len = static_cast<uint32_t>(data.size());
        uint32_t net_len = htonl(len); // network byte order (big-endian)
        std::vector<boost::asio::const_buffer> buffers;
        buffers.push_back(boost::asio::buffer(&net_len, sizeof(net_len)));
        if (!data.empty())
            buffers.push_back(boost::asio::buffer(data));
        boost::asio::write(*socket, buffers);
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[TcpTransport::writeBinary] " << ex.what() << '\n';
        return false;
    }
}

// === BINARY READ: blocking, returns string, empty if fail ===
std::string TcpTransport::readBinaryBlocking()
{
    if (!isOpen()) return {};
    try {
        uint32_t net_len = 0;
        size_t read1 = boost::asio::read(*socket, boost::asio::buffer(&net_len, sizeof(net_len)));
        if (read1 != sizeof(net_len))
            return {};
        uint32_t len = ntohl(net_len);
        if (len == 0 || len > 32 * 1024 * 1024) // 32MB sanity
            return {};
        std::string buf(len, '\0');
        size_t total = 0;
        while (total < len) {
            size_t got = boost::asio::read(*socket, boost::asio::buffer(&buf[total], len - total));
            if (got == 0) return {};
            total += got;
        }
        return buf;
    } catch (const std::exception& ex) {
        std::cerr << "[TcpTransport::readBinaryBlocking] " << ex.what() << '\n';
        return {};
    }
}

// --- existing helpers, unchanged ---

bool TcpTransport::connect(const std::string& host, int port)
{
    try {
        boost::asio::ip::tcp::resolver res(socket->get_executor());
        auto eps = res.resolve(host, std::to_string(port));
        boost::asio::connect(*socket, eps);
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[TcpTransport::connect] " << ex.what() << '\n';
        return false;
    }
}

std::string TcpTransport::getRemoteIP() const
{
    try { return socket->remote_endpoint().address().to_string(); }
    catch (...) { return {}; }
}

int TcpTransport::getRemotePort() const
{
    try { return static_cast<int>(socket->remote_endpoint().port()); }
    catch (...) { return 0; }
}

std::string TcpTransport::readLineBlocking()
{
    boost::asio::streambuf buf;
    boost::asio::read_until(*socket, buf, '\n');
    std::istream is(&buf);
    std::string  line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

std::string TcpTransport::readLineWithTimeout(int /*seconds*/)
{
    return readLineBlocking();
}

void TcpTransport::startReadLoop(std::function<void(const std::string&)> onLine)
{
    asyncReadLine(
        [self = shared_from_this(), onLine = std::move(onLine)]
        (const boost::system::error_code& ec, const std::string& line)
        {
            if (ec || line.empty()) return;
            onLine(line);
            self->startReadLoop(onLine);
        });
}

void TcpTransport::asyncReadLine(
    std::function<void(const boost::system::error_code&, const std::string&)> cb)
{
    // Allocate a generous streambuf so very large single-line messages
    // (such as FULL_CHAIN sync responses) don't hit the default ~65k limit.
    auto buf  = std::make_shared<boost::asio::streambuf>(4 * 1024 * 1024);
    auto self = shared_from_this();

    boost::asio::async_read_until(*socket, *buf, '\n',
        [self, buf, cb = std::move(cb)]
        (const boost::system::error_code& ec, std::size_t) mutable
        {
            std::string line;
            if (!ec) {
                std::istream is(buf.get());
                std::getline(is, line);
                if (!line.empty() && line.back() == '\r') line.pop_back();
            }
            cb(ec, line);
        });
}

// ---- Async queue write implementation ----
void TcpTransport::queueWrite(const std::string& data)
{
    std::lock_guard<std::mutex> lock(writeMutex);
    writeQueue.push_back(data);
    if (!writeInProgress)
        doWrite();
}

void TcpTransport::doWrite()
{
    if (writeQueue.empty() || !isOpen()) {
        writeInProgress = false;
        return;
    }
    writeInProgress = true;
    auto self = shared_from_this();
    std::string msg = writeQueue.front();
    if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    boost::asio::async_write(*socket, boost::asio::buffer(msg),
        [this, self](const boost::system::error_code& ec, std::size_t) {
            std::lock_guard<std::mutex> lock(writeMutex);
            if (!writeQueue.empty()) writeQueue.pop_front();
            if (!ec)
                doWrite();
            else
                writeInProgress = false;
        });
}
