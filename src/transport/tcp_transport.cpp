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
#include <thread>
#include <chrono>
#include <sys/select.h>
#include "wire/varint.h"

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

void TcpTransport::close()
{
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->close(ec);
    }
}

void TcpTransport::closeGraceful()
{
    if (socket && socket->is_open()) {
        boost::system::error_code ec;
        socket->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        socket->close(ec);
    }
}

bool TcpTransport::write(const std::string& data)
{
    if (!isOpen()) return false;
    std::string msg = data;
    if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    boost::system::error_code ec;
    boost::asio::write(*socket, boost::asio::buffer(msg), ec);
    if (ec) {
        std::cerr << "[TcpTransport::write] " << ec.message() << '\n';
        close();
        return false;
    }
    return true;
}

// === BINARY WRITE: raw protobuf frame ===
bool TcpTransport::writeBinary(const std::string& data)
{
    std::lock_guard<std::mutex> lock(writeMutex);
    return writeBinaryLocked(data);
}

bool TcpTransport::writeBinaryLocked(const std::string& data)
{
    if (!isOpen()) return false;
    boost::system::error_code ec;
    boost::asio::write(*socket, boost::asio::buffer(data), ec);
    if (ec) {
        std::cerr << "[TcpTransport] ❌ Write binary failed: " << ec.message() << '\n';
        close();
        return false;
    }
    return true;
}

// === BINARY READ: blocking, returns string, empty if fail ===
std::string TcpTransport::readBinaryBlocking()
{
    if (!isOpen()) return {};
    try {
        uint64_t need = 0;
        if (!readVarIntBlocking(*socket, need))
            return {};
        if (need == 0 || need > 32 * 1024 * 1024)
            return {};
        std::string buf(need, '\0');
        boost::asio::read(*socket, boost::asio::buffer(buf));
        return buf;            // protobuf-ready
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

bool TcpTransport::waitReadable(int seconds)
{
    if (!isOpen()) return false;
    int fd = socket->native_handle();
    fd_set rfd; FD_ZERO(&rfd); FD_SET(fd, &rfd);
    struct timeval tv{seconds, 0};
    int rc = select(fd+1, &rfd, nullptr, nullptr, seconds >= 0 ? &tv : nullptr);
    return rc > 0 && FD_ISSET(fd, &rfd);
}

//
void TcpTransport::startReadBinaryLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb)
{
    auto readBuffer = std::make_shared<std::vector<uint8_t>>(1024);
    auto dataBuffer = std::make_shared<std::vector<uint8_t>>();
    auto self       = shared_from_this();

    // Keep the async handler alive across invocations using a shared_ptr.
    auto handler = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();
    *handler = [=, this](const boost::system::error_code& ec, std::size_t bytes) mutable {
        if (ec) {
            cb(ec, "");
            return;
        }

        dataBuffer->insert(dataBuffer->end(), readBuffer->begin(), readBuffer->begin() + bytes);

        while (true) {
            if (dataBuffer->empty()) break;

            uint64_t frameLen = 0; size_t used = 0;
            if (!decodeVarInt(dataBuffer->data(), dataBuffer->size(), &frameLen, &used)) {
                if (dataBuffer->size() < 10)
                    break; // wait for more bytes
                std::cerr << "[readHandler] ❌ Failed to decode varint header.\n";
                cb(boost::asio::error::invalid_argument, "");
                return;
            }

            if (frameLen == 0 || frameLen > 32 * 1024 * 1024) {
                cb(boost::asio::error::invalid_argument, "");
                return;
            }

            if (dataBuffer->size() < used + frameLen)
                break; // wait for rest

            std::string frame(reinterpret_cast<char*>(dataBuffer->data() + used), frameLen);
            cb(boost::system::error_code(), frame);

            dataBuffer->erase(dataBuffer->begin(), dataBuffer->begin() + used + frameLen);
        }

        socket->async_read_some(
            boost::asio::buffer(*readBuffer),
            [handler](const boost::system::error_code& ec, std::size_t n) {
                (*handler)(ec, n);
            });
    };

    socket->async_read_some(
        boost::asio::buffer(*readBuffer),
        [handler](const boost::system::error_code& ec, std::size_t n) {
            (*handler)(ec, n);
        });
}

// ---- Async queue write implementation ----
void TcpTransport::queueWrite(std::string data, bool binary)
{
    std::lock_guard<std::mutex> lock(writeMutex);
    writeQueue.push_back(std::move(data));
    writeQueueBinary.push_back(binary);
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
    std::string &msg = writeQueue.front();
    bool binary = writeQueueBinary.front();
    if (!binary) {
        if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    }
    boost::asio::async_write(*socket, boost::asio::buffer(msg),
        [this, self](const boost::system::error_code& ec, std::size_t) {
            std::lock_guard<std::mutex> lock(writeMutex);
            if (!writeQueue.empty()) writeQueue.pop_front();
            if (!writeQueueBinary.empty()) writeQueueBinary.pop_front();
            if (!ec)
                doWrite();
            else
                writeInProgress = false;
        });
}

void TcpTransport::startReadLineLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb)
{
    auto buf  = std::make_shared<boost::asio::streambuf>();
    auto self = shared_from_this();
    auto handler = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();
    *handler = [=, this](const boost::system::error_code& ec, std::size_t) mutable {
        if (ec) { cb(ec, ""); return; }
        std::istream is(buf.get());
        std::string line; std::getline(is, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        cb(boost::system::error_code(), line);
        boost::asio::async_read_until(*socket, *buf, '\n', *handler);
    };
    boost::asio::async_read_until(*socket, *buf, '\n', *handler);
}
