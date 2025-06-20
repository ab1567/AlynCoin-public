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

// === BINARY WRITE: raw protobuf frame ===
bool TcpTransport::writeBinary(const std::string& data)
{
    if (!isOpen()) return false;
    try {
        boost::asio::write(*socket, boost::asio::buffer(data));
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
        uint8_t hdr[10];
        size_t pos = 0; uint64_t need = 0; size_t used = 0;
        while (pos < sizeof(hdr)) {
            size_t got = boost::asio::read(*socket, boost::asio::buffer(hdr + pos, 1));
            if (got != 1) return {};
            ++pos;
            if (decodeVarInt(hdr, pos, &need, &used))
                break;
        }
        if (used == 0 || need > 32 * 1024 * 1024)
            return {};
        std::string buf(need, '\0');
        boost::asio::read(*socket, boost::asio::buffer(buf));
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
    auto self   = shared_from_this();
    auto header = std::make_shared<std::vector<uint8_t>>(1);

    std::shared_ptr<std::function<void(const boost::system::error_code&, std::size_t)>> readHeader;
    readHeader = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();

    *readHeader = [this, self, header, cb, readHeader](const boost::system::error_code& ec, std::size_t) {
        if (ec) { cb(ec, {}); return; }

        uint64_t len = 0; size_t used = 0;
        if (decodeVarInt(header->data(), header->size(), &len, &used)) {
            if (len == 0 || len > 32 * 1024 * 1024) {
                cb(boost::asio::error::invalid_argument, {});
                return;
            }
            auto body = std::make_shared<std::vector<char>>(len);
            boost::asio::async_read(*socket, boost::asio::buffer(*body),
                [this, self, body, cb, header, readHeader](const boost::system::error_code& ec2, std::size_t) {
                    std::string out;
                    if (!ec2)
                        out.assign(body->data(), body->size());
                    cb(ec2, out);
                    if (!ec2) {
                        header->clear();
                        header->resize(1);
                        boost::asio::async_read(*self->socket, boost::asio::buffer(*header), *readHeader);
                    }
                });
        } else if (header->size() < 10) {
            header->resize(header->size() + 1);
            boost::asio::async_read(*socket, boost::asio::buffer(header->data() + header->size() - 1, 1), *readHeader);
        } else {
            cb(boost::asio::error::invalid_argument, {});
        }
    };

    boost::asio::async_read(*socket, boost::asio::buffer(*header), *readHeader);
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
