#include "transport/ssl_transport.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include "wire/varint.h"

#include <iostream>
#include <sys/select.h>

using boost::asio::ip::tcp;

SslTransport::SslTransport(boost::asio::io_context& ctx, boost::asio::ssl::context& sslCtx)
    : TcpTransport(ctx),
      sslSocket(std::make_shared<boost::asio::ssl::stream<tcp::socket>>(ctx, sslCtx)) {}

SslTransport::SslTransport(std::shared_ptr<boost::asio::ssl::stream<tcp::socket>> stream)
    : TcpTransport(static_cast<boost::asio::io_context&>(stream->get_executor().context())),
      sslSocket(std::move(stream)) {}

std::string SslTransport::remoteId() const {
    try {
        auto ep = sslSocket->lowest_layer().remote_endpoint();
        return ep.address().to_string() + ':' + std::to_string(ep.port());
    } catch (...) {
        return "unknown";
    }
}

bool SslTransport::isOpen() const {
    return sslSocket && sslSocket->lowest_layer().is_open();
}

void SslTransport::close() {
    if (sslSocket && sslSocket->lowest_layer().is_open()) {
        boost::system::error_code ec;
        sslSocket->lowest_layer().close(ec);
    }
}

bool SslTransport::connect(const std::string& host, int port) {
    try {
        tcp::resolver res(sslSocket->get_executor());
        auto eps = res.resolve(host, std::to_string(port));
        boost::asio::connect(sslSocket->lowest_layer(), eps);
        sslSocket->handshake(boost::asio::ssl::stream_base::client);
        return true;
    } catch (const std::exception& ex) {
        std::cerr << "[SslTransport::connect] " << ex.what() << '\n';
        return false;
    }
}

std::string SslTransport::getRemoteIP() const {
    try { return sslSocket->lowest_layer().remote_endpoint().address().to_string(); }
    catch (...) { return {}; }
}

int SslTransport::getRemotePort() const {
    try { return static_cast<int>(sslSocket->lowest_layer().remote_endpoint().port()); }
    catch (...) { return 0; }
}

bool SslTransport::write(const std::string& data) {
    if (!isOpen()) return false;
    std::string msg = data;
    if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    boost::system::error_code ec;
    boost::asio::write(*sslSocket, boost::asio::buffer(msg), ec);
    if (ec) {
        std::cerr << "[SslTransport::write] " << ec.message() << '\n';
        close();
        return false;
    }
    return true;
}

bool SslTransport::writeBinary(const std::string& data) {
    std::lock_guard<std::mutex> lock(writeMutex);
    return writeBinaryLocked(data);
}

bool SslTransport::writeBinaryLocked(const std::string& data) {
    if (!isOpen()) return false;
    boost::system::error_code ec;
    boost::asio::write(*sslSocket, boost::asio::buffer(data), ec);
    if (ec) {
        std::cerr << "[SslTransport] ❌ Write binary failed: " << ec.message() << '\n';
        close();
        return false;
    }
    return true;
}

std::string SslTransport::readBinaryBlocking() {
    if (!isOpen()) return {};
    try {
        uint64_t need = 0;
        if (!readVarIntBlocking(*sslSocket, need))
            return {};
        if (need == 0 || need > 32 * 1024 * 1024)
            return {};
        std::string buf(need, '\0');
        boost::asio::read(*sslSocket, boost::asio::buffer(buf));
        return buf;            // protobuf-ready
    } catch (const std::exception& ex) {
        std::cerr << "[SslTransport::readBinaryBlocking] " << ex.what() << '\n';
        return {};
    }
}

std::string SslTransport::readLineBlocking() {
    boost::asio::streambuf buf;
    boost::asio::read_until(*sslSocket, buf, '\n');
    std::istream is(&buf);
    std::string  line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

std::string SslTransport::readLineWithTimeout(int) {
    return readLineBlocking();
}

bool SslTransport::waitReadable(int seconds) {
    if (!isOpen()) return false;
    int fd = sslSocket->lowest_layer().native_handle();
    fd_set rfd; FD_ZERO(&rfd); FD_SET(fd, &rfd);
    struct timeval tv{seconds, 0};
    int rc = select(fd+1, &rfd, nullptr, nullptr, seconds >= 0 ? &tv : nullptr);
    return rc > 0 && FD_ISSET(fd, &rfd);
}

void SslTransport::startReadBinaryLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) {
    auto readBuffer = std::make_shared<std::vector<uint8_t>>(1024);
    auto dataBuffer = std::make_shared<std::vector<uint8_t>>();
    auto self       = TcpTransport::shared_from_this();
    auto handler = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();
    *handler = [=, this](const boost::system::error_code& ec, std::size_t bytes) mutable {
        if (ec) { cb(ec, ""); return; }
        dataBuffer->insert(dataBuffer->end(), readBuffer->begin(), readBuffer->begin() + bytes);
        while (true) {
            if (dataBuffer->empty()) break;
            uint64_t frameLen = 0; size_t used = 0;
            if (!decodeVarInt(dataBuffer->data(), dataBuffer->size(), &frameLen, &used)) {
                if (dataBuffer->size() < 10)
                    break; // wait for more bytes
                std::cerr << "[SslTransport/readHandler] failed to decode varint header\n";
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
        sslSocket->async_read_some(boost::asio::buffer(*readBuffer), *handler);
    };
    sslSocket->async_read_some(boost::asio::buffer(*readBuffer), *handler);
}

void SslTransport::startReadLineLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) {
    auto buf  = std::make_shared<boost::asio::streambuf>();
    auto self = TcpTransport::shared_from_this();
    auto handler = std::make_shared<std::function<void(const boost::system::error_code&, std::size_t)>>();
    *handler = [=, this](const boost::system::error_code& ec, std::size_t) mutable {
        if (ec) { cb(ec, ""); return; }
        std::istream is(buf.get());
        std::string line; std::getline(is, line);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        cb(boost::system::error_code(), line);
        boost::asio::async_read_until(*sslSocket, *buf, '\n', *handler);
    };
    boost::asio::async_read_until(*sslSocket, *buf, '\n', *handler);
}

void SslTransport::queueWrite(std::string data, bool binary) {
    std::lock_guard<std::mutex> lock(writeMutex);
    writeQueue.push_back(std::move(data));
    writeQueueBinary.push_back(binary);
    if (!writeInProgress)
        doWrite();
}

void SslTransport::doWrite() {
    if (writeQueue.empty() || !isOpen()) {
        writeInProgress = false;
        return;
    }
    writeInProgress = true;
    auto self = TcpTransport::shared_from_this();
    std::string &msg = writeQueue.front();
    bool binary = writeQueueBinary.front();
    if (!binary) {
        if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    }
    boost::asio::async_write(*sslSocket, boost::asio::buffer(msg),
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
