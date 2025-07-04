#pragma once
#include "transport/tcp_transport.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <deque>
#include <memory>
#include <mutex>

class SslTransport : public TcpTransport {
public:
    SslTransport(boost::asio::io_context& ctx, boost::asio::ssl::context& sslCtx);
    explicit SslTransport(std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> stream);

    std::string  remoteId() const override;
    bool         write(const std::string& data) override;
    bool         isOpen() const override;
    void         close() override;
    void         closeGraceful() override;

    bool         connect(const std::string& host, int port) override;
    std::string  getRemoteIP() const override;
    int          getRemotePort() const override;
    std::string  readLineBlocking() override;
    std::string  readLineWithTimeout(int seconds) override;
    bool         waitReadable(int seconds) override;

    bool         writeBinary(const std::string& data) override;
    bool         writeBinaryLocked(const std::string& data);
    std::string  readBinaryBlocking() override;
    void         startReadBinaryLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) override;
    void         startReadLineLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) override;

    void         queueWrite(std::string data, bool binary = false) override;

private:
    std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> sslSocket;
    std::deque<std::string> writeQueue;
    std::deque<bool>        writeQueueBinary;
    std::mutex              writeMutex;
    bool                    writeInProgress{false};
    void doWrite();
};
