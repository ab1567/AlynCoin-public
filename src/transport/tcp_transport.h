#pragma once
#include "transport.h"
#include <boost/asio.hpp>
#include <memory>
#include <deque>
#include <mutex>

/**
 * Concrete Boost-Asio TCP transport.
 */
class TcpTransport : public Transport,
                     public std::enable_shared_from_this<TcpTransport>
{
public:
    // Outgoing connection helper (network.cpp uses make_shared<TcpTransport>(io_ctx)).
    explicit TcpTransport(boost::asio::io_context& ctx);
    explicit TcpTransport(std::shared_ptr<boost::asio::ip::tcp::socket> sock);

    std::string  remoteId()        const override;
    bool         write(const std::string& data) override;
    bool         isOpen()          const override;
    void         startReadLoop(std::function<void(const std::string&)> cb) override;

    bool         connect(const std::string& host, int port) override;
    std::string  getRemoteIP()     const override;
    int          getRemotePort()   const override;
    std::string  readLineBlocking() override;
    std::string  readLineWithTimeout(int seconds) override;
    void         asyncReadLine(std::function<void(const boost::system::error_code&, const std::string&)> cb) override;

    // === NEW: BINARY ===
    bool         writeBinary(const std::string& data) override;
    std::string  readBinaryBlocking() override;

    // Queue-based async write
    void         queueWrite(const std::string& data) override;

private:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    std::deque<std::string> writeQueue;
    std::mutex              writeMutex;
    bool                    writeInProgress{false};
    void doWrite();
};
