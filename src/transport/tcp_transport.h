#pragma once
#include "transport.h"
#include <boost/asio.hpp>
#include <memory>
#include <deque>
#include <mutex>
#include <array>

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
    void         close() override;
    void         closeGraceful() override;

    bool         connect(const std::string& host, int port) override;
    std::string  getRemoteIP()     const override;
    int          getRemotePort()   const override;
    std::string  readLineBlocking() override;
    std::string  readLineWithTimeout(int seconds) override;
    bool         waitReadable(int seconds) override;

    // === NEW: BINARY ===
    bool         writeBinary(const std::string& data) override;
    bool         writeBinaryLocked(const std::string& data);
    std::string  readBinaryBlocking() override;
    void         startReadBinaryLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) override;
    void         startReadLineLoop(std::function<void(const boost::system::error_code&, const std::string&)> cb) override;

    // Queue-based async write
    // Queue write now takes ownership of the data
    void         queueWrite(std::string data, bool binary = false) override;

private:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    std::array<char, 8 * 1024>                      readBuf_{};
    std::deque<std::string> writeQueue;
    std::deque<bool>        writeQueueBinary;
    std::mutex              writeMutex;
    bool                    writeInProgress{false};
    void doWrite();

protected:
    // Protects all blocking and async reads to avoid concurrent access
    mutable std::mutex                              readMutex;
};
