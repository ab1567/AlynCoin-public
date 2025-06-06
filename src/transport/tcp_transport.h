#pragma once
#include "transport.h"
#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <string>

class TcpTransport : public Transport, public std::enable_shared_from_this<TcpTransport> {
public:
    TcpTransport(std::shared_ptr<boost::asio::ip::tcp::socket> sock);
    std::string remoteId() const override;
    void send(const std::string& data) override;
    void startReadLoop(std::function<void(const std::string&)> onLine) override;
private:
    std::shared_ptr<boost::asio::ip::tcp::socket> socket;
};
