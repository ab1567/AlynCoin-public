#include "tcp_transport.h"
#include <iostream>
#include <boost/asio.hpp>

TcpTransport::TcpTransport(std::shared_ptr<boost::asio::ip::tcp::socket> sock)
    : socket(std::move(sock)) {}

std::string TcpTransport::remoteId() const {
    try {
        auto ep = socket->remote_endpoint();
        return ep.address().to_string() + ":" + std::to_string(ep.port());
    } catch (...) {
        return "unknown";
    }
}

void TcpTransport::send(const std::string& data) {
    if (!socket || !socket->is_open()) return;
    try {
        std::string msg = data;
        if (msg.back() != '\n') msg += '\n';
        boost::asio::write(*socket, boost::asio::buffer(msg));
    } catch (const std::exception& e) {
        std::cerr << "[TcpTransport::send] Exception: " << e.what() << std::endl;
    }
}

void TcpTransport::startReadLoop(std::function<void(const std::string&)> onLine) {
    auto self = shared_from_this();
    auto buf = std::make_shared<boost::asio::streambuf>();

    auto handler = std::make_shared<
        std::function<void(const boost::system::error_code&, std::size_t)>
    >();

    *handler = [self, buf, handler, onLine](const boost::system::error_code& ec, std::size_t) {
        if (ec) return;
        std::istream is(buf.get());
        std::string line;
        while (std::getline(is, line)) {
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                line.pop_back();
            if (!line.empty())
                onLine(line);
        }
        boost::asio::async_read_until(*self->socket, *buf, "\n", *handler);
    };
    boost::asio::async_read_until(*socket, *buf, "\n", *handler);
}
