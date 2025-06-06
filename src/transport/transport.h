#pragma once
#include <string>
#include <functional>
#include <memory>

class Transport {
public:
    virtual ~Transport() = default;
    virtual std::string remoteId() const = 0; // e.g., "1.2.3.4:8333"
    virtual void send(const std::string& data) = 0;
    virtual void startReadLoop(std::function<void(const std::string&)> onLine) = 0;
};
