#pragma once
#include <string>
#include <functional>
#include <boost/system/error_code.hpp>

// ---- Core abstract transport interface ----
class Transport {
public:
    virtual ~Transport() = default;

    // Text line (legacy)
    virtual std::string  remoteId()  const                                        = 0;
    virtual bool         write     (const std::string& data)                      = 0;
    virtual bool         isOpen    () const                                       = 0;
    virtual void         close() {}

    // Legacy helpers
    virtual bool send(const std::string& data)            { return write(data); }
    virtual bool connect(const std::string& /*host*/, int /*port*/) { return false; }
    virtual std::string  getRemoteIP()   const  { return {}; }
    virtual int          getRemotePort() const  { return 0;  }
    virtual std::string  readLineBlocking()                 { return {}; }
    virtual std::string  readLineWithTimeout(int /*sec*/)   { return {}; }
    // Wait until readable or timeout. Default returns true.
    virtual bool         waitReadable(int /*seconds*/)      { return true; }

    // ==== NEW: BINARY SUPPORT ====
    virtual bool writeBinary(const std::string& data) = 0;
    // Returns empty string on failure or disconnect.
    virtual std::string readBinaryBlocking() = 0;
    virtual void startReadBinaryLoop(std::function<void(const boost::system::error_code&, const std::string&)> /*cb*/) {}

    // ---- Async queue based send ----
    // Default implementation falls back to blocking write().
    virtual void queueWrite(std::string data, bool binary = false) {
        if (binary)
            writeBinary(data);
        else
            write(data);
    }

    virtual void startReadLineLoop(std::function<void(const boost::system::error_code&, const std::string&)> /*cb*/) {}
};
