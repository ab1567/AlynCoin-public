#pragma once
#include <string>

namespace tls {
bool ensure_self_signed_cert(const std::string& dataDir, std::string& certPath, std::string& keyPath);
}
