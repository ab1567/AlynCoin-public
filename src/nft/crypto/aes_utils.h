#ifndef AES_CRYPTO_H
#define AES_CRYPTO_H

#include <string>

namespace AES {
    std::string encrypt(const std::string& plaintext, const std::string& password);
    std::string decrypt(const std::string& ciphertextBase64, const std::string& password);
}

#endif
