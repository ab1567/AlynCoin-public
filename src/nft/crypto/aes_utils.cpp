#include "aes_utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/aes.h>

#define AES_KEYLEN 32
#define AES_IVLEN 16
#define PBKDF2_ITER 100000

static std::string base64Encode(const std::vector<unsigned char>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

static std::vector<unsigned char> base64Decode(const std::string& input) {
    BIO* bio, * b64;
    int length = static_cast<int>(input.length());
    std::vector<unsigned char> buffer(length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), length);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    int decodedLen = BIO_read(bio, buffer.data(), length);
    buffer.resize(decodedLen);
    BIO_free_all(bio);
    return buffer;
}

namespace AES {

std::string encrypt(const std::string& plaintext, const std::string& password) {
    std::vector<unsigned char> salt(8);
    RAND_bytes(salt.data(), salt.size());

    unsigned char key[AES_KEYLEN], iv[AES_IVLEN];
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()), salt.data(), salt.size(),
                      PBKDF2_ITER, EVP_sha256(), AES_KEYLEN, key);
    RAND_bytes(iv, AES_IVLEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertextLen = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), static_cast<int>(plaintext.size()));
    ciphertextLen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertextLen += len;
    ciphertext.resize(ciphertextLen);
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> fullOutput;
    fullOutput.insert(fullOutput.end(), salt.begin(), salt.end());
    fullOutput.insert(fullOutput.end(), iv, iv + AES_IVLEN);
    fullOutput.insert(fullOutput.end(), ciphertext.begin(), ciphertext.end());

    return base64Encode(fullOutput);
}

std::string decrypt(const std::string& ciphertextBase64, const std::string& password) {
    auto decoded = base64Decode(ciphertextBase64);
    if (decoded.size() < 8 + AES_IVLEN) throw std::runtime_error("Invalid encrypted data");

    unsigned char key[AES_KEYLEN], iv[AES_IVLEN];
    std::vector<unsigned char> salt(decoded.begin(), decoded.begin() + 8);
    std::copy(decoded.begin() + 8, decoded.begin() + 8 + AES_IVLEN, iv);

    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()), salt.data(), salt.size(),
                      PBKDF2_ITER, EVP_sha256(), AES_KEYLEN, key);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(decoded.size());
    int len;
    int plaintextLen = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, decoded.data() + 8 + AES_IVLEN, static_cast<int>(decoded.size() - 8 - AES_IVLEN));
    plaintextLen += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintextLen += len;
    plaintext.resize(plaintextLen);
    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.end());
}

}  // namespace AES
