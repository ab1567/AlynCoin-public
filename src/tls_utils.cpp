#include "tls_utils.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <filesystem>
#include <fstream>

namespace tls {

bool ensure_self_signed_cert(const std::string& dir, std::string& certPath, std::string& keyPath) {
    namespace fs = std::filesystem;
    fs::path certP = fs::path(dir) / "cert.pem";
    fs::path keyP  = fs::path(dir) / "key.pem";
    certPath = certP.string();
    keyPath  = keyP.string();
    if (fs::exists(certP) && fs::exists(keyP))
        return true;

    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
        return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return false;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        return false;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("AlynCoin Node"), -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    fs::create_directories(fs::path(dir));
    FILE* f = fopen(keyPath.c_str(), "w");
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);
    f = fopen(certPath.c_str(), "w");
    PEM_write_X509(f, x509);
    fclose(f);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

} // namespace tls
