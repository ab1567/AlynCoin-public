#include "tls_utils.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <filesystem>
#include <fstream>

namespace tls {

bool ensure_self_signed_cert(const std::string& dir, std::string& certPath, std::string& keyPath) {
    namespace fs = std::filesystem;
    certPath = fs::path(dir) / "cert.pem";
    keyPath  = fs::path(dir) / "key.pem";
    if (fs::exists(certPath) && fs::exists(keyPath))
        return true;

    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey)
        return false;

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
