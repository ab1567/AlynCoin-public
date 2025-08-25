#include "mnemonic.h"
#include "wordlist.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <sstream>
#include <random>
#include <cstring>

namespace Mnemonic {

static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data){
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::vector<std::string> entropyToMnemonic(const std::vector<uint8_t>& entropy){
    if(entropy.empty() || entropy.size() % 4 != 0) return {};
    size_t entBits = entropy.size()*8;
    size_t checksumBits = entBits/32;
    std::vector<uint8_t> hash = sha256(entropy);
    std::vector<bool> bits;
    bits.reserve(entBits+checksumBits);
    for(uint8_t b: entropy){
        for(int i=7;i>=0;--i) bits.push_back((b>>i)&1);
    }
    for(size_t i=0;i<checksumBits;i++) bits.push_back((hash[0]>>(7-i)) &1);
    std::vector<std::string> words;
    for(size_t i=0;i<bits.size()/11;i++){
        int idx=0;
        for(int j=0;j<11;j++) idx=(idx<<1)|bits[i*11+j];
        words.push_back(BIP39_WORDLIST[idx]);
    }
    return words;
}

std::vector<uint8_t> mnemonicToEntropy(const std::vector<std::string>& words){
    if(words.size()%3!=0) return {};
    std::vector<bool> bits;
    bits.reserve(words.size()*11);
    for(const auto& w:words){
        int index=-1;
        for(int i=0;i<2048;i++) if(w==BIP39_WORDLIST[i]){ index=i; break; }
        if(index==-1) return {};
        for(int j=10;j>=0;--j) bits.push_back((index>>j)&1);
    }
    size_t checksumBits=bits.size()/33;
    size_t entBits=bits.size()-checksumBits;
    std::vector<uint8_t> entropy(entBits/8);
    for(size_t i=0;i<entropy.size();i++){
        uint8_t b=0; for(int j=0;j<8;j++) b=(b<<1)|bits[i*8+j];
        entropy[i]=b;
    }
    std::vector<uint8_t> hash=sha256(entropy);
    for(size_t i=0;i<checksumBits;i++){
        bool bit=(hash[0]>>(7-i))&1;
        if(bits[entBits+i]!=bit) return {}; // invalid checksum
    }
    return entropy;
}

std::vector<std::string> generate(int wordCount){
    size_t entBytes = wordCount==24?32:16; //12->16bytes,24->32bytes
    std::random_device rd;
    std::vector<uint8_t> entropy(entBytes);
    for(auto &b:entropy) b = rd();
    auto words = entropyToMnemonic(entropy);
    OPENSSL_cleanse(entropy.data(), entropy.size());
    return words;
}

std::vector<uint8_t> mnemonicToSeed(const std::vector<std::string>& words, const std::string& passphrase){
    std::string mnemonic;
    for(size_t i=0;i<words.size();++i){ if(i) mnemonic+=' '; mnemonic+=words[i]; }
    std::string salt = "mnemonic" + passphrase;
    std::vector<uint8_t> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.size(),
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                      2048, EVP_sha512(), seed.size(), seed.data());
    OPENSSL_cleanse(mnemonic.data(), mnemonic.size());
    OPENSSL_cleanse(salt.data(), salt.size());
    return seed;
}

bool validate(const std::vector<std::string>& words){
    return !mnemonicToEntropy(words).empty();
}

} // namespace Mnemonic
