#ifndef BASE64_H
#define BASE64_H

#include <string>
#include <vector>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace Base64 {
    inline std::string encode(const std::string& input) {
        BIO* bio, *b64;
        BUF_MEM* bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        BIO_write(bio, input.c_str(), input.length());
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        std::string output(bufferPtr->data, bufferPtr->length);

        BIO_free_all(bio);
        return output;
    }

    inline std::string decode(const std::string& input) {
        BIO* bio, *b64;
        char* buffer = new char[input.length()];
        memset(buffer, 0, input.length());

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new_mem_buf(input.c_str(), input.length());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        int decodedSize = BIO_read(bio, buffer, input.length());
        std::string output(buffer, decodedSize);

        delete[] buffer;
        BIO_free_all(bio);
        return output;
    }
}

#endif // BASE64_H
