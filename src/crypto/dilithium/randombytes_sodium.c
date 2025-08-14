#include <sodium.h>
void randombytes(unsigned char *buf, unsigned long long n) {
    if (sodium_init() < 0) {
        /* panic or handle error */
    }
    randombytes_buf(buf, (size_t)n);
}
