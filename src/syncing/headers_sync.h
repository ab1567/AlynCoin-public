#ifndef HEADERS_SYNC_H
#define HEADERS_SYNC_H

#include <generated/net_frame.pb.h>
#include <string>
#include <vector>

class HeadersSync {
public:
    struct HeaderRecord {
        std::string hash;
        std::string previousHash;
        int index{0};
    };

    static void requestHeaders(const std::string &peer, const std::string &fromHash);
    static void handleHeaders(const std::string &peer, const alyncoin::net::Headers &proto);
};

#endif // HEADERS_SYNC_H
