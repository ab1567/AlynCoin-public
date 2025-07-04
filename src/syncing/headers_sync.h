#ifndef HEADERS_SYNC_H
#define HEADERS_SYNC_H

#include <string>
#include "generated/net_frame.pb.h"

class HeadersSync {
public:
    static void requestHeaders(const std::string &peer, const std::string &fromHash);
    static void handleHeaders(const std::string &peer, const alyncoin::net::Headers &proto);
};

#endif // HEADERS_SYNC_H
