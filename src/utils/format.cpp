#include "format.h"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace pretty {

std::string shortenHash(const std::string& h) {
    if (h.size() <= 16) return h;
    return h.substr(0, 8) + ".." + h.substr(h.size() - 8);
}

std::string formatTimestampISO(uint64_t ts) {
    std::time_t t = static_cast<std::time_t>(ts);
    std::tm gm{};
    gmtime_r(&t, &gm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%FT%TZ", &gm);
    return buf;
}

double estimateFee(double amount) {
    double rawFee = amount * 0.01;
    double maxFee = std::min(amount * 0.00005, 1.0);
    return std::min(rawFee, maxFee);
}

std::string formatBlock(const BlockInfo& b) {
    std::ostringstream oss;
    oss << "height " << b.height
        << " time " << formatTimestampISO(b.timestamp)
        << " miner " << b.miner
        << " prev " << shortenHash(b.prevHash)
        << " hash " << shortenHash(b.hash)
        << " txs " << b.txCount
        << " est_size " << b.sizeEstimate;
    return oss.str();
}

std::string formatTx(const TxInfo& t) {
    std::ostringstream oss;
    oss << "#" << t.index
        << " from " << t.from
        << " to " << t.to
        << " amount " << t.amount
        << " fee " << t.fee
        << " nonce " << t.nonce
        << " type " << t.type
        << " status " << t.status;
    return oss.str();
}

} // namespace pretty
