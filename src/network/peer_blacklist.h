#ifndef PEER_BLACKLIST_H
#define PEER_BLACKLIST_H

#include <string>
#include <vector>
#include <rocksdb/db.h>
#include <mutex>

struct BlacklistEntry {
    std::string peer_id;       // Public key or IP
    std::string reason;        // Reason for blacklisting
    uint64_t timestamp;        // Unix time when blacklisted
    int strikes;               // Number of offenses
};

class PeerBlacklist {
private:
    rocksdb::DB* db;
    std::string db_path;
    std::mutex db_mutex;
    int strike_threshold;
    bool blacklistEnabled;  // <== Add this flag

    std::string makeKey(const std::string& peer_id) const;

public:
    PeerBlacklist(const std::string& path, int threshold = 3);
    ~PeerBlacklist();

    bool addPeer(const std::string& peer_id, const std::string& reason);
    bool removePeer(const std::string& peer_id);
    bool isBlacklisted(const std::string& peer_id);
    bool incrementStrike(const std::string& peer_id, const std::string& reason);
    std::vector<BlacklistEntry> getAllEntries();
    bool clearBlacklist();
};

#endif // PEER_BLACKLIST_H
