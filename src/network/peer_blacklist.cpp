#include "peer_blacklist.h"
#include <rocksdb/options.h>
#include <rocksdb/write_batch.h>
#include <chrono>
#include <iostream>
#include <sstream>
#include <json/json.h> // You already use JSON in explorer
#include "db/db_paths.h"

PeerBlacklist::PeerBlacklist(const std::string& path, int threshold) : db_path(path), strike_threshold(threshold) {
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, db_path, &db);
    if (!status.ok()) {
        std::cerr << "Failed to open peer blacklist DB: " << status.ToString() << std::endl;
        db = nullptr;
    }
}

PeerBlacklist::~PeerBlacklist() {
    delete db;
}

std::string PeerBlacklist::makeKey(const std::string& peer_id) const {
    return "blacklist_" + peer_id;
}

bool PeerBlacklist::addPeer(const std::string& peer_id, const std::string& reason) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return false;

    BlacklistEntry entry;
    entry.peer_id = peer_id;
    entry.reason = reason;
    entry.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    entry.strikes = strike_threshold;

    Json::Value json;
    json["peer_id"] = entry.peer_id;
    json["reason"] = entry.reason;
    json["timestamp"] = (Json::UInt64)entry.timestamp;
    json["strikes"] = entry.strikes;

    Json::StreamWriterBuilder writer;
    std::string value = Json::writeString(writer, json);

    rocksdb::Status s = db->Put(rocksdb::WriteOptions(), makeKey(peer_id), value);
    return s.ok();
}

bool PeerBlacklist::removePeer(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return false;
    rocksdb::Status s = db->Delete(rocksdb::WriteOptions(), makeKey(peer_id));
    return s.ok();
}

bool PeerBlacklist::isBlacklisted(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return false;
    std::string value;
    rocksdb::Status s = db->Get(rocksdb::ReadOptions(), makeKey(peer_id), &value);
    return s.ok();
}

bool PeerBlacklist::incrementStrike(const std::string& peer_id, const std::string& reason) {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return false;

    std::string value;
    rocksdb::Status s = db->Get(rocksdb::ReadOptions(), makeKey(peer_id), &value);
    BlacklistEntry entry;
    if (s.ok()) {
        Json::Value json;
        Json::CharReaderBuilder reader;
        std::istringstream ss(value);
        std::string errs;
        if (Json::parseFromStream(reader, ss, &json, &errs)) {
            entry.peer_id = json["peer_id"].asString();
            entry.reason = json["reason"].asString();
            entry.timestamp = json["timestamp"].asUInt64();
            entry.strikes = json["strikes"].asInt();
        }
        entry.strikes++;
        if (entry.strikes >= strike_threshold) {
            entry.reason = reason;
            entry.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        }
    } else {
        // First strike
        entry.peer_id = peer_id;
        entry.reason = reason;
        entry.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        entry.strikes = 1;
    }

    Json::Value json;
    json["peer_id"] = entry.peer_id;
    json["reason"] = entry.reason;
    json["timestamp"] = (Json::UInt64)entry.timestamp;
    json["strikes"] = entry.strikes;

    Json::StreamWriterBuilder writer;
    std::string new_value = Json::writeString(writer, json);

    s = db->Put(rocksdb::WriteOptions(), makeKey(peer_id), new_value);
    return s.ok();
}

std::vector<BlacklistEntry> PeerBlacklist::getAllEntries() {
    std::lock_guard<std::mutex> lock(db_mutex);
    std::vector<BlacklistEntry> entries;
    if (!db) return entries;

    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("blacklist_") != 0) continue;

        Json::Value json;
        Json::CharReaderBuilder reader;
        std::istringstream ss(it->value().ToString());
        std::string errs;
        if (Json::parseFromStream(reader, ss, &json, &errs)) {
            BlacklistEntry entry;
            entry.peer_id = json["peer_id"].asString();
            entry.reason = json["reason"].asString();
            entry.timestamp = json["timestamp"].asUInt64();
            entry.strikes = json["strikes"].asInt();
            entries.push_back(entry);
        }
    }
    delete it;
    return entries;
}

bool PeerBlacklist::clearBlacklist() {
    std::lock_guard<std::mutex> lock(db_mutex);
    if (!db) return false;

    rocksdb::WriteBatch batch;
    rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find("blacklist_") == 0) {
            batch.Delete(key);
        }
    }
    delete it;
    rocksdb::Status s = db->Write(rocksdb::WriteOptions(), &batch);
    return s.ok();
}
