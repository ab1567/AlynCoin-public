  GNU nano 7.2                                          rocksdb_swap_store.cpp                                                    1 #include "rocksdb_swap_store.h"
 2 #include <rocksdb/utilities/transaction_db.h>
 3 #include <rocksdb/write_batch.h>
 4 #include "../utils/proto_utils.h"  // serializeSwap, deserializeSwap
 5
 6 RocksDBAtomicSwapStore::RocksDBAtomicSwapStore(const std::string& dbPath) {
 7     options.create_if_missing = true;
 8     rocksdb::Status status = rocksdb::TransactionDB::Open(options, txn_options, dbPath, &db);
 9     if (!status.ok()) {
10         throw std::runtime_error("Failed to open RocksDB: " + status.ToString());
11     }
12 }
13
14 RocksDBAtomicSwapStore::~RocksDBAtomicSwapStore() {
15     delete db;
16 }
17
18 bool RocksDBAtomicSwapStore::saveSwap(const AtomicSwap& swap) {
19     std::lock_guard<std::mutex> lock(mtx);
20     std::string key = makeKey(swap.id);
21     std::string value;
22     if (!serializeSwap(swap, value)) return false;
23     return db->Put(rocksdb::WriteOptions(), key, value).ok();
24 }
25
26 bool RocksDBAtomicSwapStore::updateSwap(const AtomicSwap& swap) {
27     return saveSwap(swap); // alias for clarity
28 }
29
30 std::optional<AtomicSwap> RocksDBAtomicSwapStore::loadSwap(const std::string& uuid) {
31     std::lock_guard<std::mutex> lock(mtx);
32     std::string value;
33     rocksdb::Status status = db->Get(rocksdb::ReadOptions(), makeKey(uuid), &value);
34     if (!status.ok()) return std::nullopt;
35
36     AtomicSwap swap;
37     if (!deserializeSwap(value, swap)) return std::nullopt;
38     return swap;
39 }
40
41 std::vector<AtomicSwap> RocksDBAtomicSwapStore::getAllSwaps() {
42     std::lock_guard<std::mutex> lock(mtx);
43     std::vector<AtomicSwap> result;
44     std::unique_ptr<rocksdb::Iterator> it(db->NewIterator(rocksdb::ReadOptions()));
45
46     for (it->Seek("aswap:"); it->Valid() && it->key().starts_with("aswap:"); it->Next()) {
47         AtomicSwap swap;
48         if (deserializeSwap(it->value().ToString(), swap)) {
49             result.push_back(swap);
50         }
51     }
52     return result;
53 }
54

