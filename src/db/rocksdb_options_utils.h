#pragma once

#include <rocksdb/options.h>
#include <rocksdb/version.h>

namespace alyn::db {

inline const char *DescribeCompression(rocksdb::CompressionType compression) {
  switch (compression) {
  case rocksdb::kNoCompression:
    return "none";
  case rocksdb::kSnappyCompression:
    return "Snappy";
  case rocksdb::kZlibCompression:
    return "Zlib";
  case rocksdb::kBZip2Compression:
    return "BZip2";
  case rocksdb::kLZ4Compression:
    return "LZ4";
  case rocksdb::kLZ4HCCompression:
    return "LZ4HC";
#if defined(ROCKSDB_MAJOR) && ROCKSDB_MAJOR >= 7
  case rocksdb::kZSTD:
    return "ZSTD";
#endif
#if defined(ROCKSDB_MAJOR) && ROCKSDB_MAJOR >= 6
  case rocksdb::kZSTDNotFinalCompression:
    return "ZSTD (not final)";
#endif
#if defined(ROCKSDB_MAJOR) && ROCKSDB_MAJOR >= 6 && ROCKSDB_MAJOR < 7
  case rocksdb::kZSTDCompression:
    return "ZSTD";
#endif
  default:
    return "unknown";
  }
}

inline rocksdb::CompressionType PreferredCompression() {
#if defined(ROCKSDB_MAJOR) && ROCKSDB_MAJOR >= 7
  return rocksdb::kZSTD;
#elif defined(ROCKSDB_MAJOR) && ROCKSDB_MAJOR >= 6
  return rocksdb::kZSTDCompression;
#else
  return rocksdb::kSnappyCompression;
#endif
}

template <typename OptionsT>
inline void ApplyCompactionDefaults(OptionsT &options) {
  options.OptimizeLevelStyleCompaction();
  options.compression = PreferredCompression();
  options.bottommost_compression = PreferredCompression();
  options.level_compaction_dynamic_level_bytes = true;
  options.target_file_size_base = 32ULL * 1024 * 1024;
}

inline void ApplyDatabaseDefaults(rocksdb::Options &options) {
  ApplyCompactionDefaults(options);
  options.write_buffer_size = 64ULL * 1024 * 1024;
}

}  // namespace alyn::db
