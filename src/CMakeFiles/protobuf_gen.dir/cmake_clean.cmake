file(REMOVE_RECURSE
  "../generated/block_protos.pb.cc"
  "../generated/block_protos.pb.h"
  "../generated/blockchain_protos.pb.cc"
  "../generated/blockchain_protos.pb.h"
  "../generated/crypto_protos.pb.cc"
  "../generated/crypto_protos.pb.h"
  "../generated/main_protos.pb.cc"
  "../generated/main_protos.pb.h"
  "../generated/sync_protos.pb.cc"
  "../generated/sync_protos.pb.h"
  "../generated/transaction_protos.pb.cc"
  "../generated/transaction_protos.pb.h"
  "CMakeFiles/protobuf_gen"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/protobuf_gen.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
