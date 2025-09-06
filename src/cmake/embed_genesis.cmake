# Generate a header that embeds genesis_block.bin as a byte array.
# Usage:
#   -DINPUT=/path/to/genesis_block.bin  (optional)
#   -DOUTPUT=/path/to/generated/genesis_embed.h (required)

if(NOT DEFINED OUTPUT)
  message(FATAL_ERROR "embed_genesis.cmake requires -DOUTPUT=<header>")
endif()

set(GENESIS_SIZE 0)
set(GENESIS_LIST "")

if(DEFINED INPUT AND EXISTS "${INPUT}")
  file(READ "${INPUT}" GENESIS_HEX HEX)
  # Convert pairs of hex chars into 0xXX,
  string(REGEX REPLACE "([0-9A-Fa-f][0-9A-Fa-f])" "0x\\1," GENESIS_LIST "${GENESIS_HEX}")
  # Compute size: number of nibbles / 2
  string(LENGTH "${GENESIS_HEX}" GENESIS_NIBBLES)
  math(EXPR GENESIS_SIZE "${GENESIS_NIBBLES} / 2")
else()
  message(STATUS "No INPUT genesis provided; generating empty embed header")
endif()

file(WRITE "${OUTPUT}" "#pragma once\n")
file(APPEND "${OUTPUT}" "#include <cstddef>\n\n")
file(APPEND "${OUTPUT}" "namespace alyn_assets {\n")
file(APPEND "${OUTPUT}" "static const unsigned char kEmbeddedGenesis[] = {\n")
file(APPEND "${OUTPUT}" "${GENESIS_LIST}\n")
file(APPEND "${OUTPUT}" "};\n")
file(APPEND "${OUTPUT}" "static const size_t kEmbeddedGenesisSize = ${GENESIS_SIZE};\n")
file(APPEND "${OUTPUT}" "} // namespace alyn_assets\n")

message(STATUS "Wrote genesis embed header: ${OUTPUT} (size: ${GENESIS_SIZE} bytes)")

