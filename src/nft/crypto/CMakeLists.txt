add_library(nft_crypto
    aes_utils.cpp
)

target_include_directories(nft_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(nft_crypto OpenSSL::Crypto)
