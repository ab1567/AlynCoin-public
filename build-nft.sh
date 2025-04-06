#!/bin/bash
cd ~/AlynCoin/src/nft
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
