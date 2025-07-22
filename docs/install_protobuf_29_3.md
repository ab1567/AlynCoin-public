# Building Protobuf 29.3 from Source

Ubuntu packages typically provide an older version of Protobuf. To match the macOS build you can compile Protobuf v29.3 manually.

```bash
# Download and unpack the source
curl -L -o protobuf-29.3.tar.gz https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protobuf-cpp-29.3.tar.gz
mkdir -p ~/src && tar -xf protobuf-29.3.tar.gz -C ~/src
cd ~/src/protobuf-29.3

# Build and install
./configure --disable-shared
make -j$(nproc)
sudo make install
sudo ldconfig
```

After installation `protoc --version` should report `libprotoc 29.3`.
