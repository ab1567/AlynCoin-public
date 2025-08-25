#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include "wasm3.h"
#ifndef ENABLE_L2_VM
#define ENABLE_L2_VM 1
#endif


struct WasmCallResult {
    int32_t retcode;
    std::vector<uint8_t> returndata;
    uint64_t gas_used;
    std::vector<std::vector<uint8_t>> events;
};

class WasmEngine {
public:
    WasmEngine();
    ~WasmEngine();

    struct ModuleHandle { IM3Module module; };
    struct Instance {
        IM3Runtime runtime;
        IM3Module module;
        uint64_t gas_limit;
        uint64_t gas_used;
        std::vector<std::vector<uint8_t>> events;
    };

    ModuleHandle load(const std::vector<uint8_t>& code);
    Instance* instantiate(const ModuleHandle& module, uint64_t gas_limit, uint32_t memory_limit);
    WasmCallResult call(Instance* inst, const std::string& entry, const std::vector<uint8_t>& calldata);

private:
    IM3Environment env;
};
