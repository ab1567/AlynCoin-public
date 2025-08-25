#include "layer2/wasm_engine.h"
#include "keccak.h"
#include "blake3.h"
#include "m3_env.h"
#include <vector>
#include <cstring>

WasmEngine::WasmEngine() { env = m3_NewEnvironment(); }
WasmEngine::~WasmEngine() { if (env) m3_FreeEnvironment(env); }

// Host functions
auto *get_instance(IM3Runtime rt) {
    return static_cast<WasmEngine::Instance*>(rt->userdata);
}

m3ApiRawFunction(host_get_caller) {
    m3ApiGetArgMem(uint8_t*, out);
    memset(out, 0, 32);
    m3ApiSuccess();
}

m3ApiRawFunction(host_block_height) {
    m3ApiReturnType(uint64_t);
    m3ApiReturn(0);
}

m3ApiRawFunction(host_block_time) {
    m3ApiReturnType(uint64_t);
    m3ApiReturn(0);
}

m3ApiRawFunction(host_keccak256) {
    m3ApiGetArgMem(const uint8_t*, ptr);
    m3ApiGetArg(uint32_t, len);
    m3ApiGetArgMem(uint8_t*, out);
    std::vector<uint8_t> input(ptr, ptr + len);
    auto hash = Keccak::keccak256_raw(input);
    memcpy(out, hash.data(), 32);
    m3ApiSuccess();
}

m3ApiRawFunction(host_blake3) {
    m3ApiGetArgMem(const uint8_t*, ptr);
    m3ApiGetArg(uint32_t, len);
    m3ApiGetArgMem(uint8_t*, out);
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, ptr, len);
    blake3_hasher_finalize(&hasher, out, 32);
    m3ApiSuccess();
}

m3ApiRawFunction(host_verify_dilithium) {
    m3ApiReturnType(uint32_t);
    m3ApiReturn(0);
}

m3ApiRawFunction(host_verify_falcon) {
    m3ApiReturnType(uint32_t);
    m3ApiReturn(0);
}

m3ApiRawFunction(host_emit_event) {
    m3ApiGetArgMem(const uint8_t*, ptr);
    m3ApiGetArg(uint32_t, len);
    auto inst = get_instance(runtime);
    inst->events.emplace_back(ptr, ptr + len);
    m3ApiSuccess();
}

WasmEngine::ModuleHandle WasmEngine::load(const std::vector<uint8_t>& code) {
#if ENABLE_L2_VM
    IM3Module module;
    m3_ParseModule(env, &module, code.data(), code.size());
    return {module};
#else
    (void)code;
    return {nullptr};
#endif
}

WasmEngine::Instance* WasmEngine::instantiate(const ModuleHandle& mh, uint64_t gas_limit, uint32_t stack_size) {
#if ENABLE_L2_VM
    Instance* inst = new Instance();
    inst->gas_limit = gas_limit;
    inst->gas_used = 0;
    inst->module = mh.module;
    inst->runtime = m3_NewRuntime(env, stack_size, NULL);
    inst->runtime->userdata = inst;
    m3_LoadModule(inst->runtime, inst->module);
    m3_LinkRawFunction(inst->module, "env", "get_caller", "v(*)", &host_get_caller);
    m3_LinkRawFunction(inst->module, "env", "block_height", "I()", &host_block_height);
    m3_LinkRawFunction(inst->module, "env", "block_time", "I()", &host_block_time);
    m3_LinkRawFunction(inst->module, "env", "keccak256", "v(*i*)", &host_keccak256);
    m3_LinkRawFunction(inst->module, "env", "blake3", "v(*i*)", &host_blake3);
    m3_LinkRawFunction(inst->module, "env", "verify_dilithium", "i(***)", &host_verify_dilithium);
    m3_LinkRawFunction(inst->module, "env", "verify_falcon", "i(***)", &host_verify_falcon);
    m3_LinkRawFunction(inst->module, "env", "emit_event", "v(*i)", &host_emit_event);
    return inst;
#else
    (void)mh; (void)gas_limit; (void)stack_size;
    return nullptr;
#endif
}

WasmCallResult WasmEngine::call(Instance* inst, const std::string& entry, const std::vector<uint8_t>& calldata) {
#if ENABLE_L2_VM
    WasmCallResult res{1, {}, 0, {}};
    IM3Function fn;
    if (m3_FindFunction(&fn, inst->runtime, entry.c_str()) != m3Err_none) return res;
    if (inst->gas_limit < 1000) { res.gas_used = inst->gas_limit; return res; }
    M3Result r = m3_CallArgv(fn, 0, nullptr);
    res.retcode = (r == m3Err_none) ? 0 : 1;
    uint32_t value = 0;
    const void* retptrs[1] = { &value };
    if (m3_GetResults(fn, 1, retptrs) == m3Err_none) {
        res.returndata.resize(sizeof(uint32_t));
        memcpy(res.returndata.data(), &value, sizeof(uint32_t));
    }
    res.events = inst->events;
    res.gas_used = 1000;
    return res;
#else
    (void)inst; (void)entry; (void)calldata;
    return {1, {}, 0, {}};
#endif
}
