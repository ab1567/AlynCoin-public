#include "layer2/wasm_engine.h"
#include "keccak.h"
#include <cassert>
#include <iostream>
#include <vector>

static const uint8_t wasm[]={0,97,115,109,1,0,0,0,1,16,3,96,3,127,127,127,0,96,2,127,127,0,96,0,1,127,2,34,2,3,101,110,118,9,107,101,99,99,97,107,50,53,54,0,0,3,101,110,118,10,101,109,105,116,95,101,118,101,110,116,0,1,3,2,1,2,5,3,1,0,1,7,18,2,6,109,101,109,111,114,121,2,0,5,101,110,116,114,121,0,2,10,20,1,18,0,65,0,65,3,65,16,16,0,65,16,65,32,16,1,65,0,11,11,9,1,0,65,0,11,3,97,98,99};

int main(){
    WasmEngine eng;
    auto mod = eng.load(std::vector<uint8_t>(wasm, wasm + sizeof(wasm)));
    auto inst = eng.instantiate(mod, 1000000, 64*1024);
    auto res = eng.call(inst, "entry", {});
    auto expected = Keccak::keccak256_raw(std::vector<uint8_t>{'a','b','c'});
    assert(res.events.size()==1);
    assert(res.events[0]==expected);
    auto inst2 = eng.instantiate(mod, 1, 64*1024);
    auto res2 = eng.call(inst2, "entry", {});
    assert(res2.retcode!=0);
    std::cout<<"wasm_vm_test OK\n";
    return 0;
}
