#include "layer2/l2_state.h"
#include "layer2/l2_executor.h"
#include "layer2/wasm_engine.h"
#include <cassert>
#include <iostream>

static const uint8_t wasm[]={0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,9,1,5,101,110,116,114,121,0,0,10,6,1,4,0,65,0,11};

int main(){
    L2StateManager state;
    std::vector<uint8_t> code(wasm, wasm+sizeof(wasm));
    std::string addr = state.deploy(code);
    L2Executor exec(state);
    // storage write/read
    std::vector<uint8_t> key{0xde,0xad};
    std::vector<uint8_t> val{1,2,3};
    state.writeStorage(addr, key, val);
    auto out = state.readStorage(addr, key);
    assert(out==val);
    // success tx
    state.ensureAccount("caller");
    L2Tx tx{"caller", addr, 0,0,{},100000,0,0};
    auto res = exec.execute({tx});
    assert(res.second[0].status==0);
    // replay
    auto res2 = exec.execute({tx});
    assert(res2.second[0].status!=0);
    // OOG
    L2Tx tx2{"caller", addr, 1,0,{},1,0,0};
    auto res3 = exec.execute({tx2});
    assert(res3.second[0].status==2);
    std::cout<<"l2_state_test OK\n";
    return 0;
}
