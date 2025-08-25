#pragma once
#include <vector>
#include <utility>
#include "l2_tx.h"
#include "l2_state.h"
#include "layer2/wasm_engine.h"

struct L2Receipt {
    int status; // 0=OK,1=FAIL,2=OOG
    uint64_t gas_used;
    std::vector<std::vector<uint8_t>> events;
    std::vector<uint8_t> return_data;
};

class L2Executor {
public:
    explicit L2Executor(L2StateManager& state) : state(state) {}

    std::pair<std::vector<uint8_t>, std::vector<L2Receipt>>
    execute(const std::vector<L2Tx>& txs);

private:
    L2StateManager& state;
};
