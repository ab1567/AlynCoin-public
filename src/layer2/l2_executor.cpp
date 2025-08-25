#include "l2_executor.h"
#include "crypto_utils.h"

std::pair<std::vector<uint8_t>, std::vector<L2Receipt>>
L2Executor::execute(const std::vector<L2Tx>& txs) {
    std::vector<L2Receipt> receipts;
    WasmEngine eng;
    for (const auto& tx : txs) {
        L2Receipt rc{1,0,{},{}};
        try {
            auto& fromAcc = state.getAccount(tx.from);
            if (fromAcc.nonce != tx.nonce) {
                receipts.push_back(rc);
                continue;
            }
            auto& toAcc = state.getAccount(tx.to);
            auto code = state.getCode(toAcc.codeHash);
            auto mod = eng.load(code);
            auto st = state.getStorage(tx.to);
            auto inst = eng.instantiate(mod, tx.gas_limit, 64*1024,
                [&](const std::vector<uint8_t>& key){
                    auto it = st.find(Crypto::toHex(key));
                    if (it == st.end()) return std::vector<uint8_t>{};
                    return it->second;
                },
                [&](const std::vector<uint8_t>& key, const std::vector<uint8_t>& val){
                    st[Crypto::toHex(key)] = val;
                });
            auto res = eng.call(inst, "entry", tx.calldata);
            rc.gas_used = res.gas_used;
            rc.events = res.events;
            rc.return_data = res.returndata;
            if (res.gas_used > tx.gas_limit) {
                rc.status = 2; // OOG
            } else if (res.retcode == 0) {
                rc.status = 0;
                fromAcc.nonce++;
                state.setStorage(tx.to, st);
            }
        } catch (...) {
            // keep default rc
        }
        receipts.push_back(rc);
    }
    auto root = state.stateRoot();
    return {root, receipts};
}
