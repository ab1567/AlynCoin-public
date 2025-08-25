#include "blockchain.h"
#include "cli/peer_blacklist_cli.h"
#include "crypto_utils.h"
#include "network.h"
#include "network/peer_blacklist.h"
#include "wallet.h"
#include "wallet_recovery.h"
#include "layer2/wasm_engine.h"
#include <fstream>
#include <iostream>
#include <json/json.h>
#include "policy.h"
#include <limits>
#include <string>
#include <filesystem>
#include <sstream>
#include <vector>
#include <cstdlib>
#include "db/db_paths.h"
#include "governance/dao.h"
#include "governance/devfund.h"
#include "governance/dao_storage.h"
#include <ctime>
#include <filesystem>
#include "db/db_instance.h"
#include "zk/recursive_proof_helper.h"
#include "difficulty.h"

#include <unordered_set>
static std::unordered_set<std::string> cliSeenTxHashes;
#include "utils/format.h"

std::string getCurrentWallet() {
    std::ifstream in(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt");
    std::string addr;
    std::getline(in, addr);
    return addr;
}

void printMenu() {
  std::cout << "\n=== AlynCoin Wallet CLI ===\n";
  std::cout << "1. Generate new wallet\n";
  std::cout << "2. Load existing wallet\n";
  std::cout << "3. Check balance\n";
  std::cout << "4. Send L1 transaction\n";
  std::cout << "5. Send L2 transaction\n";
  std::cout << "6. Mine block\n";
  std::cout << "7. Print blockchain\n";
  std::cout << "8. View Dev Fund Info\n";
  std::cout << "9. Manage Peer Blacklist\n";
  std::cout << "10. Generate Rollup Block (zk-STARK)\n";
  std::cout << "11. Exit\n";
  std::cout << "12. Submit DAO Proposal\n";
  std::cout << "13. Vote on DAO Proposal\n";
  std::cout << "14. View DAO Proposals\n";
  std::cout << "15. Finalize DAO Proposal\n";
  std::cout << "16. View Blockchain Stats\n";
  std::cout << "17. Generate Rollup Block with Recursive zk-STARK Proof\n";
  std::cout << "18. Auto Rollup Trigger (Idle / Activity / Recursive)\n";
  std::cout << "19. Generate Recursive zk-STARK Proof (history)\n";
  std::cout << "Choose an option: ";
}

void printBlacklistMenu() {
  std::cout << "\n=== Peer Blacklist Menu ===\n";
  std::cout << "1. View Blacklist\n";
  std::cout << "2. Add Peer\n";
  std::cout << "3. Remove Peer\n";
  std::cout << "4. Clear Blacklist\n";
  std::cout << "5. Back to Main Menu\n";
  std::cout << "Choose an option: ";
}

// Version string for the CLI
static const char *CLI_VERSION = "0.1";

// Print top level help/command matrix
void printHelp() {
  std::cout << "AlynCoin CLI\n\n";
  std::cout << "Usage: alyncoin-cli <command> [args]\n\n";
  std::cout << "Commands:\n";
  std::cout << "  wallet new                     Create a new wallet\n";
  std::cout << "  wallet load <name>             Load an existing wallet\n";
  std::cout << "  balance <address>              Show wallet balance\n";
  std::cout << "  send l1 <from> <to> <amount> <metadata>  Send L1 transaction\n";
  std::cout << "  send l2 <from> <to> <amount> <metadata>  Send L2 transaction\n";
  std::cout << "  mine <miner_address>           Mine pending transactions\n";
  std::cout << "  rollup <address>               Generate rollup block\n";
  std::cout << "  dao submit <from> <desc> [type] [amount] [target]\n";
  std::cout << "  dao vote <from> <id> <yes|no>\n";
  std::cout << "  dao list                       List DAO proposals\n";
  std::cout << "  dao finalize <id>              Finalize DAO proposal\n";
  std::cout << "  blacklist add <peer>           Add peer to blacklist\n";
  std::cout << "  blacklist remove <peer>        Remove peer from blacklist\n";
  std::cout << "  stats                          View blockchain stats\n";
  std::cout << "  chain print [--json]           Print blockchain\n\n";
  std::cout << "  l2 vm selftest           Run L2 VM self-test\n";
  std::cout << "Options:\n";
  std::cout << "  --help                         Show this help message\n";
  std::cout << "  --version                      Show CLI version\n";
}

// Specific usage helpers
void printSendUsage() {
  std::cout << "Usage: alyncoin-cli send <l1|l2> <from> <to> <amount> <metadata>\n";
  std::cout << "Example: alyncoin-cli send l1 Alice Bob 10 note\n";
}

void printWalletUsage() {
  std::cout << "Usage: alyncoin-cli wallet <new|load|guardian|recover> ...\n";
  std::cout << "Examples:\n";
  std::cout << "  alyncoin-cli wallet new\n";
  std::cout << "  alyncoin-cli wallet load Alice\n";
  std::cout << "  alyncoin-cli wallet guardian list\n";
  std::cout << "  alyncoin-cli wallet recover status <id>\n";
}

int cliMain(int argc, char *argv[]);

static int handleWalletGuardian(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: alyncoin-cli wallet guardian <add|remove|list> [address]\n";
        return 1;
    }
    std::string current = getCurrentWallet();
    if (current.empty()) {
        std::cerr << "❌ No wallet loaded.\n";
        return 1;
    }
    std::string action = argv[1];
    if (action == "list" && argc == 2) {
        auto gs = WalletRecovery::listGuardians(current);
        for (const auto& g : gs) std::cout << g.address << "\n";
        return 0;
    } else if ((action == "add" || action == "remove") && argc == 3) {
        std::string addr = argv[2];
        if (action == "add") {
            GuardianInfo gi{addr, Crypto::sha256(addr)};
            WalletRecovery::addGuardian(current, gi);
        } else {
            WalletRecovery::removeGuardian(current, addr);
        }
        return 0;
    } else {
        std::cout << "Usage: alyncoin-cli wallet guardian <add|remove|list> [address]\n";
        return 1;
    }
}

static int handleWalletRecover(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: alyncoin-cli wallet recover <init|approve|status|finalize> ...\n";
        return 1;
    }
    std::string current = getCurrentWallet();
    if (current.empty()) {
        std::cerr << "❌ No wallet loaded.\n";
        return 1;
    }
    std::string action = argv[1];
    if (action == "init" && argc >= 3) {
        std::string newPass = argv[2];
        int m = 0, n = 0, lock = 0;
        for (int i = 3; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--m" && i + 1 < argc) m = std::stoi(argv[++i]);
            else if (a == "--n" && i + 1 < argc) n = std::stoi(argv[++i]);
            else if (a == "--lock" && i + 1 < argc) lock = std::stoi(argv[++i]);
        }
        auto intent = WalletRecovery::initRecovery(current, newPass, m, n, lock, current);
        Json::Value msg;
        msg["id"] = intent.id;
        msg["new_pass"] = intent.newPassHash;
        msg["m"] = intent.m;
        msg["n"] = intent.n;
        msg["lock_deadline"] = (Json::Int64)intent.lockDeadline;
        msg["initiator"] = intent.initiator;
        msg["timestamp"] = (Json::Int64)intent.timestamp;
        std::cout << Json::writeString(Json::StreamWriterBuilder(), msg) << std::endl;
        return 0;
    } else if (action == "approve" && argc >= 6) {
        std::string id = argv[2];
        std::string guardian; std::string sig;
        for (int i = 3; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--by" && i + 1 < argc) guardian = argv[++i];
            else if (a == "--sig" && i + 1 < argc) sig = argv[++i];
        }
        if (guardian.empty() || sig.empty()) {
            std::cerr << "Missing guardian or signature.\n";
            return 1;
        }
        WalletRecovery::approveRecovery(current, id, guardian, sig);
        return 0;
    } else if (action == "status" && argc == 3) {
        std::string id = argv[2];
        auto ri = WalletRecovery::getRecovery(current, id);
        if (!ri) { std::cerr << "Not found\n"; return 1; }
        Json::Value msg;
        msg["id"] = ri->id;
        msg["m"] = ri->m;
        msg["n"] = ri->n;
        msg["approvals"] = (int)ri->approvals.size();
        msg["lock_deadline"] = (Json::Int64)ri->lockDeadline;
        msg["finalized"] = ri->finalized;
        std::cout << Json::writeString(Json::StreamWriterBuilder(), msg) << std::endl;
        return 0;
    } else if (action == "finalize" && argc == 3) {
        std::string id = argv[2];
        if (WalletRecovery::finalizeRecovery(current, id)) {
            std::cout << "Finalized\n";
            return 0;
        }
        std::cerr << "Unable to finalize\n";
        return 1;
    }
    std::cout << "Usage: alyncoin-cli wallet recover <init|approve|status|finalize> ...\n";
    return 1;
}


int main(int argc, char **argv) {
    std::ios::sync_with_stdio(true);
    std::cout.setf(std::ios::unitbuf);
    if (argc == 1) {
        printHelp();
        std::_Exit(0);
    }

    std::string first = argv[1];
    if (first == "--help" || first == "-h") {
        printHelp();
        std::_Exit(0);
    }
    if (first == "--version") {
        std::cout << "alyncoin-cli " << CLI_VERSION << "\n";
        std::_Exit(0);
    }

    // Map friendly subcommands to legacy ones
    if (first == "wallet") {
        if (argc < 3) {
            printWalletUsage();
            std::_Exit(1);
        }
        std::string action = argv[2];
        if (action == "guardian") {
            std::_Exit(handleWalletGuardian(argc - 2, argv + 2));
        } else if (action == "recover") {
            std::_Exit(handleWalletRecover(argc - 2, argv + 2));
        } else if (action == "new" && argc == 3) {
            argv[1] = (char*)"createwallet";
            argc = 2;
        } else if (action == "load" && argc == 4) {
            argv[1] = (char*)"loadwallet";
            argv[2] = argv[3];
            argc = 3;
        } else {
            printWalletUsage();
            std::_Exit(1);
        }
    } else if (first == "send") {
        if (argc < 3) {
            printSendUsage();
            std::_Exit(1);
        }
        std::string layer = argv[2];
        if (layer != "l1" && layer != "l2") {
            printSendUsage();
            std::_Exit(1);
        }
        if (argc < 7) {
            printSendUsage();
            std::_Exit(1);
        }
        argv[1] = (char*)(layer == "l1" ? "sendl1" : "sendl2");
        for (int i = 3; i < argc; ++i) {
            argv[i - 1] = argv[i];
        }
        argc -= 1; // remove layer arg
    } else if (first == "dao") {
        if (argc < 3) {
            printHelp();
            std::_Exit(1);
        }
        std::string action = argv[2];
        if (action == "submit") {
            if (argc < 5) {
                std::cout << "Usage: alyncoin-cli dao submit <from> <desc> [type] [amount] [target]\n";
                std::cout << "Example: alyncoin-cli dao submit Alice 'upgrade network'\n";
                std::_Exit(1);
            }
            argv[1] = (char*)"dao-submit";
            for (int i = 3; i < argc; ++i) argv[i - 1] = argv[i];
            argc -= 1;
        } else if (action == "vote") {
            if (argc < 5) {
                std::cout << "Usage: alyncoin-cli dao vote <from> <id> <yes|no>\n";
                std::cout << "Example: alyncoin-cli dao vote Alice 1 yes\n";
                std::_Exit(1);
            }
            argv[1] = (char*)"dao-vote";
            for (int i = 3; i < argc; ++i) argv[i - 1] = argv[i];
            argc -= 1;
        } else if (action == "list" && argc == 3) {
            argv[1] = (char*)"dao-view";
            argc = 2;
        } else if (action == "finalize" && argc == 4) {
            argv[1] = (char*)"dao-finalize";
            argv[2] = argv[3];
            argc = 3;
        } else {
            printHelp();
            std::_Exit(1);
        }
    } else if (first == "policy") {
        if (argc < 3) {
            std::cout << "Usage: alyncoin-cli policy <set|show|clear|export|import> ...\n";
            std::_Exit(1);
        }
        std::string action = argv[2];
        if (action == "set") {
            argv[1] = (char*)"policy-set";
            for (int i = 3; i < argc; ++i) argv[i - 1] = argv[i];
            argc -= 1;
        } else if (action == "show" && argc == 3) {
            argv[1] = (char*)"policy-show"; argc = 2;
        } else if (action == "clear" && argc == 3) {
            argv[1] = (char*)"policy-clear"; argc = 2;
        } else if (action == "export" && argc == 4) {
            argv[1] = (char*)"policy-export"; argv[2] = argv[3]; argc = 3;
        } else if (action == "import" && argc == 4) {
            argv[1] = (char*)"policy-import"; argv[2] = argv[3]; argc = 3;
        } else {
            std::cout << "Usage: alyncoin-cli policy <set|show|clear|export|import> ...\n";
            std::_Exit(1);
        }
    } else if (first == "blacklist") {
        if (argc < 3) {
            std::cout << "Usage: alyncoin-cli blacklist <add|remove> <peer>\n";
            std::cout << "Example: alyncoin-cli blacklist add 1.2.3.4:15671\n";
            std::_Exit(1);
        }
        std::string action = argv[2];
        if ((action == "add" || action == "remove") && argc == 4) {
            argv[1] = (char*)(action == "add" ? "blacklist-add" : "blacklist-remove");
            argv[2] = argv[3];
            argc = 3;
        } else {
            std::cout << "Usage: alyncoin-cli blacklist <add|remove> <peer>\n";
            std::_Exit(1);
        }
    } else if (first == "chain" && argc >= 3 && std::string(argv[2]) == "print") {
        argv[1] = (char*)"chainprint"; // placeholder; handled later if implemented
        for (int i = 3; i < argc; ++i) argv[i - 1] = argv[i];
        argc -= 1;
    } else if (first == "l2" && argc >= 4 && std::string(argv[2]) == "vm" && std::string(argv[3]) == "selftest") {
        argv[1] = (char*)"l2-vm-selftest";
        argc = 2;
    }    }

    std::string keyDir = DBPaths::getKeyDir();

    // Helper to check command
    auto cmd = (argc >= 2) ? std::string(argv[1]) : "";
    auto isQuery =
        cmd == "balance" || cmd == "balance-force" ||
        cmd == "history" || cmd == "stats" ||
        cmd == "dao-view" || cmd == "mychain" ||
        cmd == "recursiveproof" ||
        cmd == "createwallet" || cmd == "loadwallet" ||
        cmd == "policy-set" || cmd == "policy-show" || cmd == "policy-clear" ||
        cmd == "policy-export" || cmd == "policy-import";

    // Helper: mining/send/rollup always need full DB+network
    auto isFullNet =
        cmd == "mine" || cmd == "mineonce" || cmd == "mineloop" ||
        cmd == "sendl1" || cmd == "sendl2" ||
        cmd == "dao-submit" || cmd == "dao-vote" || cmd == "dao-finalize" ||
        cmd == "rollup" || cmd == "recursive-rollup" ||
        // Peer connect if host:port in arg
        (cmd.find(':') != std::string::npos && cmd.find('.') != std::string::npos);

    // Unknown command guard
    {
        static const std::unordered_set<std::string> known = {
            "createwallet", "loadwallet", "balance", "balance-force", "sendl1",
            "sendl2", "mine", "mineonce", "mineloop", "rollup",
            "dao-submit", "dao-vote", "dao-view", "dao-finalize",
            "blacklist-add", "blacklist-remove", "stats", "chainprint", "history",
            "mychain", "recursiveproof", "recursive-rollup",
            "policy-set", "policy-show", "policy-clear", "policy-export", "policy-import", "l2-vm-selftest"};
        if (!cmd.empty() && known.find(cmd) == known.end()) {
            std::cerr << "Unknown command: " << cmd << "\n";
            printHelp();
            std::_Exit(1);
        }
    }

// ==== Robust CLI initialization block ====

// Helper for flags
auto hasFlag = [](int argc, char** argv, const std::string& flag) -> bool {
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == flag)
            return true;
    return false;
};

bool skipDB = hasFlag(argc, argv, "--nodb");
bool skipNet = hasFlag(argc, argv, "--nonetwork");

Blockchain* chainPtr = nullptr;
Network* network = nullptr;
std::unique_ptr<PeerBlacklist> peerBlacklistPtr;

// === Initialize Blockchain ===
if (skipDB) {
    std::cout << "⚠️ CLI is running in --nodb mode.\n";
    chainPtr = &Blockchain::getInstanceNoDB();
} else if (skipNet) {
    std::cout << "⚠️ CLI is running in --nonetwork mode (DB OK).\n";
    chainPtr = &Blockchain::getInstanceNoNetwork();
} else {
    std::cout << "🌐 CLI is using full network+DB mode.\n";
    chainPtr = &Blockchain::getInstance(15671, DBPaths::getBlockchainDB(), true);

    try {
        peerBlacklistPtr = std::make_unique<PeerBlacklist>(DBPaths::getBlacklistDB(), 3);
        network = &Network::getInstance(15671, chainPtr, peerBlacklistPtr.get());
    } catch (const std::exception& e) {
        std::cerr << "❌ Failed to initialize PeerBlacklist or Network: " << e.what() << "\n";
        peerBlacklistPtr = nullptr;
    }
}

// ✅ Make getBlockchain() available again
auto getBlockchain = [&]() -> Blockchain& {
    return *chainPtr;
};

Blockchain& b = *chainPtr; // Optional alias (used only in current scope, not elsewhere)


   // mineonce <minerAddress>
if (argc >= 3 && std::string(argv[1]) == "mineonce") {
    std::string minerAddress = argv[2];
    Blockchain &b = getBlockchain();

    if (!b.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    b.loadPendingTransactionsFromDB();
    std::cout << "⛏️ Mining single block for: " << minerAddress << "\n";
    Block minedBlock = b.mineBlock(minerAddress);

    if (!minedBlock.getHash().empty()) {
        b.saveToDB();
        b.reloadBlockchainState();
        if (!Network::isUninitialized()) {
            Network::getInstance().broadcastBlock(minedBlock);  // ✅ reuse existing Network instance
        }
        std::cout << "✅ Block mined by: " << minerAddress << "\n"
                  << "🧱 Block Hash: " << minedBlock.getHash() << "\n"
                  << "✅ Block added to chain.\n";
    } else {
        std::cerr << "⚠️ Mining failed.\n";
    }

    return 0;
}
// mineloop <minerAddress>
if (argc >= 3 && std::string(argv[1]) == "mineloop") {
    std::string minerAddress = argv[2];
    Blockchain &b = getBlockchain();  // ✅ uses correct Network + peerBlacklist

    if (!b.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    std::cout << "🔁 Starting mining loop for: " << minerAddress << "\n";
    while (true) {
        b.loadPendingTransactionsFromDB();
        Block minedBlock = b.mineBlock(minerAddress);

        if (!minedBlock.getHash().empty()) {
            b.saveToDB();

            try {
                b.reloadBlockchainState();
                if (!Network::isUninitialized()) {
                    Network::getInstance().broadcastBlock(minedBlock);  // ✅ no conflict
                }
            } catch (const std::exception &e) {
                std::cerr << "⚠️ reloadBlockchainState() skipped due to network error: " << e.what() << "\n";
            }

            std::cout << "✅ Block mined by: " << minerAddress << "\n"
                      << "🧱 Block Hash: " << minedBlock.getHash() << "\n";
        } else {
            std::cerr << "⚠️ Mining failed or no valid transactions.\n";
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
    // === DAO view ===
    if (cmd == "dao-view" && argc == 2) {
        auto proposals = DAOStorage::getAllProposals();
        std::cout << "\n=== DAO Proposals ===\n";
        for (const auto &p : proposals) {
            std::cout << "📜 ID: " << p.proposal_id << "\n";
            std::cout << "📝 Description: " << p.description << "\n";
            std::cout << "🛍 Type: " << static_cast<int>(p.type) << "\n";
            std::cout << "📅 Deadline: " << p.deadline_time << "\n";
            std::cout << "✅ YES: " << static_cast<uint64_t>(p.yes_votes) << " | ❌ NO: " << static_cast<uint64_t>(p.no_votes) << "\n";
            std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
        }
        return 0;
    }
    // === Blockchain stats ===
    if (cmd == "l2-vm-selftest") {
        static const uint8_t wasm[]={0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,9,1,5,101,110,116,114,121,0,0,10,6,1,4,0,65,0,11};
        WasmEngine eng;
        auto mod = eng.load(std::vector<uint8_t>(wasm, wasm + sizeof(wasm)));
        auto inst = eng.instantiate(mod, 1000000, 64*1024);
        auto res = eng.call(inst, "entry", {});
        std::cout << (res.retcode == 0 ? "OK" : "FAIL") << "\n";
        return res.retcode;
    }
    if (cmd == "stats" && argc >= 2) {
        std::cout << "\n=== Blockchain Stats ===\n";
        std::cout << "Total Blocks: " << b.getBlockCount() << "\n";
        std::cout << "Difficulty: " << calculateSmartDifficulty(b) << "\n";
        std::cout << "Total Supply: " << b.getTotalSupply() << " AlynCoin\n";
        std::cout << "Total Burned Supply: " << b.getTotalBurnedSupply() << " AlynCoin\n";
        std::cout << "Dev Fund Balance: " << b.getBalance("DevFundWallet") << " AlynCoin\n";
        return 0;
    }
    if (cmd == "chainprint") {
        Blockchain &bc = getBlockchain();
        bool skipDB = hasFlag(argc, argv, "--nodb");
        if (!skipDB) {
            bc.reloadBlockchainState();
        } else if (bc.getChain().empty()) {
            bc.createGenesisBlock(true);
        }
        bool jsonOut = hasFlag(argc, argv, "--json");
        const auto &chain = bc.getChain();
        if (jsonOut) {
            Json::Value arr(Json::arrayValue);
            for (const auto &blk : chain) {
                pretty::BlockInfo bi{blk.getIndex(), static_cast<uint64_t>(blk.getTimestamp()), blk.getMinerAddress(), blk.getPreviousHash(), blk.getHash(), blk.getTransactions().size(), 0};
                Json::StreamWriterBuilder bld; bld["indentation"] = "";
                bi.sizeEstimate = Json::writeString(bld, blk.toJSON()).size();
                Json::Value bj;
                bj["height"] = bi.height;
                bj["timestamp"] = pretty::formatTimestampISO(bi.timestamp);
                bj["miner"] = bi.miner;
                bj["prev_hash"] = pretty::shortenHash(bi.prevHash);
                bj["hash"] = pretty::shortenHash(bi.hash);
                bj["tx_count"] = static_cast<Json::UInt64>(bi.txCount);
                bj["size_estimate"] = static_cast<Json::UInt64>(bi.sizeEstimate);
                Json::Value txs(Json::arrayValue);
                const auto &blockTxs = blk.getTransactions();
                for (size_t i = 0; i < blockTxs.size(); ++i) {
                    const auto &tx = blockTxs[i];
                    Json::Value tj;
                    tj["index"] = static_cast<Json::UInt64>(i);
                    tj["from"] = tx.getSender();
                    tj["to"] = tx.getRecipient();
                    tj["amount"] = tx.getAmount();
                    tj["fee"] = pretty::estimateFee(tx.getAmount());
                    tj["nonce"] = static_cast<Json::UInt64>(tx.getTimestamp());
                    tj["type"] = tx.isL2() ? "L2" : "L1";
                    tj["status"] = "confirmed";
                    txs.append(tj);
                }
                bj["transactions"] = txs;
                arr.append(bj);
            }
            Json::StreamWriterBuilder w; w["indentation"] = "";
            std::cout << Json::writeString(w, arr) << "\n";
        } else {
            for (const auto &blk : chain) {
                pretty::BlockInfo bi{blk.getIndex(), static_cast<uint64_t>(blk.getTimestamp()), blk.getMinerAddress(), blk.getPreviousHash(), blk.getHash(), blk.getTransactions().size(), 0};
                Json::StreamWriterBuilder bld; bld["indentation"] = "";
                bi.sizeEstimate = Json::writeString(bld, blk.toJSON()).size();
                std::cout << pretty::formatBlock(bi) << "\n";
                const auto &blockTxs = blk.getTransactions();
                for (size_t i = 0; i < blockTxs.size(); ++i) {
                    const auto &tx = blockTxs[i];
                    pretty::TxInfo ti{i, tx.getSender(), tx.getRecipient(), tx.getAmount(), pretty::estimateFee(tx.getAmount()), static_cast<uint64_t>(tx.getTimestamp()), tx.isL2() ? "L2" : "L1", "confirmed"};
                    std::cout << "  " << pretty::formatTx(ti) << "\n";
                }
            }
        }
        return 0;
    }
    if (cmd == "listpeers" && argc >= 2) {
        PeerManager *pm = network ? network->getPeerManager() : nullptr;
        if (!pm) {
            std::cout << "No peers connected.\n";
        } else {
            auto peers = pm->getConnectedPeers();
            std::cout << "Connected peers (" << peers.size() << "):\n";
            for (const auto &p : peers)
                std::cout << " - " << p << "\n";
        }
        return 0;
    }
    // Wallet create/load
    if (cmd == "createwallet" && argc == 2) {
        std::string name;
        do {
            name = Crypto::generateRandomHex(40);
        } while (std::filesystem::exists(keyDir + name + "_private.pem"));

        std::string pass;
        std::cout << "Set passphrase (leave blank for none): ";
        std::getline(std::cin >> std::ws, pass);
        if (!pass.empty() && pass.size() < 12) {
            std::cerr << "⚠️ Passphrase must be at least 12 characters.\n";
            return 1;
        }
        if (!pass.empty()) {
            std::string confirm;
            std::cout << "Confirm passphrase: ";
            std::getline(std::cin, confirm);
            if (pass != confirm) {
                std::cerr << "❌ Passphrases do not match.\n";
                return 1;
            }
        }

        try {
            Wallet w(name, keyDir, pass);
            if (!pass.empty()) {
                std::ofstream(keyDir + name + "_pass.txt")
                    << Crypto::sha256(pass);
            }
            std::cout << "✅ Wallet created: " << w.getAddress() << "\n";
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet creation failed: " << e.what() << "\n";
            return 1;
        }
        return 0;
    }
    if (cmd == "loadwallet" && argc == 3) {
        std::string name = argv[2];
        std::string priv = keyDir + name + "_private.pem";
        std::string dil = keyDir + name + "_dilithium.key";
        std::string fal = keyDir + name + "_falcon.key";
        std::string passPath = keyDir + name + "_pass.txt";
        if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) || !std::filesystem::exists(fal)) {
            std::cerr << "❌ Wallet key files not found for: " << name << std::endl;
            return 1;
        }
        std::string pass;
        std::cout << "Enter passphrase (leave blank if none): ";
        std::getline(std::cin >> std::ws, pass);
        if (std::filesystem::exists(passPath)) {
            std::ifstream pin(passPath);
            std::string stored;
            std::getline(pin, stored);
            if (Crypto::sha256(pass) != stored) {
                std::cerr << "❌ Incorrect passphrase\n";
                return 1;
            }
        }
        try {
            Wallet w(priv, keyDir, name, pass);
            std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt") << w.getAddress();
            std::cout << "✅ Wallet loaded: " << w.getAddress() << std::endl;
        } catch (const std::exception &e) {
            std::cerr << "❌ Wallet load failed: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

// === Balance check (normal or forced) ===
    if ((cmd == "balance" || cmd == "balance-force") && argc >= 3) {
        std::string addr = argv[2];
        // Use the no-network singleton to avoid DB locks
        Blockchain &bb = *chainPtr;
        if (cmd == "balance-force") bb.reloadBlockchainState();
        std::cout << "Balance: " << bb.getBalance(addr) << " AlynCoin" << std::endl;
        return 0;
    }
    // === Policy commands ===
    if (cmd == "policy-show" && argc == 2) {
        std::string addr = getCurrentWallet();
        Policy p = PolicyManager::load(addr);
        std::cout << Json::writeString(Json::StreamWriterBuilder(), p.toJson()) << std::endl;
        return 0;
    }
    if (cmd == "policy-clear" && argc == 2) {
        std::string addr = getCurrentWallet();
        PolicyManager::clear(addr);
        std::cout << "Policy cleared\n";
        return 0;
    }
    if (cmd == "policy-export" && argc == 3) {
        std::string addr = getCurrentWallet();
        PolicyManager::exportPolicy(addr, argv[2]);
        std::cout << "Policy exported\n";
        return 0;
    }
    if (cmd == "policy-import" && argc == 3) {
        std::string addr = getCurrentWallet();
        PolicyManager::importPolicy(addr, argv[2]);
        std::cout << "Policy imported\n";
        return 0;
    }
    if (cmd == "policy-set" && argc >= 2) {
        std::string addr = getCurrentWallet();
        Policy p = PolicyManager::load(addr);
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--multisig" && i + 1 < argc) {
                std::string val = argv[++i];
                size_t pos = val.find("-of-");
                if (pos != std::string::npos) {
                    p.m = std::stoi(val.substr(0, pos));
                    p.n = std::stoi(val.substr(pos + 4));
                }
            } else if (arg == "--daily" && i + 1 < argc) {
                p.daily_limit = std::stod(argv[++i]);
            } else if (arg == "--allow" && i + 1 < argc) {
                p.allowlist.clear();
                std::string list = argv[++i];
                std::stringstream ss(list); std::string item;
                while (std::getline(ss, item, ',')) if(!item.empty()) p.allowlist.push_back(item);
            } else if (arg == "--lock-large" && i + 1 < argc) {
                std::string v = argv[++i];
                size_t colon = v.find(':');
                if (colon != std::string::npos) {
                    p.lock_threshold = std::stod(v.substr(0, colon));
                    p.lock_minutes = std::stoi(v.substr(colon + 1));
                }
            }
        }
        PolicyManager::save(addr, p);
        std::cout << "Policy saved\n";
        return 0;
    }
// === sendl1 / sendl2 with duplicate filter ===
if ((argc >= 6) && (std::string(argv[1]) == "sendl1" || std::string(argv[1]) == "sendl2")) {
    std::string from = argv[2];
    std::string to = argv[3];
    std::string rawAmount = argv[4];
    std::string metadata = argv[5];
    std::vector<std::string> cosigners;
    for (int i = 6; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--cosign" && i + 1 < argc) {
            std::string list = argv[++i];
            std::stringstream ss(list); std::string item;
            while (std::getline(ss, item, ',')) if(!item.empty()) cosigners.push_back(item);
        }
    }

    double amount = -1;
    try {
        amount = std::stod(rawAmount);
    } catch (...) {
        std::cerr << "❌ Invalid amount format: " << rawAmount << "\n";
        return 1;
    }

    // ✅ Allow zero amount only for metadataSink transactions
    if (amount <= 0.0 && to != "metadataSink") {
        std::cerr << "❌ Invalid amount. Zero allowed only when sending to metadataSink.\n";
        return 1;
    }

    Blockchain &b = getBlockchain();

    std::string policyErr;
    if (!PolicyManager::checkSend(from, to, amount, cosigners, policyErr)) {
        std::cerr << "❌ " << policyErr << "\n";
        return 1;
    }
    // ✅ Skip balance check if it's metadata-only (to metadataSink with 0.0)
    if (!(amount == 0.0 && to == "metadataSink")) {
        double currentBalance = b.getBalance(from);
        if (amount > currentBalance) {
            std::cerr << "❌ Insufficient balance. You have " << currentBalance
                      << " AlynCoin, but tried to send " << amount << ".\n";
            return 1;
        }
    }

    auto dil = Crypto::loadDilithiumKeys(from);
    auto fal = Crypto::loadFalconKeys(from);

    Transaction tx(from, to, amount, "", metadata, time(nullptr));
    if (std::string(argv[1]) == "sendl2") {
        tx.setMetadata("L2:" + metadata);
    }

    // Hash-based deduplication for CLI too (mirrors network, prevents resending on retry)
    std::string txHash = tx.getHash();
    if (cliSeenTxHashes.count(txHash)) {
        std::cerr << "⚠️ Transaction already submitted by this CLI session (hash dedupe).\n";
        return 1;
    }

    for (const auto& existing : b.getPendingTransactions()) {
        if (existing.getSender() == tx.getSender() &&
            existing.getRecipient() == tx.getRecipient() &&
            existing.getAmount() == tx.getAmount() &&
            existing.getMetadata() == tx.getMetadata()) {
            std::cerr << "⚠️ Duplicate transaction already exists in mempool.\n";
            return 1;
        }
    }
    cliSeenTxHashes.insert(txHash);

    tx.signTransaction(dil.privateKey, fal.privateKey);
    if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
        b.addTransaction(tx);
        b.savePendingTransactionsToDB();
        if (!Network::isUninitialized()) {
            Network::getInstance().broadcastTransaction(tx);
        }
        PolicyManager::recordSpend(from, amount);
        std::cout << "✅ Transaction broadcasted: " << from << " → " << to

                  << " (" << amount << " AlynCoin, metadata: " << metadata << ")\n";
    } else {
        std::cerr << "❌ Transaction signing failed.\n";
        return 1;
    }

    std::exit(0);
}
    // === DAO proposal submission ===
    if (argc >= 4 && std::string(argv[1]) == "dao-submit") {
        std::string from = argv[2];
        std::string desc = argv[3];
        ProposalType type = ProposalType::CUSTOM_ACTION;
        double amt = (argc >= 6) ? std::stod(argv[5]) : 0.0;
        std::string target = (argc >= 7) ? argv[6] : "";
        if (argc >= 5) type = static_cast<ProposalType>(std::stoi(argv[4]));

        std::string policyErr;
        if (!PolicyManager::checkSend(from, target, amt, {}, policyErr)) {
            std::cerr << "❌ " << policyErr << "\n";
            return 1;
        }

        Proposal prop;
        prop.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
        prop.proposer_address = from;
        prop.description = desc;
        prop.type = type;
        prop.transfer_amount = amt;
        prop.target_address = target;
        prop.creation_time = std::time(nullptr);
        prop.deadline_time = prop.creation_time + 86400;
        prop.status = ProposalStatus::PENDING;

        if (DAO::createProposal(prop)) {
            std::cout << "✅ Proposal submitted. ID: " << prop.proposal_id << "\n";
            if (amt > 0) PolicyManager::recordSpend(from, amt);
        } else {
            std::cerr << "❌ Failed to submit proposal.\n";
        }
        std::exit(0);
    }

    // === DAO voting ===
    if (argc >= 5 && std::string(argv[1]) == "dao-vote") {
        std::string from = argv[2];
        std::string propID = argv[3];
        std::string vote = argv[4];
        bool yes = (vote == "yes" || vote == "y");

        Blockchain &b = getBlockchain();
        double weight = b.getBalance(from);
        if (DAO::castVote(propID, from, yes, static_cast<uint64_t>(weight))) {
            std::cout << "✅ Vote cast!\n";
        } else {
            std::cerr << "❌ Failed to vote.\n";
        }
        std::exit(0);
    }

    // === DAO finalize ===
    if (argc >= 3 && std::string(argv[1]) == "dao-finalize") {
        std::string propID = argv[2];
        if (DAO::finalizeProposal(propID)) {
            std::cout << "✅ Proposal finalized.\n";
            std::exit(0);
        } else {
            std::cerr << "❌ Failed to finalize proposal.\n";
            std::exit(1);
        }
    }

  // === Transaction history ===
    if (cmd == "history" && argc >= 3) {
        std::string addr = argv[2];
        Blockchain& bb = Blockchain::getInstanceNoNetwork();
        std::cout << "🔍 Loading blockchain from DB...\n";
        bb.loadFromDB();
        bb.reloadBlockchainState();
        std::vector<Transaction> relevant;
        std::unordered_map<std::string, std::string> txType;
        std::unordered_set<std::string> seen;
        auto toLower = [](std::string s) {
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return s;
        };
        std::string addrLower = toLower(addr);
        auto blocks = bb.getAllBlocks();
        for (const auto& blk : blocks) {
            std::string blockMiner = toLower(blk.getMinerAddress());
            double reward = blk.getReward();
            for (const auto& tx : blk.getTransactions()) {
                std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
                if (!seen.count(hash) &&
                    (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                    relevant.push_back(tx);
                    txType[hash] = "L1";
                    seen.insert(hash);
                }
            }
            if (blockMiner == addrLower && reward > 0.0) {
                Transaction rewardTx = Transaction::createSystemRewardTransaction(
                    blk.getMinerAddress(), reward, blk.getTimestamp(), "mined_" + blk.getHash());
                std::string rewardHash = rewardTx.getHash();
                if (!seen.count(rewardHash)) {
                    relevant.push_back(rewardTx);
                    txType[rewardHash] = "Mined";
                    seen.insert(rewardHash);
                }
            }
        }
        auto rollups = bb.getAllRollupBlocks();
        for (const auto& roll : rollups) {
            for (const auto& tx : roll.getTransactions()) {
                std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
                if (!seen.count(hash) &&
                    (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                    relevant.push_back(tx);
                    txType[hash] = "L2";
                    seen.insert(hash);
                }
            }
        }
        auto allTxs = Transaction::loadAllFromDB();
        for (const auto& tx : allTxs) {
            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            if (!seen.count(hash) &&
                (toLower(tx.getSender()) == addrLower || toLower(tx.getRecipient()) == addrLower)) {
                relevant.push_back(tx);
                txType[hash] = "L1";
                seen.insert(hash);
            }
        }
        std::sort(relevant.begin(), relevant.end(), [](const Transaction& a, const Transaction& b) {
            return a.getTimestamp() < b.getTimestamp();
        });
        std::cout << "\n=== Transaction History for: " << addr << " ===\n";
        std::cout << "📜 Found " << relevant.size() << " related transactions.\n\n";
        for (const auto& tx : relevant) {
            std::string hash = tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            std::string type = txType.count(hash) ? txType[hash] : "Unknown";
            time_t ts = tx.getTimestamp();
            std::tm* tmPtr = std::localtime(&ts);
            char timeStr[64];
            std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tmPtr);
            std::cout << "🕒 " << timeStr << " [" << type << "]\n"
                    << "From: " << tx.getSender() << "\n"
                    << "To:   " << tx.getRecipient() << "\n"
                    << "💰 Amount: " << tx.getAmount() << " AlynCoin\n";
            if (!tx.getMetadata().empty()) std::cout << "📎 Metadata: " << tx.getMetadata() << "\n";
            std::cout << "🔑 TxHash: " << hash << "\n"
                    << "------------------------------\n";
        }
        return 0;
    }

	// === Recursive zk-STARK Proof by address (GUI / filtered) ===
	if (argc >= 5 && std::string(argv[1]) == "recursiveproof") {
	    std::string addr = argv[2];
	    int count = 0;
	    std::string outputFile;

	    for (int i = 3; i < argc; ++i) {
	        std::string arg = argv[i];
	        if (arg == "--last" && i + 1 < argc) {
	            try {
	                count = std::stoi(argv[++i]);
	            } catch (...) {
	                std::cerr << "❌ Invalid --last argument.\n";
	                return 1;
	            }
	        } else if (arg == "--out" && i + 1 < argc) {
	            outputFile = argv[++i];
	        }
	    }

	    if (addr.empty() || count <= 0) {
	        std::cerr << "❌ Invalid address or --last count.\n";
	        return 1;
	    }

	    Blockchain& b = getBlockchain();
	    b.loadFromDB();  // ensure block list is populated
	    b.reloadBlockchainState();

	    std::vector<std::string> hashes;
	    int selected = 0;

	    auto blocks = b.getAllBlocks();
	    for (auto it = blocks.rbegin(); it != blocks.rend() && selected < count; ++it) {
	        auto txs = it->getTransactions();
	        for (const auto& tx : txs) {
	            if (selected >= count) break;
	            if (tx.getSender() == addr || tx.getRecipient() == addr) {
	                hashes.push_back(tx.getHash());
	                selected++;
	            }
	        }
	    }

	    if (hashes.empty()) {
	        std::cout << "⚠️ No transactions found for " << addr << ".\n";
	        return 0;
	    }

	    std::string result = generateRecursiveProofToFile(hashes, addr, selected, outputFile);
	    std::cout << result << "\n";
	    return 0;
	}

    // === Mined block stats ===
    if (argc == 3 && std::string(argv[1]) == "mychain") {
        std::string addr = argv[2];
        Blockchain &b = getBlockchain();
        int count = 0;
        double reward = 0.0;
        for (const auto &blk : b.getAllBlocks()) {
            if (blk.getMinerAddress() == addr) {
                count++;
                reward += blk.getReward();
            }
        }
        std::cout << "📦 Blocks mined: " << count << "\n";
        std::cout << "💰 Total rewards: " << reward << " AlynCoin\n";
        std::exit(0);
    }

       // === CLI mining support ===
   if (argc == 3 && std::string(argv[1]) == "mine") {
     std::string minerAddr = argv[2];
     auto dil = Crypto::loadDilithiumKeys(minerAddr);
     auto fal = Crypto::loadFalconKeys(minerAddr);

     Blockchain &b = getBlockchain();
     Block mined = b.minePendingTransactions(minerAddr, dil.privateKey, fal.privateKey);

     if (mined.getHash().empty()) {
         std::cerr << "❌ Mining failed or returned empty block.\n";
         return 1;
     }

     b.saveToDB();
     std::cout << "✅ Block mined! Hash: " << mined.getHash() << "\n";
     std::exit(0);
 }

// === ROLLUP ===
if (argc >= 3 && std::string(argv[1]) == "rollup") {
    std::string walletAddr = argv[2];
    Blockchain& blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout << "🔁 Generating Normal Rollup Block...\n";

    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
        return 0;
    }

    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(
        blockchain.getRollupChainSize(),
        blockchain.getLastRollupHash(),
        l2Transactions
    );

    std::string prevRecursive = blockchain.getLastRollupProof();
    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

    if (blockchain.isRollupBlockValid(rollup)) {
        blockchain.addRollupBlock(rollup);
	if (!Network::isUninitialized()) {
    	Network::getInstance().broadcastRollupBlock(rollup);
	}
        std::cout << "✅ Rollup Block created successfully!\n";
        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
    } else {
        std::cerr << "❌ Rollup Block creation failed: Proof invalid.\n";
    }

    return 0;
}

// === RECURSIVE ROLLUP ===
if (argc >= 3 && std::string(argv[1]) == "recursive-rollup") {
    std::string walletAddr = argv[2];
    Blockchain& blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
        std::cerr << "❌ Could not load blockchain from DB.\n";
        return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout << "🔁 Generating Rollup Block with Recursive zk-STARK Proof...\n";

    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
        return 0;
    }

    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(
        blockchain.getRollupChainSize(),
        blockchain.getLastRollupHash(),
        l2Transactions
    );

    std::string prevRecursive = blockchain.getLastRollupProof();
    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

    if (blockchain.isRollupBlockValid(rollup)) {
        blockchain.addRollupBlock(rollup);
	if (!Network::isUninitialized()) {
	    Network::getInstance().broadcastRollupBlock(rollup);
	}
        std::cout << "✅ Recursive Rollup Block created successfully!\n";
        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
    } else {
        std::cerr << "❌ Recursive Rollup Block creation failed: Proof invalid.\n";
    }

    return 0;
}

   if (cmd.find(':') != std::string::npos && cmd.find('.') != std::string::npos && argc == 2) {
        std::string ip = cmd.substr(0, cmd.find(':'));
        int port = std::stoi(cmd.substr(cmd.find(':') + 1));
        Blockchain& b = getBlockchain();
        if (!Network::isUninitialized()) {
            Network& net = Network::getInstance();
            if (net.connectToNode(ip, port)) {
                std::cout << "✅ Connected to peer " << cmd << "\n";
            } else {
                std::cerr << "❌ Could not connect to peer: " << cmd << "\n";
            }
        } else {
            std::cerr << "❌ Network not initialized.\n";
        }
        return 0;
    }
// ✅ Final fallback to interactive CLI if no recognized args
return cliMain(argc, argv);
}

int cliMain(int argc, char *argv[]) {
  unsigned short port = 15671;
  std::string dbPath = DBPaths::getBlockchainDB();
  std::string connectPeer = "";
  std::string keyDir = DBPaths::getKeyDir();
  std::string blacklistPath = DBPaths::getBlacklistDB();
  bool skipNetwork = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--dbpath" && i + 1 < argc) {
      dbPath = argv[++i];
    } else if (arg == "--connect" && i + 1 < argc) {
      connectPeer = argv[++i];
    } else if (arg == "--keypath" && i + 1 < argc) {
      keyDir = argv[++i];
      if (keyDir.back() != '/') keyDir += '/';
      std::cout << "Using custom key directory: " << keyDir << std::endl;
     } else if (arg == "--nonetwork") {
        skipNetwork = true;
        std::cout << "⚙️  Network disabled via --nonetwork flag.\n";

    } else {
      try {
        port = std::stoi(arg);
        std::cout << "Using custom port: " << port << std::endl;
      } catch (...) {
        std::cerr << "Unknown argument ignored: " << arg << "\n";
      }
    }
  }

  Wallet *wallet = nullptr;
  Blockchain &blockchain = Blockchain::getInstance();
  PeerBlacklist peerBlacklist(blacklistPath, 3);

  Network *network = nullptr;
  if (!skipNetwork) {
  network = &Network::getInstance(port, &blockchain, &peerBlacklist);
  }

  if (!connectPeer.empty()) {
    size_t colonPos = connectPeer.find(':');
    if (colonPos != std::string::npos) {
      std::string ip = connectPeer.substr(0, colonPos);
      int peerPort = std::stoi(connectPeer.substr(colonPos + 1));
      if (!network->connectToNode(ip, peerPort)) {
        std::cerr << "Failed to connect to AlynCoin node at " << connectPeer << "\n";
      } else {
        std::cout << "Connected to AlynCoin Node at " << connectPeer << "\n";
      }
    }
  }

  bool running = true;
  while (running) {
    printMenu();
    int choice;
    std::cin >> choice;

    if (std::cin.fail()) {
      std::cin.clear();
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      std::cout << "Invalid input. Please enter a valid option.\n";
      continue;
    }

    switch (choice) {
    case 1: {
      // Always generate a new wallet with a random, unique address
      std::cout << "🔐 Generating new wallet...\n";
      std::string derivedAddress;
      while (true) {
        std::string tempID = Crypto::generateRandomHex(12);
        std::string privPem = Crypto::generatePrivateKey(tempID, "unused");
        std::string pubPem = Crypto::getPublicKey(tempID);
        derivedAddress = Crypto::generateAddress(pubPem);

        std::string privPath = keyDir + derivedAddress + "_private.pem";
        if (!std::filesystem::exists(privPath)) {
          std::ofstream(privPath) << privPem;
          std::ofstream(keyDir + derivedAddress + "_public.pem") << pubPem;
          break;
        }
      }

      std::string pass;
      std::cout << "Set passphrase (leave blank for none): ";
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      std::getline(std::cin, pass);
      if (!pass.empty() && pass.size() < 8) {
        std::cerr << "⚠️ Passphrase must be at least 8 characters.\n";
        break;
      }
      if (!pass.empty()) {
        std::string confirm;
        std::cout << "Confirm passphrase: ";
        std::getline(std::cin, confirm);
        if (pass != confirm) {
          std::cerr << "❌ Passphrases do not match.\n";
          break;
        }
      }

      if (wallet) delete wallet;
      try {
        wallet = new Wallet(derivedAddress, keyDir, pass);
        if (!pass.empty()) {
          std::ofstream(keyDir + derivedAddress + "_pass.txt") << Crypto::sha256(pass);
        }
        std::cout << "✅ New wallet created!\nAddress: " << wallet->getAddress() << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "❌ Wallet creation failed: " << e.what() << std::endl;
        wallet = nullptr;
      }
      break;
    }

    case 2: {
      std::string walletAddress;
      std::cout << "Enter wallet address to load: ";
      std::cin >> walletAddress;

      std::string privPath = keyDir + walletAddress + "_private.pem";
      std::string dilPath = keyDir + walletAddress + "_dilithium.key";
      std::string falPath = keyDir + walletAddress + "_falcon.key";
      std::string passPath = keyDir + walletAddress + "_pass.txt";

      if (!std::filesystem::exists(privPath) || !std::filesystem::exists(dilPath) || !std::filesystem::exists(falPath)) {
        std::cerr << "❌ Missing required key files for wallet: " << walletAddress << "\n";
        break;
      }

      std::string pass;
      std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
      std::cout << "Enter passphrase (leave blank if none): ";
      std::getline(std::cin, pass);
      if (std::filesystem::exists(passPath)) {
        std::ifstream pin(passPath);
        std::string stored;
        std::getline(pin, stored);
        if (Crypto::sha256(pass) != stored) {
          std::cerr << "❌ Incorrect passphrase\n";
          break;
        }
      }

      if (wallet) delete wallet;
      try {
        wallet = new Wallet(privPath, keyDir, walletAddress, pass);
        std::cout << "✅ Wallet loaded successfully!\nAddress: " << wallet->getAddress() << std::endl;
      } catch (const std::exception &e) {
        std::cerr << "❌ Wallet loading failed: " << e.what() << std::endl;
        wallet = nullptr;
      }
      break;
    }

    case 3: {
      if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
      }
      std::cout << "Checking balance for: " << wallet->getAddress() << "\n";
      std::cout << "Balance: " << blockchain.getBalance(wallet->getAddress()) << " AlynCoin\n";
      break;
    }

	case 4: {  // 🔁 Send L1 Transaction
	    if (!wallet) {
	        std::cout << "❌ Load or create a wallet first!\n";
	        break;
	    }

	    std::string recipient;
	    double amount;
	    std::cout << "Enter recipient address: ";
	    std::cin >> recipient;
	    std::cout << "Enter amount: ";
	    std::cin >> amount;

	    if (recipient.empty() || amount <= 0) {
	        std::cout << "❌ Invalid input. Address must not be empty and amount must be positive.\n";
	        break;
	    }

	    double currentBalance = blockchain.getBalance(wallet->getAddress());
	    if (amount > currentBalance) {
	        std::cout << "❌ Insufficient balance. You have " << currentBalance << " AlynCoin, but tried to send " << amount << ".\n";
	        break;
	    }

	    std::string sender = wallet->getAddress();
	    auto dilPriv = Crypto::loadDilithiumKeys(sender);
	    auto falPriv = Crypto::loadFalconKeys(sender);

	    Transaction tx(sender, recipient, amount, "", "", time(nullptr));
	    std::cout << "[DEBUG] signTransaction() called for sender: " << sender << "\n";
	    tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

	    // === New: Deduplication block (session-level and mempool) ===
	    std::string txHash = tx.getHash();
	    if (cliSeenTxHashes.count(txHash)) {
	        std::cerr << "⚠️ Transaction already submitted by this CLI session (hash dedupe).\n";
	        break;
	    }
	    for (const auto& existing : blockchain.getPendingTransactions()) {
	        if (existing.getSender() == tx.getSender() &&
	            existing.getRecipient() == tx.getRecipient() &&
	            existing.getAmount() == tx.getAmount() &&
	            existing.getMetadata() == tx.getMetadata()) {
	            std::cerr << "⚠️ Duplicate transaction already exists in mempool.\n";
	            break;
	        }
	    }
	    cliSeenTxHashes.insert(txHash);

	    if (!tx.getSignatureDilithium().empty() && !tx.getSignatureFalcon().empty()) {
	        blockchain.addTransaction(tx);
	        std::cout << "📦 [DEBUG] Saving pending transactions to RocksDB...\n";
	        blockchain.savePendingTransactionsToDB();
	        if (network) network->broadcastTransaction(tx);
	        std::cout << "✅ Transactions successfully saved to RocksDB.\n";
	        std::cout << "✅ Transaction created and broadcasted!\n";
	    } else {
	        std::cerr << "❌ Signature failure. Transaction not broadcasted.\n";
	    }

	    break;
	}

	case 5: {  // 🔁 Send L2 Transaction
	    if (!wallet) {
	        std::cout << "❌ Load or create a wallet first!\n";
	        break;
	    }

	    std::string recipient;
	    double amount;
	    std::cout << "Enter recipient address (L2): ";
	    std::cin >> recipient;
	    std::cout << "Enter amount: ";
	    std::cin >> amount;

	    if (recipient.empty() || amount <= 0) {
	        std::cout << "❌ Invalid input. Address must not be empty and amount must be positive.\n";
	        break;
	    }

	    double currentBalance = blockchain.getBalance(wallet->getAddress());
	    if (amount > currentBalance) {
	        std::cout << "❌ Insufficient balance. You have " << currentBalance << " AlynCoin, but tried to send " << amount << ".\n";
	        break;
	    }

	    std::string sender = wallet->getAddress();
	    auto dilPriv = Crypto::loadDilithiumKeys(sender);
	    auto falPriv = Crypto::loadFalconKeys(sender);

	    Transaction tx(sender, recipient, amount, "", "", time(nullptr));
	    tx.setMetadata("L2");

	    std::cout << "[DEBUG] signTransaction() called for sender: " << sender << "\n";
	    tx.signTransaction(dilPriv.privateKey, falPriv.privateKey);

	    // === New: Deduplication block (session-level and mempool) ===
	    std::string txHash = tx.getHash();
	    if (cliSeenTxHashes.count(txHash)) {
	        std::cerr << "⚠️ Transaction already submitted by this CLI session (hash dedupe).\n";
	        break;
	    }
	    for (const auto& existing : blockchain.getPendingTransactions()) {
	        if (existing.getSender() == tx.getSender() &&
	            existing.getRecipient() == tx.getRecipient() &&
	            existing.getAmount() == tx.getAmount() &&
	            existing.getMetadata() == tx.getMetadata()) {
	            std::cerr << "⚠️ Duplicate transaction already exists in mempool.\n";
	            break;
	        }
	    }
	    cliSeenTxHashes.insert(txHash);

	    if (tx.getSignatureDilithium().empty() || tx.getSignatureFalcon().empty()) {
	        std::cerr << "❌ Signature failure. L2 Transaction not broadcasted.\n";
	        break;
	    }

	    std::string seed = sender + recipient + std::to_string((int)amount) + std::to_string(tx.getTimestamp());
	    std::string proof = WinterfellStark::generateProof(tx.getHash(), tx.getHash(), seed);
	    if (proof.empty()) {
	        std::cerr << "❌ [ERROR] zk-STARK proof generation failed!\n";
	        break;
	    }

	    tx.setZkProof(proof);
	    blockchain.addTransaction(tx);
	    std::cout << "📦 [DEBUG] Saving pending transactions to RocksDB...\n";
	    blockchain.savePendingTransactionsToDB();
	    if (network) network->broadcastTransaction(tx);
	    std::cout << "✅ Transactions successfully saved to RocksDB.\n";
	    std::cout << "✅ L2 Transaction created and broadcasted!\n";
	    break;
	}

    case 6: {
      if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
      }

      std::string addr = wallet->getAddress();
      auto dilPriv = Crypto::loadDilithiumKeys(addr);
      auto falPriv = Crypto::loadFalconKeys(addr);

      std::cout << "Starting mining with address: " << addr << std::endl;
      Block mined = blockchain.minePendingTransactions(addr, dilPriv.privateKey, falPriv.privateKey);

      if (mined.getHash().empty()) {
        std::cout << "❌ Mining failed or returned empty block.\n";
      } else {
        blockchain.saveToDB();
        if (network) {
 	   network->broadcastBlock(mined);
	}
	std::cout << "✅ Block mined! Hash: " << mined.getHash() << std::endl;
      }
      break;
    }

    case 7:
      std::cout << "=== AlynCoin Blockchain ===\n";
      std::cout << Json::writeString(Json::StreamWriterBuilder(), blockchain.toJSON()) << std::endl;
      break;

    case 8:
      std::cout << "\n=== Dev Fund Information ===\n";
      std::cout << "Address: DevFundWallet\n";
      std::cout << "Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
      break;

    case 9: {
      bool blacklistRunning = true;
      while (blacklistRunning) {
        printBlacklistMenu();
        int blChoice;
        std::cin >> blChoice;
        if (std::cin.fail()) {
          std::cin.clear();
          std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
          std::cout << "Invalid input!\n";
          continue;
        }
        switch (blChoice) {
          case 1: showBlacklist(&peerBlacklist); break;
          case 2: {
            std::string peerID, reason;
            std::cout << "Enter peer ID: ";
            std::cin >> peerID;
            std::cout << "Enter reason: ";
            std::cin.ignore();
            std::getline(std::cin, reason);
            addPeer(&peerBlacklist, peerID, reason);
            break;
          }
          case 3: {
            std::string peerID;
            std::cout << "Enter peer ID: ";
            std::cin >> peerID;
            removePeer(&peerBlacklist, peerID);
            break;
          }
          case 4: clearBlacklist(&peerBlacklist); break;
          case 5: blacklistRunning = false; break;
          default: std::cout << "Invalid choice!\n";
        }
      }
      break;
    }

    case 10: {
	    if (!wallet) {
	        std::cout << "Load or create a wallet first!\n";
	        break;
	    }

	    if (!blockchain.loadFromDB()) {
	        std::cerr << "❌ Could not load blockchain from DB.\n";
	        break;
	    }
	    blockchain.reloadBlockchainState();

	    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
	    if (l2Transactions.empty()) {
	        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
	        break;
	    }

	    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
	    std::unordered_map<std::string, double> stateAfter =
	        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

	    RollupBlock rollup(
	        blockchain.getRollupChainSize(),
	        blockchain.getLastRollupHash(),
	        l2Transactions
	    );

	    std::string prevRecursive = blockchain.getLastRollupProof();
	    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

	    if (blockchain.isRollupBlockValid(rollup)) {
	        blockchain.addRollupBlock(rollup);
	        std::cout << "✅ Rollup Block created successfully!\n";
	        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
	    } else {
	        std::cerr << "❌ Rollup Block creation failed: Proof invalid.\n";
	    }
	    break;
	}

	    case 11: running = false; break;

	   case 12: {
	    if (!wallet) {
	        std::cout << "Load or create a wallet first!\n";
	        break;
	    }

	    Proposal proposal;
	    proposal.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
	    proposal.proposer_address = wallet->getAddress();

	    std::cin.ignore();
	    std::cout << "Enter proposal description: ";
	    std::getline(std::cin, proposal.description);

	    std::cout << "Select Proposal Type:\n"
              << "1. Protocol Upgrade\n"
              << "2. Fund Allocation\n"
              << "3. Blacklist Appeal\n"
              << "4. Custom Action\n"
              << "Choice: ";
	    int typeChoice;
	    std::cin >> typeChoice;
	    proposal.type = static_cast<ProposalType>(typeChoice - 1);

    // Handle FUND_ALLOCATION-specific input
    if (proposal.type == ProposalType::FUND_ALLOCATION) {
        std::cout << "Enter amount to transfer from Dev Fund: ";
        std::cin >> proposal.transfer_amount;

        std::cout << "Enter recipient address: ";
        std::cin.ignore(); // flush newline
        std::getline(std::cin, proposal.target_address);

        if (proposal.transfer_amount <= 0 || proposal.target_address.empty()) {
            std::cerr << "❌ Invalid fund allocation details.\n";
            break;
        }
    }

    proposal.yes_votes = 0;
    proposal.no_votes = 0;
    proposal.creation_time = std::time(nullptr);
    proposal.deadline_time = proposal.creation_time + 86400;  // 24 hours
    proposal.status = ProposalStatus::PENDING;

    if (DAO::createProposal(proposal)) {
        std::cout << "✅ Proposal submitted. ID: " << proposal.proposal_id << "\n";
    } else {
        std::cerr << "❌ Failed to submit proposal.\n";
    }

    break;
}

   case 13: {
    if (!wallet) {
        std::cout << "Load or create a wallet first!\n";
        break;
    }

    std::string proposal_id;
    std::cout << "Enter Proposal ID: ";
    std::cin >> proposal_id;

    std::string voteStr;
    std::cout << "Vote YES or NO: ";
    std::cin >> voteStr;

    bool voteYes = (voteStr == "YES" || voteStr == "yes" || voteStr == "Y" || voteStr == "y");
    uint64_t weight = static_cast<uint64_t>(blockchain.getBalance(wallet->getAddress()));

    if (weight == 0) {
        std::cerr << "⚠️ You have no voting weight (0 balance).\n";
        break;
    }

    if (DAO::castVote(proposal_id, wallet->getAddress(), voteYes, weight)) {
        std::cout << "✅ Vote cast successfully! Weight: " << weight << "\n";
    } else {
        std::cerr << "❌ Failed to cast vote.\n";
    }

    break;
  }
    case 14: {
        std::vector<Proposal> proposals = DAOStorage::getAllProposals();
        std::cout << "\n=== DAO Proposals ===\n";
        for (const auto& p : proposals) {
            std::cout << "📜 ID: " << p.proposal_id << "\n";
            std::cout << "📝 Description: " << p.description << "\n";
            std::cout << "🧭 Type: " << static_cast<int>(p.type) << "\n";
            std::cout << "📅 Deadline: " << p.deadline_time << "\n";
            std::cout << "✅ YES: " << static_cast<uint64_t>(p.yes_votes) << " | ❌ NO: " << static_cast<uint64_t>(p.no_votes) << "\n";
            std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
        }
        break;
    }

    case 15: {
        std::string pid;
        std::cout << "Enter Proposal ID to finalize: ";
        std::cin >> pid;
        if (DAO::finalizeProposal(pid)) {
            std::cout << "✅ Proposal finalized.\n";
        } else {
            std::cerr << "❌ Failed to finalize proposal.\n";
        }
        break;
    }

    case 16: {
        std::cout << "\n=== Blockchain Stats ===\n";
        std::cout << "Total Blocks: " << blockchain.getBlockCount() << "\n";
        std::cout << "Difficulty: " << calculateSmartDifficulty(blockchain) << "\n";
        std::cout << "Total Supply: " << totalSupply << " AlynCoin\n";
        std::cout << "Total Burned Supply: " << blockchain.getTotalBurnedSupply() << " AlynCoin\n";
        std::cout << "Dev Fund Balance: " << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
        break;
    }

    case 17: {
	    if (!wallet) {
	        std::cout << "❌ Load or create a wallet first!\n";
	        break;
	    }

	    std::cout << "🔁 Generating Rollup Block with Recursive zk-STARK Proof...\n";

	    if (!blockchain.loadFromDB()) {
	        std::cerr << "❌ Could not load blockchain from DB.\n";
	        break;
	    }
	    blockchain.reloadBlockchainState();

	    std::vector<Transaction> l2Transactions = blockchain.getPendingL2Transactions();
	    if (l2Transactions.empty()) {
	        std::cout << "⚠️ No pending L2 transactions to roll up.\n";
	        break;
	    }

	    std::unordered_map<std::string, double> stateBefore = blockchain.getCurrentState();
	    std::unordered_map<std::string, double> stateAfter =
	        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

         RollupBlock rollup(
        blockchain.getRollupChainSize(),
        blockchain.getLastRollupHash(),
        l2Transactions
    	);

	    std::string prevRecursive = blockchain.getLastRollupProof();
	    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

	    if (blockchain.isRollupBlockValid(rollup)) {
	        blockchain.addRollupBlock(rollup);
	        std::cout << "✅ Rollup Block with Recursive Proof created successfully!\n";
	        std::cout << "📦 Rollup Hash: " << rollup.getHash() << "\n";
	    } else {
	        std::cerr << "❌ Rollup Block creation failed: Proof invalid.\n";
	    }

	    break;
	}

    case 18: {
	    if (!wallet) {
	        std::cout << "❌ Load or create a wallet first!\n";
	        break;
	    }

    std::cout << "\n⚙️ Auto Rollup Trigger Started...\n";

    const int idleThresholdSecs = 300;  // 5 minutes
    const int midThresholdTxs = 10;
    const int midThresholdSecs = 20;
    const int highThresholdTxs = 25;
    const int highThresholdSecs = 10;

    Blockchain& blockchain = Blockchain::getInstance();
    auto lastRollupTime = blockchain.getLastRollupTimestamp();
    auto now = std::time(nullptr);
    auto pendingL2 = blockchain.getPendingL2Transactions();

    bool didRollup = false;

    // 🔁 1. High Activity → Recursive zk-STARK
    if (pendingL2.size() >= highThresholdTxs &&
        (now - blockchain.getFirstPendingL2Timestamp()) <= highThresholdSecs) {
        std::cout << "⚡ High activity detected (≥ 25 tx in 10s). Generating Recursive zk-STARK Rollup...\n";
        auto stateBefore = blockchain.getCurrentState();
        auto stateAfter = blockchain.simulateL2StateUpdate(stateBefore, pendingL2);

        RollupBlock rollup(blockchain.getRollupChainSize(), blockchain.getLastRollupHash(), pendingL2);
        std::string prevRecursive = blockchain.getLastRollupProof();
        rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

        if (blockchain.isRollupBlockValid(rollup)) {
            blockchain.addRollupBlock(rollup);
            std::cout << "✅ Recursive Rollup Block created! Hash: " << rollup.getHash() << "\n";
            didRollup = true;
        } else {
            std::cerr << "❌ Recursive Rollup failed validation.\n";
        }
    }
    // 📈 2. Mid Activity → Normal zk-STARK
    else if (pendingL2.size() >= midThresholdTxs &&
             (now - blockchain.getFirstPendingL2Timestamp()) <= midThresholdSecs) {
        std::cout << "📈 Mid activity detected (≥ 10 tx in 20s). Generating Normal zk-STARK Rollup...\n";
        auto stateBefore = blockchain.getCurrentState();
        auto stateAfter = blockchain.simulateL2StateUpdate(stateBefore, pendingL2);

        RollupBlock rollup(blockchain.getRollupChainSize(), blockchain.getLastRollupHash(), pendingL2);
        std::string prevRecursive = blockchain.getLastRollupProof();
        rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

        if (blockchain.isRollupBlockValid(rollup)) {
            blockchain.addRollupBlock(rollup);
            std::cout << "✅ Rollup Block created! Hash: " << rollup.getHash() << "\n";
            didRollup = true;
        } else {
            std::cerr << "❌ Mid Activity Rollup failed validation.\n";
        }
    }
    // ⏱️ 3. Idle Trigger → 5 min timeout
    else if ((now - lastRollupTime) >= idleThresholdSecs && !pendingL2.empty()) {
        std::cout << "⏱️ Idle trigger (no rollup in 5 minutes). Generating zk-STARK Rollup...\n";
        auto stateBefore = blockchain.getCurrentState();
        auto stateAfter = blockchain.simulateL2StateUpdate(stateBefore, pendingL2);

        RollupBlock rollup(blockchain.getRollupChainSize(), blockchain.getLastRollupHash(), pendingL2);
        std::string prevRecursive = blockchain.getLastRollupProof();
        rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

        if (blockchain.isRollupBlockValid(rollup)) {
            blockchain.addRollupBlock(rollup);
            std::cout << "✅ Idle Rollup Block created! Hash: " << rollup.getHash() << "\n";
            didRollup = true;
        } else {
            std::cerr << "❌ Idle Rollup failed validation.\n";
        }
    } else {
        std::cout << "ℹ️ No rollup condition met (Txs: " << pendingL2.size() << ").\n";
    }

    if (!didRollup) {
        std::cout << "⚠️ Rollup not generated. All thresholds unmet or no pending L2 transactions.\n";
    }
    break;
	}
	case 19: {
    if (!wallet) {
        std::cout << "❌ Load or create a wallet first!\n";
        break;
    }

    std::string addr = wallet->getAddress();
    int count;
    std::cout << "How many recent transactions to include in recursive proof? ";
    std::cin >> count;

    if (count <= 0) {
        std::cerr << "❌ Invalid transaction count.\n";
        break;
    }

    std::vector<Transaction> allTxs = Transaction::loadAllFromDB();
    std::vector<std::string> hashes;

    for (auto it = allTxs.rbegin(); it != allTxs.rend(); ++it) {
        if ((it->getSender() == addr || it->getRecipient() == addr) && hashes.size() < (size_t)count) {
            hashes.push_back(it->getHash());
        }
    }

    if (hashes.empty()) {
        std::cerr << "⚠️ No transactions found for " << addr << ".\n";
        break;
    }

    std::string output = generateRecursiveProofToFile(hashes, addr, hashes.size(), "");
    std::cout << output << "\n";
    break;
}


    default: std::cout << "Invalid choice! Please select a valid option.\n";
    }
  }


  if (wallet) delete wallet;
  return 0;
}
