#include "atomic_swaps/rocksdb_swap_store.h"
#include "atomic_swaps/swap_manager.h"
#include "blockchain.h"
#include "cli/peer_blacklist_cli.h"
#include "config.h"
#include "crypto_utils.h"
#include "db/db_instance.h"
#include "db/db_paths.h"
#include "difficulty.h"
#include "governance/dao.h"
#include "governance/dao_storage.h"
#include "governance/devfund.h"
#include "httplib.h"
#include "json.hpp"
#include "miner.h"
#include "network.h"
#include "network/peer_blacklist.h"
#include "nft/crypto/aes_utils.h"
#include "nft/nft.h"
#include "nft/nft_storage.h"
#include "nft/nft_utils.h"
#include "rpc/metrics.h"
#include "self_healing/self_healing_node.h"
#include "wallet.h"
#include "zk/recursive_proof_helper.h"
#include "zk/winterfell_stark.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <json/json.h>
#include <limits>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

// Print usage information for CLI commands
void print_usage() {
  std::cout
      << "Usage: alyncoin-cli <command> [args]\n"
      << "Commands:\n"
      << "  createwallet                         Create a new wallet (prompts "
         "for passphrase)\n"
      << "  loadwallet <name|address>           Load an existing wallet\n"
      << "  exportwallet [name] <file>           Export wallet keys and "
         "balance to file\n"
      << "  importwallet <file>                 Import wallet keys from backup "
         "file\n"
      << "  export-genesis <file>               Export genesis block to file\n"
      << "  import-genesis <file>               Import genesis block from "
         "file\n"
      << "  balance <address>                    Show wallet balance\n"
      << "  balance-force <address>             Reload chain and show balance\n"
      << "  sendl1 <from> <to> <amount> <metadata>  Send L1 transaction\n"
      << "  sendl2 <from> <to> <amount> <metadata>  Send L2 transaction\n"
      << "  dao-submit <from> <desc> [type] [amount] [target]  Submit DAO "
         "proposal\n"
      << "  dao-vote <from> <id> <yes|no>        Vote on DAO proposal\n"
      << "  history <address>                    Show transaction history\n"
      << "  mychain <address>                    Show mined block stats\n"
      << "  mine <miner_address>                Mine pending transactions\n"
      << "  rollup <address>                     Generate rollup block\n"
      << "  recursive-rollup <address>          Generate recursive rollup "
         "block\n"
      << "  --help                              Show this message\n";
}

static bool exportWalletToFile(const std::string &keyDir,
                               Blockchain &blockchain, const std::string &name,
                               const std::string &outPath) {
  std::string keyId =
      Crypto::resolveWalletKeyIdentifier(name).value_or(name);

  std::string priv = keyDir + keyId + "_private.pem";
  std::string dil = keyDir + keyId + "_dilithium.key";
  std::string fal = keyDir + keyId + "_falcon.key";
  if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) ||
      !std::filesystem::exists(fal)) {
    std::cerr << "❌ Wallet key files not found for: " << name << "\n";
    return false;
  }
  auto readFile = [](const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
  };
  nlohmann::json j;
  j["address"] = name;
  j["key_id"] = keyId;
  j["private_key"] = readFile(priv);
  j["dilithium_key"] = readFile(dil);
  j["falcon_key"] = readFile(fal);
  std::string passPath = keyDir + name + "_pass.txt";
  if (std::filesystem::exists(passPath)) {
    j["pass_hash"] = readFile(passPath);
  }
  j["balance"] = blockchain.getBalance(name);
  std::ofstream out(outPath);
  if (!out) {
    std::cerr << "❌ Unable to open file for writing: " << outPath << "\n";
    return false;
  }
  out << j.dump(2);
  std::cout << "✅ Wallet exported to " << outPath << "\n";
  return true;
}

static bool importWalletFromFile(const std::string &keyDir,
                                 const std::string &inPath) {
  std::ifstream in(inPath);
  if (!in) {
    std::cerr << "❌ Unable to open file: " << inPath << "\n";
    return false;
  }
  nlohmann::json j;
  try {
    in >> j;
  } catch (const std::exception &e) {
    std::cerr << "❌ Invalid wallet backup JSON: " << e.what() << "\n";
    return false;
  }
  std::string address = j.value("address", "");
  std::string keyId = j.value("key_id", address);
  std::string priv = j.value("private_key", "");
  std::string dil = j.value("dilithium_key", "");
  std::string fal = j.value("falcon_key", "");
  std::string passHash = j.value("pass_hash", "");
  if (keyId.empty() || priv.empty() || dil.empty() || fal.empty()) {
    std::cerr << "❌ Invalid wallet backup data\n";
    return false;
  }
  if (std::filesystem::exists(keyDir + keyId + "_private.pem")) {
    std::cerr << "❌ Wallet already exists: " << keyId << "\n";
    return false;
  }
  auto writeFile = [](const std::string &path, const std::string &contents) {
    std::ofstream out(path, std::ios::binary);
    out << contents;
  };
  try {
    writeFile(keyDir + keyId + "_private.pem", priv);
    writeFile(keyDir + keyId + "_dilithium.key", dil);
    writeFile(keyDir + keyId + "_falcon.key", fal);
    if (!j.value("dilithium_pub", std::string()).empty()) {
      auto pub = Crypto::fromHex(j.value("dilithium_pub", std::string()));
      writeFile(keyDir + keyId + "_dilithium.pub",
                std::string(pub.begin(), pub.end()));
    }
    if (!j.value("falcon_pub", std::string()).empty()) {
      auto pub = Crypto::fromHex(j.value("falcon_pub", std::string()));
      writeFile(keyDir + keyId + "_falcon.pub",
                std::string(pub.begin(), pub.end()));
    }
    if (!passHash.empty()) {
      writeFile(keyDir + keyId + "_pass.txt", passHash);
    }
    std::string resolvedAddress = address;
    if (resolvedAddress.empty()) {
      auto dilHex = j.value("dilithium_pub", std::string());
      if (!dilHex.empty()) {
        auto bytes = Crypto::fromHex(dilHex);
        if (!bytes.empty())
          resolvedAddress = Crypto::deriveAddressFromPub(bytes);
      }
    }
    if (resolvedAddress.empty()) {
      auto falHex = j.value("falcon_pub", std::string());
      if (!falHex.empty()) {
        auto bytes = Crypto::fromHex(falHex);
        if (!bytes.empty())
          resolvedAddress = Crypto::deriveAddressFromPub(bytes);
      }
    }
    if (resolvedAddress.empty())
      resolvedAddress = keyId;

    Crypto::rememberWalletKeyIdentifier(resolvedAddress, keyId);
    std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt")
        << resolvedAddress;
    std::cout << "✅ Wallet imported: " << resolvedAddress;
    if (!resolvedAddress.empty() && resolvedAddress != keyId)
      std::cout << " (Key ID: " << keyId << ")";
    std::cout << "\n";
  } catch (const std::exception &e) {
    std::cerr << "❌ Wallet import failed: " << e.what() << "\n";
    return false;
  }
  return true;
}

// --- AlynCoin RPC/HTTP Server ---
void start_rpc_server(Blockchain *blockchain, Network *network,
                      SelfHealingNode *healer, const std::string &rpc_host,
                      int rpc_port) {
  RocksDBAtomicSwapStore swapStore(DBPaths::getHomePath() + "/swapdb");
  AtomicSwapManager swapMgr(&swapStore);
  httplib::Server svr;
  const auto cors = getAppConfig().rpc_cors;
  auto set_cors = [cors](httplib::Response &res) {
    if (!cors.empty()) {
      res.set_header("Access-Control-Allow-Origin", cors.c_str());
      res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      res.set_header("Access-Control-Allow-Headers", "Content-Type");
    }
  };

  svr.Options(R"(/.*)",
              [set_cors](const httplib::Request &, httplib::Response &res) {
                set_cors(res);
                res.status = 204;
              });

  std::thread updater([blockchain, network]() {
    while (true) {
      metrics::chain_height.value = blockchain->getHeight();
      metrics::orphan_pool_size.value = blockchain->getOrphanPoolSize();
      int pc = 0;
      if (network && network->getPeerManager())
        pc = network->getPeerManager()->getPeerCount();
      metrics::peer_count.value = pc;
      metrics::rx_queue_depth.value = 0;
      metrics::reorg_depth.value = 0;
      std::this_thread::sleep_for(std::chrono::seconds(5));
    }
  });
  updater.detach();

  svr.Get("/metrics", [](const httplib::Request &, httplib::Response &res) {
    res.set_content(metrics::toPrometheus(), "text/plain");
  });

  svr.Get("/healthz", [blockchain, set_cors](const httplib::Request &,
                                             httplib::Response &res) {
    nlohmann::json out{{"ok", true},
                       {"height", blockchain->getHeight()},
                       {"tip", blockchain->getTipHashHex()},
                       {"peers", blockchain->getPeerCount()}};
    res.set_content(out.dump(), "application/json");
    set_cors(res);
  });

  svr.Get("/status", [blockchain, network, set_cors](const httplib::Request &,
                                                     httplib::Response &res) {
    nlohmann::json info{{"network", "mainnet"},
                        {"version", "0.1.0"},
                        {"height", blockchain->getHeight()},
                        {"tipHash", blockchain->getTipHashHex()},
                        {"totalWork", blockchain->getTotalWork()},
                        {"peers", blockchain->getPeerCount()},
                        {"timestamp", (uint64_t)std::time(nullptr)}};
    res.set_content(info.dump(), "application/json");
    set_cors(res);
  });

  svr.Get("/supply", [blockchain, set_cors](const httplib::Request &,
                                            httplib::Response &res) {
    auto s = blockchain->getSupplyInfo();
    nlohmann::json out{{"total", s.total},
                       {"burned", s.burned},
                       {"locked", s.locked},
                       {"circulating", s.circulating}};
    res.set_content(out.dump(), "application/json");
    set_cors(res);
  });

  svr.Get(R"(/balance/(.+))", [blockchain,
                               set_cors](const httplib::Request &req,
                                         httplib::Response &res) {
    std::string addr = req.matches[1];
    auto is_valid = [](const std::string &a) {
      if (a.rfind("ALYN", 0) == 0)
        return a.size() >= 10 && a.size() <= 64;
      if (a.size() < 34 || a.size() > 64)
        return false;
      return std::all_of(a.begin(), a.end(),
                         [](unsigned char c) { return std::isxdigit(c); });
    };
    if (!is_valid(addr)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid address\"}", "application/json");
    } else {
      uint64_t bal = blockchain->getBalanceOf(addr);
      nlohmann::json out{{"address", addr}, {"balance", bal}};
      res.set_content(out.dump(), "application/json");
    }
    set_cors(res);
  });

  svr.Post("/rpc", [blockchain, network, healer, &swapMgr, set_cors](
                       const httplib::Request &req, httplib::Response &res) {
    nlohmann::json input;
    nlohmann::json id = nullptr;
    try {
      input = nlohmann::json::parse(req.body);
      id = input.value("id", nullptr);
    } catch (...) {
      nlohmann::json resp{
          {"jsonrpc", "2.0"},
          {"id", nullptr},
          {"error", {{"code", -32700}, {"message", "Parse error"}}}};
      res.status = 200;
      res.set_content(resp.dump(), "application/json");
      set_cors(res);
      return;
    }

    nlohmann::json output;
    std::string method = input.value("method", "");
    auto params = input.value("params", nlohmann::json::array());

    auto make_error = [](int code, const std::string &msg) {
      return nlohmann::json{{"error",
                             {{"code", code}, {"message", msg}}}};
    };

    auto params_error = [&](const std::string &msg) { output = make_error(-32602, msg); };

    auto json_to_hex = [](const std::vector<uint8_t> &data) {
      if (data.empty())
        return std::string();
      std::vector<unsigned char> bytes(data.begin(), data.end());
      return Crypto::toHex(bytes);
    };

    try {
      // --- Chain helpers ---
      if (method == "chain.getInfo") {
        nlohmann::json info{{"network", "mainnet"},
                            {"version", "0.1.0"},
                            {"height", blockchain->getHeight()},
                            {"tipHash", blockchain->getTipHashHex()},
                            {"totalWork", blockchain->getTotalWork()},
                            {"peers", blockchain->getPeerCount()},
                            {"timestamp", (uint64_t)std::time(nullptr)}};
        output = {{"result", info}};
      } else if (method == "chain.getSupply") {
        auto s = blockchain->getSupplyInfo();
        nlohmann::json info{{"total", s.total},
                            {"burned", s.burned},
                            {"locked", s.locked},
                            {"circulating", s.circulating}};
        output = {{"result", info}};
      } else if (method == "address.getBalance") {
        std::string addr;
        if (input.contains("params") && input["params"].is_object())
          addr = input["params"].value("address", "");
        auto is_valid = [](const std::string &a) {
          if (a.rfind("ALYN", 0) == 0)
            return a.size() >= 10 && a.size() <= 64;
          if (a.size() < 34 || a.size() > 64)
            return false;
          return std::all_of(a.begin(), a.end(),
                             [](unsigned char c) { return std::isxdigit(c); });
        };
        if (!is_valid(addr)) {
          output = {{"error", nlohmann::json{{"code", -32602},
                                             {"message", "Invalid address"}}}};
        } else {
          uint64_t bal = blockchain->getBalanceOf(addr);
          output = {
              {"result", nlohmann::json{{"address", addr}, {"balance", bal}}}};
        }
      } else if (method == "system.selfHealNow") {
        std::thread([healer]() { healer->monitorAndHeal(); }).detach();
        output = {{"result", nlohmann::json{{"ok", true}}}};
      } else if (method == "bridge.getPoR") {
        auto &cfg = getAppConfig();
        uint64_t reserve = blockchain->getBalanceOf(cfg.reserve_address);
        nlohmann::json r{{"reserveAlyn", std::to_string(reserve)}};
        if (cfg.por_expected_walyn > 0) {
          uint64_t expected = static_cast<uint64_t>(cfg.por_expected_walyn);
          r["expectedWalyn"] = std::to_string(expected);
          r["delta"] = std::to_string(reserve - expected);
        }
        output = {{"result", r}};
      }

      // Wallet
      else if (method == "balance") {
        std::string addr = params.at(0);
        double bal = blockchain->getBalance(addr);
        output = {{"result", bal}};
      } else if (method == "createwallet") {
        std::string keyId;
        std::string pass;
        if (!params.empty()) {
          if (params.size() == 1 && params.at(0).is_string()) {
            pass = params.at(0).get<std::string>();
          } else if (params.size() >= 2 && params.at(0).is_string() &&
                     params.at(1).is_string()) {
            keyId = params.at(0).get<std::string>();
            pass = params.at(1).get<std::string>();
          }
        }

        std::filesystem::path keyDirPath(DBPaths::getKeyDir());
        Crypto::ensureKeysDirectory();

        auto privPathFor = [&keyDirPath](const std::string &candidate) {
          return keyDirPath / (candidate + "_private.pem");
        };

        if (keyId.empty()) {
          do {
            keyId = Crypto::generateRandomHex(40);
          } while (std::filesystem::exists(privPathFor(keyId)));
        } else if (std::filesystem::exists(privPathFor(keyId))) {
          output = {{"error", "Wallet already exists: " + keyId}};
        }

        if (!output.contains("error")) {
          try {
            Wallet w(keyId, keyDirPath.string(), pass);
            if (!pass.empty()) {
              std::ofstream(keyDirPath / (keyId + "_pass.txt"))
                  << Crypto::sha256(pass);
            }
            Crypto::rememberWalletKeyIdentifier(w.getAddress(), keyId);
            std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt")
                << w.getAddress();
            output = {{"result", w.getAddress()}, {"key_id", keyId}};
          } catch (const std::exception &e) {
            output = {
                {"error", std::string("Wallet creation failed: ") + e.what()}};
          }
        }
      } else if (method == "loadwallet") {
        if (params.size() < 1) {
          output = {{"error", "Missing wallet name parameter"}};
        } else {
          std::string requested = params.at(0);
          std::string pass = params.size() > 1 && params.at(1).is_string()
                                 ? params.at(1).get<std::string>()
                                 : "";

          auto resolved = Crypto::resolveWalletKeyIdentifier(requested);
          std::string keyId = resolved.value_or(requested);

          std::string priv = DBPaths::getKeyDir() + keyId + "_private.pem";
          std::string dil = DBPaths::getKeyDir() + keyId + "_dilithium.key";
          std::string fal = DBPaths::getKeyDir() + keyId + "_falcon.key";
          std::string passPath = DBPaths::getKeyDir() + keyId + "_pass.txt";
          if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) ||
              !std::filesystem::exists(fal)) {
            output = {{"error", "Wallet key files not found for: " + requested}};
          } else if (std::filesystem::exists(passPath)) {
            std::ifstream pin(passPath);
            std::string stored;
            std::getline(pin, stored);
            if (Crypto::sha256(pass) != stored) {
              output = {{"error", "Incorrect passphrase"}};
            } else {
              try {
                Wallet w(priv, DBPaths::getKeyDir(), keyId, pass);
                Crypto::rememberWalletKeyIdentifier(w.getAddress(), keyId);
                std::ofstream(DBPaths::getHomePath() +
                              "/.alyncoin/current_wallet.txt")
                    << w.getAddress();
                nlohmann::json walletInfo = {
                    {"address", w.getAddress()},
                    {"key_id", keyId},
                };
                output = {{"result", walletInfo}};
              } catch (const std::exception &e) {
                output = {
                    {"error", std::string("Wallet load failed: ") + e.what()}};
              }
            }
          } else {
            try {
              Wallet w(priv, DBPaths::getKeyDir(), keyId, pass);
              Crypto::rememberWalletKeyIdentifier(w.getAddress(), keyId);
              std::ofstream(DBPaths::getHomePath() +
                            "/.alyncoin/current_wallet.txt")
                  << w.getAddress();
              nlohmann::json walletInfo = {
                  {"address", w.getAddress()},
                  {"key_id", keyId},
              };
              output = {{"result", walletInfo}};
            } catch (const std::exception &e) {
              output = {
                  {"error", std::string("Wallet load failed: ") + e.what()}};
            }
          }
        }
      } else if (method == "exportwallet") {
        if (!params.is_array() || params.empty() || !params[0].is_string()) {
          params_error("exportwallet expects the wallet key identifier");
        } else {
          std::string keyId = params[0].get<std::string>();
          auto dil = Crypto::loadDilithiumKeys(keyId);
          auto fal = Crypto::loadFalconKeys(keyId);

          if (dil.privateKey.empty() && fal.privateKey.empty()) {
            output = {{"error", "Wallet not found"}};
          } else {
            std::string addr;
            if (!dil.publicKey.empty())
              addr = Crypto::deriveAddressFromPub(
                  std::vector<unsigned char>(dil.publicKey.begin(),
                                             dil.publicKey.end()));
            if (addr.empty() && !fal.publicKey.empty())
              addr = Crypto::deriveAddressFromPub(
                  std::vector<unsigned char>(fal.publicKey.begin(),
                                             fal.publicKey.end()));
            if (addr.empty())
              addr = keyId;

            auto readFile = [](const std::string &path) {
              if (!std::filesystem::exists(path))
                return std::string();
              std::ifstream in(path, std::ios::binary);
              std::ostringstream ss;
              ss << in.rdbuf();
              return ss.str();
            };

            nlohmann::json j;
            j["address"] = addr;
            j["key_id"] = keyId;

            if (!dil.publicKey.empty())
              j["dilithium_pub"] = json_to_hex(dil.publicKey);
            if (!fal.publicKey.empty())
              j["falcon_pub"] = json_to_hex(fal.publicKey);
            if (!dil.privateKey.empty())
              j["dilithium_priv"] = json_to_hex(dil.privateKey);
            if (!fal.privateKey.empty())
              j["falcon_priv"] = json_to_hex(fal.privateKey);

            std::string privPath =
                DBPaths::getKeyDir() + keyId + "_private.pem";
            std::string passPath =
                DBPaths::getKeyDir() + keyId + "_pass.txt";
            std::string dilPath =
                DBPaths::getKeyDir() + keyId + "_dilithium.key";
            std::string falPath =
                DBPaths::getKeyDir() + keyId + "_falcon.key";

            std::string rsaPriv = readFile(privPath);
            if (!rsaPriv.empty())
              j["private_key"] = rsaPriv;

            std::string rawDil = readFile(dilPath);
            if (!rawDil.empty())
              j["dilithium_key"] = rawDil;
            std::string rawFal = readFile(falPath);
            if (!rawFal.empty())
              j["falcon_key"] = rawFal;

            std::string passHash = readFile(passPath);
            if (!passHash.empty())
              j["pass_hash"] = passHash;

            j["balance"] = blockchain->getBalance(addr);
            output = {{"result", j}};
          }
        }
      } else if (method == "importwallet") {
        if (!params.is_array() || params.empty() || !params[0].is_object()) {
          output = {{"error", "Missing wallet data"}};
        } else {
          auto data = params[0];
          std::string name = data.value("address", "");
          std::string keyId = data.value("key_id", name);
          if (keyId.empty())
            keyId = name;

          auto decodeHexOrRaw = [](const nlohmann::json &obj,
                                   const std::string &hexField,
                                   const std::string &rawField) {
            std::string hex = obj.value(hexField, "");
            if (!hex.empty()) {
              auto bytes = Crypto::fromHex(hex);
              return std::string(bytes.begin(), bytes.end());
            }
            return obj.value(rawField, std::string());
          };

          std::string priv = data.value("private_key", "");
          std::string dil = decodeHexOrRaw(data, "dilithium_priv",
                                           "dilithium_key");
          std::string fal = decodeHexOrRaw(data, "falcon_priv",
                                           "falcon_key");
          std::string passHash = data.value("pass_hash", "");

          if (keyId.empty() || priv.empty() || dil.empty() || fal.empty()) {
            output = {{"error", "Invalid wallet backup data"}};
          } else if (std::filesystem::exists(DBPaths::getKeyDir() + keyId +
                                             "_private.pem")) {
            output = {{"error", "Wallet already exists: " + keyId}};
          } else {
            auto writeFile = [](const std::string &path,
                                const std::string &contents) {
              std::ofstream out(path, std::ios::binary);
              out << contents;
            };
            try {
              writeFile(DBPaths::getKeyDir() + keyId + "_private.pem", priv);
              writeFile(DBPaths::getKeyDir() + keyId + "_dilithium.key", dil);
              writeFile(DBPaths::getKeyDir() + keyId + "_falcon.key", fal);
              if (!data.value("dilithium_pub", "").empty()) {
                auto pub = Crypto::fromHex(data.value("dilithium_pub", ""));
                writeFile(DBPaths::getKeyDir() + keyId + "_dilithium.pub",
                          std::string(pub.begin(), pub.end()));
              }
              if (!data.value("falcon_pub", "").empty()) {
                auto pub = Crypto::fromHex(data.value("falcon_pub", ""));
                writeFile(DBPaths::getKeyDir() + keyId + "_falcon.pub",
                          std::string(pub.begin(), pub.end()));
              }
              if (!passHash.empty()) {
                writeFile(DBPaths::getKeyDir() + keyId + "_pass.txt", passHash);
              }

              std::string resolvedAddress = data.value("address", std::string());
              if (resolvedAddress.empty()) {
                auto dilHex = data.value("dilithium_pub", std::string());
                if (!dilHex.empty()) {
                  auto bytes = Crypto::fromHex(dilHex);
                  if (!bytes.empty())
                    resolvedAddress = Crypto::deriveAddressFromPub(bytes);
                }
              }
              if (resolvedAddress.empty()) {
                auto falHex = data.value("falcon_pub", std::string());
                if (!falHex.empty()) {
                  auto bytes = Crypto::fromHex(falHex);
                  if (!bytes.empty())
                    resolvedAddress = Crypto::deriveAddressFromPub(bytes);
                }
              }
              if (resolvedAddress.empty())
                resolvedAddress = keyId;

              Crypto::rememberWalletKeyIdentifier(resolvedAddress, keyId);
              std::ofstream(DBPaths::getHomePath() +
                            "/.alyncoin/current_wallet.txt")
                  << resolvedAddress;

              nlohmann::json result{{"key_id", keyId},
                                    {"address", resolvedAddress}};
              output = {{"result", result}};
            } catch (const std::exception &e) {
              output = {
                  {"error", std::string("Wallet import failed: ") + e.what()}};
            }
          }
        }
      }
      // Mine One Block
      else if (method == "mineonce") {
        if (params.empty() || !params.at(0).is_string()) {
          output = {{"error", "mineonce expects miner address as first param"}};
        } else {
          std::string miner = params.at(0);
          auto resolvedMiner = Crypto::resolveWalletKeyIdentifier(miner);
          std::string minerKeyId = resolvedMiner.value_or(miner);

          auto ensureFile = [](const std::string &path) {
            return std::filesystem::exists(path);
          };
          std::string base = DBPaths::getKeyDir();
          std::string privPath = base + minerKeyId + "_private.pem";
          std::string dilPath = base + minerKeyId + "_dilithium.key";
          std::string falPath = base + minerKeyId + "_falcon.key";
          if (!ensureFile(privPath) || !ensureFile(dilPath) ||
              !ensureFile(falPath)) {
            output = {{"error",
                       "Missing key files for miner wallet: " + minerKeyId}};
          } else {
            blockchain->loadPendingTransactionsFromDB();
            if (!network || !network->getPeerManager() ||
                network->getPeerManager()->getPeerCount() == 0) {
              output = {{"error", "No peers connected"}};
            } else {
              Block mined = blockchain->mineBlock(miner);
              if (!mined.getHash().empty()) {
                blockchain->saveToDB();
                if (network)
                  network->broadcastBlock(mined);
                blockchain->reloadBlockchainState();
                output = {{"result", mined.getHash()}};
              } else {
                output = {{"error", "Mining failed"}};
              }
            }
          }
        }
      }
      // Start Mining Loop (Non-blocking trigger, returns immediately)
      // NOTE: This RPC spawns an infinite mining thread on the server and
      // does not provide a stop mechanism or return mined block hashes.
      // The GUI now prefers calling "mineonce" repeatedly instead.
      else if (method == "mineloop") {
        std::string miner = params.at(0);
        std::thread([blockchain, network, miner]() {
          while (true) {
            blockchain->loadPendingTransactionsFromDB();
            Block minedBlock = blockchain->mineBlock(miner);
            if (!minedBlock.getHash().empty()) {
              blockchain->saveToDB();
              try {
                blockchain->reloadBlockchainState();
                if (network)
                  network->broadcastBlock(minedBlock);
              } catch (...) {
              }
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
          }
        }).detach();
        output = {{"result", "Mining loop started"}};
      }
      // Stats
      else if (method == "stats") {
        nlohmann::json stats = {
            {"blocks", blockchain->getBlockCount()},
            {"difficulty", calculateSmartDifficulty(*blockchain)},
            {"supply", blockchain->getTotalSupply()},
            {"block_reward", blockchain->getBlockReward()},
            {"burned", blockchain->getTotalBurnedSupply()},
            {"devfund", blockchain->getBalance("DevFundWallet")}};
        output = {{"result", stats}};
      }
      //
      else if (method == "syncstatus") {
        uint64_t localHeight = blockchain->getHeight();
        uint64_t networkHeight = 0;
        bool synced = false;
        if (network && network->getPeerManager()) {
          networkHeight = network->getPeerManager()->getMedianNetworkHeight();
          if (networkHeight == 0) {
            networkHeight = network->getPeerManager()->getMaxPeerHeight();
          }
          if (networkHeight == 0) {
            networkHeight = localHeight;
          }
          synced = (localHeight >= networkHeight);
        } else {
          networkHeight = localHeight;
          synced = true; // assume synced if no network
        }
        nlohmann::json status = {{"local_height", localHeight},
                                 {"network_height", networkHeight},
                                 {"synced", synced}};
        output = {{"result", status}};
      } else if (method == "peercount") {
        int pc = 0;
        if (network && network->getPeerManager())
          pc = network->getPeerManager()->getPeerCount();
        output = {{"result", pc}};
      } else if (method == "peerlist") {
        std::vector<std::string> peers;
        if (network && network->getPeerManager())
          peers = network->getPeerManager()->getConnectedPeers();
        output = {{"result", peers}};
      } else if (method == "selfheal") {
        if (healer) {
          healer->monitorAndHeal();
          output = {{"result", "Self-heal triggered"}};
        } else {
          output = {{"error", "Healer unavailable"}};
        }
      }
      // Send L1 Transaction
      else if (method == "sendl1" || method == "sendl2") {
        if (!params.is_array() || params.size() < 4 || !params[0].is_string() ||
            !params[1].is_string() || !params[3].is_string()) {
          params_error(
              "sendl1/sendl2 expect [sender, recipient, amount, metadata]");
        } else {
          auto amountParam = params[2];
          double amount = 0.0;
          bool amountOk = false;
          if (amountParam.is_number_float() || amountParam.is_number_integer()) {
            amount = amountParam.get<double>();
            amountOk = true;
          } else if (amountParam.is_string()) {
            try {
              amount = std::stod(amountParam.get<std::string>());
              amountOk = true;
            } catch (const std::exception &) {
              amountOk = false;
            }
          }
          if (!amountOk) {
            params_error("Invalid amount parameter");
          } else {
            std::string from = params[0].get<std::string>();
            std::string to = params[1].get<std::string>();
            std::string metadata = params[3].get<std::string>();

            auto resolved = Crypto::resolveWalletKeyIdentifier(from);
            std::string keyId = resolved.value_or(from);

            auto dil = Crypto::loadDilithiumKeys(keyId);
            auto fal = Crypto::loadFalconKeys(keyId);
            if (dil.publicKey.empty() || fal.publicKey.empty() ||
                dil.privateKey.empty() || fal.privateKey.empty()) {
              output = {{"error",
                         "Missing PQ key material for sender (" + keyId +
                             ")"}};
            } else {
              std::string canonicalSender;
              std::vector<unsigned char> pubDil(dil.publicKey.begin(),
                                                dil.publicKey.end());
              if (!pubDil.empty()) {
                canonicalSender = Crypto::deriveAddressFromPub(pubDil);
              } else {
                std::vector<unsigned char> pubFal(fal.publicKey.begin(),
                                                  fal.publicKey.end());
                if (!pubFal.empty())
                  canonicalSender = Crypto::deriveAddressFromPub(pubFal);
              }
              if (canonicalSender.empty())
                canonicalSender = from;

              Transaction tx(canonicalSender, to, amount, "", metadata,
                              time(nullptr));
              if (method == "sendl2")
                tx.setMetadata("L2:" + metadata);
              tx.setSenderPublicKeyDilithium(std::string(
                  reinterpret_cast<const char *>(dil.publicKey.data()),
                  dil.publicKey.size()));
              tx.setSenderPublicKeyFalcon(std::string(
                  reinterpret_cast<const char *>(fal.publicKey.data()),
                  fal.publicKey.size()));
              tx.signTransaction(dil.privateKey, fal.privateKey);
              if (!tx.getSignatureDilithium().empty() &&
                  !tx.getSignatureFalcon().empty()) {
                blockchain->addTransaction(tx);
                blockchain->savePendingTransactionsToDB();
                if (network)
                  network->broadcastTransaction(tx);
                output = {{"result", "Transaction broadcasted"},
                          {"sender", canonicalSender},
                          {"key_id", keyId}};
              } else {
                output = {{"error", "Transaction signing failed"}};
              }
            }
          }
        }
      }
      // Rollup Block
      else if (method == "rollup" || method == "recursive-rollup") {
        std::string walletAddr = params.at(0);
        blockchain->loadPendingTransactionsFromDB();
        std::vector<Transaction> allTxs = blockchain->getPendingTransactions();
        blockchain->setPendingL2TransactionsIfNotInRollups(allTxs);
        std::vector<Transaction> l2Transactions =
            blockchain->getPendingL2Transactions();
        if (l2Transactions.empty()) {
          output = {{"error", "No pending L2 transactions to roll up"}};
        } else {
          std::unordered_map<std::string, double> stateBefore =
              blockchain->getCurrentState();
          std::unordered_map<std::string, double> stateAfter =
              blockchain->simulateL2StateUpdate(stateBefore, l2Transactions);

          RollupBlock rollup(blockchain->getRollupChainSize(),
                             blockchain->getLastRollupHash(), l2Transactions);
          std::string prevRecursive = blockchain->getLastRollupProof();
          rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);

          if (blockchain->isRollupBlockValid(rollup)) {
            blockchain->addRollupBlock(rollup);
            if (network)
              network->broadcastRollupBlock(rollup);
            output = {{"result", rollup.getHash()}};
          } else {
            output = {{"error", "Rollup Block creation failed: Proof invalid"}};
          }
        }
      }
      // Transaction History
      else if (method == "history") {
        std::string addr = params.at(0);
        Blockchain &b = Blockchain::getInstance();
        b.loadFromDB();
        b.reloadBlockchainState();
        std::vector<nlohmann::json> relevant;
        std::unordered_map<std::string, std::string> txType;
        std::unordered_set<std::string> seen;
        auto toLower = [](std::string s) {
          std::transform(s.begin(), s.end(), s.begin(), ::tolower);
          return s;
        };
        std::string addrLower = toLower(addr);
        auto blocks = b.getAllBlocks();
        for (const auto &blk : blocks) {
          std::string blockMiner = toLower(blk.getMinerAddress());
          double reward = blk.getReward();
          for (const auto &tx : blk.getTransactions()) {
            std::string hash =
                tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            if (!seen.count(hash) &&
                (toLower(tx.getSender()) == addrLower ||
                 toLower(tx.getRecipient()) == addrLower)) {
              relevant.push_back({{"from", tx.getSender()},
                                  {"to", tx.getRecipient()},
                                  {"amount", tx.getAmount()},
                                  {"metadata", tx.getMetadata()},
                                  {"hash", hash},
                                  {"timestamp", tx.getTimestamp()},
                                  {"type", "L1"}});
              txType[hash] = "L1";
              seen.insert(hash);
            }
          }
          if (blockMiner == addrLower && reward > 0.0) {
            Transaction rewardTx = Transaction::createSystemRewardTransaction(
                blk.getMinerAddress(), reward, blk.getTimestamp(),
                "mined_" + blk.getHash());
            std::string rewardHash = rewardTx.getHash();
            if (!seen.count(rewardHash)) {
              relevant.push_back({{"from", "system"},
                                  {"to", rewardTx.getRecipient()},
                                  {"amount", rewardTx.getAmount()},
                                  {"metadata", rewardTx.getMetadata()},
                                  {"hash", rewardHash},
                                  {"timestamp", rewardTx.getTimestamp()},
                                  {"type", "Mined"}});
              txType[rewardHash] = "Mined";
              seen.insert(rewardHash);
            }
          }
        }
        auto rollups = b.getAllRollupBlocks();
        for (const auto &roll : rollups) {
          for (const auto &tx : roll.getTransactions()) {
            std::string hash =
                tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
            if (!seen.count(hash) &&
                (toLower(tx.getSender()) == addrLower ||
                 toLower(tx.getRecipient()) == addrLower)) {
              relevant.push_back({{"from", tx.getSender()},
                                  {"to", tx.getRecipient()},
                                  {"amount", tx.getAmount()},
                                  {"metadata", tx.getMetadata()},
                                  {"hash", hash},
                                  {"timestamp", tx.getTimestamp()},
                                  {"type", "L2"}});
              txType[hash] = "L2";
              seen.insert(hash);
            }
          }
        }
        // Add mempool or DB-only txs (optional, if used in your chain)
        auto allTxs = Transaction::loadAllFromDB();
        for (const auto &tx : allTxs) {
          std::string hash =
              tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
          if (!seen.count(hash) && (toLower(tx.getSender()) == addrLower ||
                                    toLower(tx.getRecipient()) == addrLower)) {
            relevant.push_back({{"from", tx.getSender()},
                                {"to", tx.getRecipient()},
                                {"amount", tx.getAmount()},
                                {"metadata", tx.getMetadata()},
                                {"hash", hash},
                                {"timestamp", tx.getTimestamp()},
                                {"type", "L1"}});
            txType[hash] = "L1";
            seen.insert(hash);
          }
        }
        // Sort by timestamp ascending
        std::sort(relevant.begin(), relevant.end(),
                  [](const nlohmann::json &a, const nlohmann::json &b) {
                    return a.value("timestamp", 0) < b.value("timestamp", 0);
                  });
        // Return as JSON array
        output = {{"result", relevant}};
      }

      // DAO Proposal Submission
      else if (method == "dao-submit") {
        std::string from = params.at(0);
        std::string desc = params.at(1);
        int type = params.at(2);
        double amt = params.at(3);
        std::string target = params.at(4);
        Proposal prop;
        prop.proposal_id = Crypto::sha256(Crypto::generateRandomHex(16));
        prop.proposer_address = from;
        prop.description = desc;
        prop.type = static_cast<ProposalType>(type);
        prop.transfer_amount = amt;
        prop.target_address = target;
        prop.creation_time = std::time(nullptr);
        prop.deadline_time = prop.creation_time + 86400;
        prop.status = ProposalStatus::PENDING;

        if (DAO::createProposal(prop)) {
          output = {{"result", prop.proposal_id}};
        } else {
          output = {{"error", "Failed to submit proposal"}};
        }
      }
      // DAO Voting
      else if (method == "dao-vote") {
        std::string from = params.at(0);
        std::string propID = params.at(1);
        std::string vote = params.at(2);
        bool yes = (vote == "yes" || vote == "y");
        double weight = blockchain->getBalance(from);
        if (DAO::castVote(propID, from, yes, static_cast<uint64_t>(weight))) {
          output = {{"result", "Vote cast"}};
        } else {
          output = {{"error", "Failed to vote"}};
        }
      }
      // Dev Fund Balance
      else if (method == "devfund") {
        output = {{"result", blockchain->getBalance("DevFundWallet")}};
      }
      // Mined block stats
      else if (method == "mychain") {
        std::string addr = params.at(0);
        int count = 0;
        double reward = 0.0;
        for (const auto &blk : blockchain->getAllBlocks()) {
          if (blk.getMinerAddress() == addr) {
            count++;
            reward += blk.getReward();
          }
        }
        output = {
            {"result", {{"blocks_mined", count}, {"total_rewards", reward}}}};
      }

      // ===================== SWAP SPACE =====================
      else if (method == "swap-initiate") {
        std::string sender = params.at(0).get<std::string>();
        std::string receiver = params.at(1).get<std::string>();
        uint64_t amount = std::stoull(params.at(2).get<std::string>());
        std::string secretHash = params.at(3).get<std::string>();
        time_t duration =
            static_cast<time_t>(std::stoll(params.at(4).get<std::string>()));
        auto resolvedSender = Crypto::resolveWalletKeyIdentifier(sender);
        std::string senderKeyId = resolvedSender.value_or(sender);
        auto senderDil = Crypto::loadDilithiumKeys(senderKeyId);
        auto senderFal = Crypto::loadFalconKeys(senderKeyId);
        if (senderDil.privateKey.empty() || senderFal.privateKey.empty()) {
          output = {{"error", "Missing key files for wallet: " + senderKeyId}};
        } else {
          auto uuidOpt = swapMgr.initiateSwap(sender, receiver, amount,
                                              secretHash, duration);
          if (uuidOpt)
            output = {{"result", *uuidOpt}};
          else
            output = {{"error", "Failed to create swap"}};
        }
      } else if (method == "swap-redeem") {
        std::string uuid = params.at(0).get<std::string>();
        std::string secret = params.at(1).get<std::string>();
        auto s = swapMgr.getSwap(uuid);
        if (!s) {
          output = {{"error", "Swap not found"}};
        } else {
          std::ifstream cur(DBPaths::getHomePath() +
                            "/.alyncoin/current_wallet.txt");
          std::string current;
          std::getline(cur, current);
          if (current.empty()) {
            output = {{"error", "No wallet loaded"}};
          } else if (current != s->receiverAddress) {
            output = {
                {"error", "Redeem must be called by the receiver wallet"}};
          } else if (secret.empty()) {
            output = {{"error", "secret is required"}};
          } else {
            auto resolvedCurrent = Crypto::resolveWalletKeyIdentifier(current);
            std::string currentKeyId = resolvedCurrent.value_or(current);
            auto dil = Crypto::loadDilithiumKeys(currentKeyId);
            auto fal = Crypto::loadFalconKeys(currentKeyId);
            if (dil.privateKey.empty() || fal.privateKey.empty()) {
              output = {{"error", "Missing key files for wallet: " +
                                     currentKeyId}};
            } else {
              bool ok = swapMgr.redeemSwap(uuid, secret);
              output = ok ? nlohmann::json{{"result", "Swap redeemed"}}
                          : nlohmann::json{{"error", "Redeem failed"}};
            }
          }
        }
      } else if (method == "swap-refund") {
        std::ifstream cur(DBPaths::getHomePath() +
                          "/.alyncoin/current_wallet.txt");
        std::string current;
        std::getline(cur, current);
        if (current.empty()) {
          output = {{"error", "No wallet loaded"}};
        } else {
          auto resolvedCurrent = Crypto::resolveWalletKeyIdentifier(current);
          std::string currentKeyId = resolvedCurrent.value_or(current);
          auto dil = Crypto::loadDilithiumKeys(currentKeyId);
          auto fal = Crypto::loadFalconKeys(currentKeyId);
          if (dil.privateKey.empty() || fal.privateKey.empty()) {
            output = {{"error", "Missing key files for wallet: " +
                                   currentKeyId}};
          } else {
            bool ok = swapMgr.refundSwap(params.at(0).get<std::string>());
            output = ok ? nlohmann::json{{"result", "Swap refunded"}}
                        : nlohmann::json{{"error", "Refund failed"}};
          }
        }
      } else if (method == "swap-get") {
        auto s = swapMgr.getSwap(params.at(0).get<std::string>());
        if (s) {
          nlohmann::json j{{"uuid", s->uuid},
                           {"sender", s->senderAddress},
                           {"receiver", s->receiverAddress},
                           {"amount", s->amount},
                           {"secretHash", s->secretHash},
                           {"secret", s->secret.value_or("")},
                           {"createdAt", s->createdAt},
                           {"expiresAt", s->expiresAt},
                           {"state", static_cast<int>(s->state)}};
          output = {{"result", j}};
        } else {
          output = {{"error", "Swap not found"}};
        }
      } else if (method == "swap-state") {
        SwapState st = swapMgr.getSwapState(params.at(0).get<std::string>());
        output = {{"result", static_cast<int>(st)}};
      } else if (method == "swap-verify") {
        auto s = swapMgr.getSwap(params.at(0).get<std::string>());
        if (s && verifySwapSignature(*s)) {
          output = {{"result", "Signature valid"}};
        } else {
          output = {{"error", "Invalid signature or swap not found"}};
        }
      } else if (method == "swap-verifyproof") {
        auto s = swapMgr.getSwap(params.at(0).get<std::string>());
        if (!s || !s->zkProof) {
          output = {{"error", "No proof"}};
        } else {
          std::string canonical =
              s->uuid + s->senderAddress + s->receiverAddress +
              std::to_string(s->amount) + s->secretHash +
              std::to_string(s->createdAt) + std::to_string(s->expiresAt);
          std::string seed = Crypto::blake3(canonical);
          std::string expected = std::to_string(s->amount);
          bool ok = WinterfellStark::verifyProof(*s->zkProof, seed,
                                                 "AtomicSwapProof", expected);
          output = ok ? nlohmann::json{{"result", "Proof valid"}}
                      : nlohmann::json{{"error", "Proof invalid"}};
        }
      }

      // ===================== NFT SPACE =====================
      else if (method == "nft-mint") {
        // params: [creator, metadata, imageHash, identity (optional)]
        std::string creator = params.at(0);
        std::string metadata = params.at(1);
        std::string imageHash = params.at(2);
        std::string identity = params.size() > 3 ? params.at(3) : "";

        auto resolvedCreator = Crypto::resolveWalletKeyIdentifier(creator);
        std::string keyId = resolvedCreator.value_or(creator);

        std::string privKeyPath =
            DBPaths::getKeyDir() + keyId + "_private.pem";
        if (!std::filesystem::exists(privKeyPath)) {
          output = {
              {"error", "Missing private key file for wallet: " + privKeyPath}};
        } else {
          int64_t ts = std::time(nullptr);
          std::string id = generateNFTID(creator, imageHash, ts);
          std::string message = id + creator + creator + metadata + imageHash +
                                std::to_string(ts);
          auto msgHash = Crypto::sha256ToBytes(message);
          auto keypair = Crypto::loadFalconKeys(keyId);
          if (keypair.privateKey.empty()) {
            output = {{"error", "Missing Falcon key material for wallet: " +
                                   creator}};
          } else {
            std::vector<uint8_t> sig =
                Crypto::signWithFalcon(msgHash, keypair.privateKey);

            NFT nft{id, creator, creator, metadata, imageHash, ts, sig};
            nft.creator_identity = identity;
            nft.generateZkStarkProof();

            if (!nft.submitMetadataHashTransaction()) {
              output = {{"error", "Metadata transaction failed"}};
            } else if (!nft.verifySignature() ||
                       !NFTStorage::saveNFT(nft, blockchain->getRawDB())) {
              output = {{"error", "Failed to verify or save NFT"}};
            } else {
              output = {{"result", id}};
            }
          }
        }
      } else if (method == "nft-transfer") {
        // params: [nftID, newOwner, currentUser]
        std::string nftID = params.at(0);
        std::string newOwner = params.at(1);
        std::string current = params.at(2);
        NFT nft;
        if (!NFTStorage::loadNFT(nftID, nft, blockchain->getRawDB())) {
          output = {{"error", "NFT not found"}};
        } else if (nft.owner != current || nft.revoked) {
          output = {{"error", "Not the owner or NFT is revoked"}};
        } else {
          nft.transferHistory.push_back(current);
          nft.owner = newOwner;
          nft.timestamp = std::time(nullptr);
          std::string message = nft.getSignatureMessage();
          auto msgHash = Crypto::sha256ToBytes(message);
          auto resolvedCurrent = Crypto::resolveWalletKeyIdentifier(current);
          std::string currentKeyId = resolvedCurrent.value_or(current);
          auto keypair = Crypto::loadFalconKeys(currentKeyId);
          if (keypair.privateKey.empty()) {
            output = {{"error", "Missing Falcon key material for wallet: " +
                                   current}};
          } else {
            nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

            if (!nft.verifySignature() ||
                !NFTStorage::saveNFT(nft, blockchain->getRawDB())) {
              output = {{"error", "Failed to verify or save transfer"}};
            } else {
              output = {{"result", "NFT transferred"}};
            }
          }
        }
      } else if (method == "nft-remint") {
        // params: [id, newMetadata, reason, currentUser]
        std::string id = params.at(0);
        std::string newMetadata = params.at(1);
        std::string reason = params.at(2);
        std::string currentUser = params.at(3);

        if (currentUser.empty()) {
          output = {{"error", "No wallet loaded or passed"}};
        } else {
          NFT nft;
          if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
            output = {{"error", "NFT not found"}};
          } else if (nft.owner != currentUser || nft.revoked) {
            output = {{"error", "You are not the owner or NFT is revoked"}};
          } else {
            int newVersion = 1;
            if (!nft.version.empty()) {
              try {
                newVersion = std::stoi(nft.version) + 1;
              } catch (...) {
                newVersion = 1;
              }
            }
            int64_t ts = std::time(nullptr);
            std::string newId = generateNFTID(currentUser, nft.imageHash, ts);
            std::string message = newId + currentUser + currentUser +
                                  newMetadata + nft.imageHash +
                                  std::to_string(ts);
            auto msgHash = Crypto::sha256ToBytes(message);
            auto resolvedCurrent = Crypto::resolveWalletKeyIdentifier(currentUser);
            std::string currentKeyId = resolvedCurrent.value_or(currentUser);
            auto keys = Crypto::loadFalconKeys(currentKeyId);
            if (keys.privateKey.empty()) {
              output = {{"error", "Missing Falcon key material for wallet: " +
                                     currentUser}};
            } else {
              std::vector<uint8_t> sig =
                  Crypto::signWithFalcon(msgHash, keys.privateKey);

              NFT updated{newId,         currentUser, currentUser, newMetadata,
                          nft.imageHash, ts,          sig};
              updated.version = std::to_string(newVersion);
              updated.creator_identity = nft.creator_identity;
              updated.expiry_timestamp = nft.expiry_timestamp;
              updated.previous_versions = nft.previous_versions;
              updated.previous_versions.push_back(nft.id);

              updated.generateZkStarkProof();

              std::string rehash = Crypto::sha256(
                  updated.metadata + updated.imageHash + updated.version);
              if (!submitMetadataHashTransaction(rehash, currentUser, "falcon",
                                                 true)) {
                output = {{"error", "Metadata transaction failed"}};
              } else if (!updated.verifySignature() ||
                         !NFTStorage::saveNFT(updated, blockchain->getRawDB())) {
                output = {{"error", "Failed to verify or save updated NFT"}};
              } else {
                output = {{"result", newId}};
              }
            }
          }
        }
      } else if (method == "nft-export") {
        // params: [id]
        std::string id = params.at(0);
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
          output = {{"error", "NFT not found"}};
        } else {
          nft.exportToFile();
          output = {{"result", "Exported"}};
        }
      } else if (method == "nft-encrypt") {
        // params: [id, plaintext, password]
        std::string id = params.at(0);
        std::string plaintext = params.at(1);
        std::string password = params.at(2);
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
          output = {{"error", "NFT not found"}};
        } else {
          nft.encrypted_metadata = AES::encrypt(plaintext, password);
          NFTStorage::saveNFT(nft, blockchain->getRawDB());
          output = {{"result", "Encrypted metadata stored"}};
        }
      } else if (method == "nft-decrypt") {
        // params: [id, password]
        std::string id = params.at(0);
        std::string password = params.at(1);
        NFT nft;
        if (!NFTStorage::loadNFT(id, nft, blockchain->getRawDB())) {
          output = {{"error", "NFT not found"}};
        } else if (nft.encrypted_metadata.empty()) {
          output = {{"result", "No encrypted metadata"}};
        } else {
          try {
            std::string decrypted =
                AES::decrypt(nft.encrypted_metadata, password);
            output = {{"result", decrypted}};
          } catch (const std::exception &e) {
            output = {{"error", std::string("Decryption failed: ") + e.what()}};
          }
        }
      } else if (method == "nft-my") {
        // params: [walletAddress]
        std::string current = params.at(0);
        auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
        std::vector<nlohmann::json> owned;
        for (const auto &nft : all) {
          if (nft.owner == current)
            owned.push_back(nlohmann::json::parse(nft.toJSON()));
        }
        output = {{"result", owned}};
      } else if (method == "nft-all") {
        // params: []
        auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
        std::vector<nlohmann::json> allJson;
        for (const auto &nft : all) {
          allJson.push_back(nlohmann::json::parse(nft.toJSON()));
        }
        output = {{"result", allJson}};
      } else if (method == "nft-stats") {
        // params: []
        auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
        int total = 0, zk = 0;
        std::map<std::string, int> typeCount;
        for (const auto &nft : all) {
          ++total;
          if (!nft.zkStarkProof.empty())
            ++zk;
          if (!nft.nft_type.empty())
            typeCount[nft.nft_type]++;
        }
        std::string topType = "N/A";
        int max = 0;
        for (auto &[type, count] : typeCount) {
          if (count > max) {
            max = count;
            topType = type;
          }
        }
        output = {{"result",
                   {{"total", total},
                    {"zk-stark", zk},
                    {"most_common_type", topType}}}};
      } else if (method == "nft-verifyhash") {
        // params: [fileDataOrPath]
        std::string filepath = params.at(0);
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
          output = {{"error", "File not found: " + filepath}};
        } else {
          std::ostringstream buffer;
          buffer << file.rdbuf();
          std::string contents = buffer.str();
          std::string fileHash = Crypto::sha256(contents);
          auto all = NFTStorage::loadAllNFTs(blockchain->getRawDB());
          auto match = std::find_if(all.begin(), all.end(),
                                    [&](const auto &nft) {
                                      return nft.imageHash == fileHash;
                                    });
          if (match != all.end()) {
            output = {{"result", nlohmann::json::parse(match->toJSON())}};
          } else {
            output = {{"error", "No NFT found matching the file hash"}};
          }
        }
      }
      // ================== END NFT SPACE ==================

      // Unknown method fallback
      else {
        output = {
            {"error", {{"code", -32601}, {"message", "Method not found"}}}};
      }
    } catch (const std::exception &e) {
      std::cerr << "❌ [RPC] Exception while handling method '" << method
                << "': " << e.what() << "\n";
      output = {{"error", {{"code", -32603}, {"message", e.what()}}}};
    } catch (...) {
      std::cerr << "❌ [RPC] Unknown exception while handling method '"
                << method << "'\n";
      output = {{"error", {{"code", -32603}, {"message", "internal error"}}}};
    }

    if (output.contains("error")) {
      if (output["error"].is_string()) {
        std::string msg = output["error"].get<std::string>();
        output["error"] = {{"code", -32000}, {"message", msg}};
      } else {
        if (!output["error"].contains("code"))
          output["error"]["code"] = -32000;
        if (!output["error"].contains("message"))
          output["error"]["message"] = "";
      }
    }

    output["jsonrpc"] = "2.0";
    output["id"] = id;
    res.status = 200;
    res.set_content(output.dump(), "application/json");
    set_cors(res);
  });

  printf("🚀 [AlynCoin RPC] Listening on http://%s:%d/rpc\n", rpc_host.c_str(),
         rpc_port);
  svr.listen(rpc_host.c_str(), rpc_port);
}

void clearInputBuffer() {
  std::cin.clear();
  std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

static bool handleNodeMenuSelection(int choice, Blockchain &blockchain,
                                    Network *network,
                                    SelfHealingNode &healer,
                                    const std::string &keyDir) {
  switch (choice) {
  case 1: {
    std::cout << "\n=== Blockchain Stats ===\n";
    std::cout << "Total Blocks: " << blockchain.getBlockCount() << "\n";
    std::cout << "Difficulty: " << calculateSmartDifficulty(blockchain)
              << "\n";
    std::cout << "Total Supply: " << blockchain.getTotalSupply()
              << " AlynCoin\n";
    std::cout << "Total Burned Supply: " << blockchain.getTotalBurnedSupply()
              << " AlynCoin\n";
    std::cout << "Dev Fund Balance: "
              << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
    return true;
  }

  case 2: {
    std::string minerAddress;
    std::cout << "Enter miner address: ";
    std::cin >> minerAddress;
    Block mined = blockchain.mineBlock(minerAddress);
    if (!mined.getHash().empty()) {
      blockchain.saveToDB();
      blockchain.savePendingTransactionsToDB();
      if (network)
        network->broadcastBlock(mined);
      blockchain.reloadBlockchainState();
      std::cout << "✅ Block mined and broadcasted.\n";
    }
    return true;
  }

  case 3:
    blockchain.printBlockchain();
    return true;

  case 4: {
    std::string minerAddress;
    std::cout << "Enter miner address: ";
    std::cin >> minerAddress;
    Miner::startMiningProcess(minerAddress);
    return true;
  }

  case 5:
    if (network) {
      network->scanForPeers();
      network->requestPeerList();
      network->intelligentSync();
    }
    return true;

  case 6:
    std::cout << "Dev Fund Balance: "
              << blockchain.getBalance("DevFundWallet") << " AlynCoin\n";
    return true;

  case 7: {
    std::string addr;
    std::cout << "Enter address: ";
    std::cin >> addr;
    std::cout << "Balance: " << blockchain.getBalance(addr) << " AlynCoin\n";
    return true;
  }

  case 8: {
    blockchain.loadPendingTransactionsFromDB();
    auto allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);
    auto l2Transactions = blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
      std::cout << "⚠️ No pending L2 transactions to roll up.\n";
      return true;
    }
    auto stateBefore = blockchain.getCurrentState();
    auto stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);
    RollupBlock rollup(blockchain.getRollupChainSize(),
                       blockchain.getLastRollupHash(), l2Transactions);
    std::string prevRecursive = blockchain.getLastRollupProof();
    rollup.generateRollupProof(stateBefore, stateAfter, prevRecursive);
    if (blockchain.isRollupBlockValid(rollup)) {
      blockchain.addRollupBlock(rollup);
      if (network)
        network->broadcastRollupBlock(rollup);
      std::cout << "✅ Rollup Block created. Hash: " << rollup.getHash()
                << "\n";
    } else {
      std::cout << "❌ Rollup Block creation failed.\n";
    }
    return true;
  }

  case 9:
    std::cout << "Shutting down AlynCoin Node...\n";
    return false;

  case 10:
    std::cout << "🩺 Manually triggering self-healing check...\n";
    healer.monitorAndHeal();
    return true;

  case 12: {
    std::string name;
    std::string outPath;
    std::cout << "Enter wallet name (leave blank for current): ";
    std::getline(std::cin >> std::ws, name);
    if (name.empty()) {
      std::ifstream cur(DBPaths::getHomePath() +
                        "/.alyncoin/current_wallet.txt");
      std::getline(cur, name);
    }
    if (name.empty()) {
      std::cout << "❌ No wallet name provided and no current wallet set\n";
      return true;
    }
    std::cout << "Enter output file path: ";
    std::getline(std::cin, outPath);
    exportWalletToFile(keyDir, blockchain, name, outPath);
    return true;
  }

  case 13: {
    std::string inPath;
    std::cout << "Enter backup file path: ";
    std::getline(std::cin >> std::ws, inPath);
    importWalletFromFile(keyDir, inPath);
    return true;
  }

  default:
    std::cout << "Invalid choice!\n";
    return true;
  }
}

int main(int argc, char *argv[]) {
  std::srand(std::time(nullptr));
  loadConfigFile("config.ini");
  unsigned short port = DEFAULT_PORT;
  bool portSpecified = false;
  unsigned short rpcPort = 1567;
  bool rpcPortSpecified = false;
  std::string rpcBindHost = "127.0.0.1";
  std::string dbPath = DBPaths::getBlockchainDB();
  std::string connectIP = "";
  std::string keyDir = DBPaths::getKeyDir();
  bool autoMine = true;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h" || arg == "help") {
      print_usage();
      return 0;
    } else if (arg == "--port" && i + 1 < argc) {
      port = static_cast<unsigned short>(std::stoi(argv[++i]));
      portSpecified = true;
      std::cout << "🌐 Using custom port: " << port << std::endl;
    } else if (arg == "--rpcport" && i + 1 < argc) {
      rpcPort = static_cast<unsigned short>(std::stoi(argv[++i]));
      rpcPortSpecified = true;
      std::cout << "🔌 Using RPC port: " << rpcPort << std::endl;
    } else if (arg.rfind("--rpc-bind", 0) == 0) {
      std::string val;
      if (arg == "--rpc-bind" && i + 1 < argc)
        val = argv[++i];
      else if (arg.find("--rpc-bind=") == 0)
        val = arg.substr(11);
      auto pos = val.find(':');
      if (pos != std::string::npos) {
        rpcBindHost = val.substr(0, pos);
        rpcPort = static_cast<unsigned short>(std::stoi(val.substr(pos + 1)));
        rpcPortSpecified = true;
        std::cout << "🔌 RPC bind: " << rpcBindHost << ':' << rpcPort
                  << std::endl;
      }
    } else if (arg == "--rpc-cors" && i + 1 < argc) {
      getAppConfig().rpc_cors = argv[++i];
    } else if (arg == "--self-heal-interval" && i + 1 < argc) {
      getAppConfig().self_heal_interval = std::stoi(argv[++i]);
    } else if (arg == "--reserve-address" && i + 1 < argc) {
      getAppConfig().reserve_address = argv[++i];
    } else if (arg == "--por-expected-walyn" && i + 1 < argc) {
      getAppConfig().por_expected_walyn = std::stod(argv[++i]);
    } else if (arg == "--dbpath" && i + 1 < argc) {
      dbPath = argv[++i];
      std::cout << "📁 Using custom DB path: " << dbPath << std::endl;
    } else if ((arg == "--connect" || arg == "--peer") && i + 1 < argc) {
      connectIP = argv[++i];
      std::cout << "🔗 Will connect to peer: " << connectIP << std::endl;
    } else if (arg == "--keypath" && i + 1 < argc) {
      keyDir = argv[++i];
      if (keyDir.back() != '/')
        keyDir += '/';
    } else if (arg == "--no-auto-mine") {
      autoMine = false;
    } else if (arg == "--banminutes" && i + 1 < argc) {
      getAppConfig().ban_minutes = std::stoi(argv[++i]);
    }
  }
  if (!portSpecified) {
    unsigned short newPort = Network::findAvailablePort(port);
    if (newPort != 0 && newPort != port) {
      port = newPort;
      std::cout << "🌐 Auto-selected available port: " << port << std::endl;
    }
  }

  if (port == rpcPort) {
    if (!rpcPortSpecified) {
      ++rpcPort;
      std::cout << "🔌 RPC port adjusted to " << rpcPort
                << " to avoid conflict with network port" << std::endl;
    } else if (!portSpecified) {
      ++port;
      std::cout << "🌐 Network port adjusted to " << port
                << " to avoid conflict with RPC port" << std::endl;
    } else {
      std::cerr << "❌ Network port and RPC port cannot be the same."
                << std::endl;
      return 1;
    }
  }
  getAppConfig().rpc_bind = rpcBindHost + ":" + std::to_string(rpcPort);
  std::cout << "🔌 RPC bind: " << rpcBindHost << ':' << rpcPort << std::endl;
  if (!getAppConfig().rpc_cors.empty())
    std::cout << "🌐 RPC CORS: " << getAppConfig().rpc_cors << std::endl;
  if (getAppConfig().self_heal_interval > 0)
    std::cout << "🩺 Self-heal interval: " << getAppConfig().self_heal_interval
              << " sec\n";
  if (!getAppConfig().reserve_address.empty())
    std::cout << "🏦 Reserve address: " << getAppConfig().reserve_address
              << std::endl;
  if (getAppConfig().por_expected_walyn > 0)
    std::cout << "💱 Expected wALYN: " << getAppConfig().por_expected_walyn
              << std::endl;
  std::string blacklistPath = dbPath + "/blacklist";
  {
    std::error_code ec;
    std::filesystem::create_directories(blacklistPath, ec);
    if (ec) {
      std::cerr << "⚠️ Failed to create blacklist directory '" << blacklistPath
                << "': " << ec.message() << "\n";
    }
  }

  // Initialize blockchain without binding to the network yet. The network
  // instance will be created immediately afterwards and injected via
  // setNetwork(), preventing the misleading startup warning.
  Blockchain &blockchain =
      Blockchain::getInstance(port, dbPath, /*bindNetwork=*/false);

  std::unique_ptr<PeerBlacklist> peerBlacklistPtr;
  try {
    peerBlacklistPtr = std::make_unique<PeerBlacklist>(blacklistPath, 3);
  } catch (const std::exception &e) {
    std::cerr << "❌ Failed to init PeerBlacklist: " << e.what() << "\n";
    peerBlacklistPtr = nullptr;
  }

  Network *network = nullptr;
  if (peerBlacklistPtr) {
    Network::autoMineEnabled = autoMine;
    network = &Network::getInstance(port, &blockchain, peerBlacklistPtr.get());
    blockchain.setNetwork(network);
  } else {
    std::cerr << "⚠️ Network disabled due to PeerBlacklist failure.\n";
  }

  blockchain.loadFromDB();
  blockchain.reloadBlockchainState();

  // Ensure a miner keypair exists so mining can start without manual setup
  Crypto::ensureMinerKeys();

  PeerManager *peerManager = network ? network->getPeerManager() : nullptr;
  SelfHealingNode healer(&blockchain, peerManager);

  if (getAppConfig().self_heal_interval > 0) {
    int interval = getAppConfig().self_heal_interval;
    std::thread autoHealThread([&, interval]() {
      while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        std::cout << "\n🩺 [Auto-Heal] Running periodic health monitor...\n";
        healer.monitorAndHeal();
      }
    });
    autoHealThread.detach();
  }

  // ---- Start RPC server in background thread ----
  std::thread rpc_thread(start_rpc_server, &blockchain, network, &healer,
                         rpcBindHost, rpcPort);
  rpc_thread.detach();

  // ---- Helpers for CLI block ----
  static std::unordered_set<std::string> cliSeenTxHashes;
  auto getBlockchain = []() -> Blockchain & {
    return Blockchain::getInstance();
  };
  Blockchain *chainPtr = &Blockchain::getInstance();
  std::string cmd = (argc >= 2) ? std::string(argv[1]) : "";

  // ================= CLI COMMAND HANDLERS START =================
  std::string currentBinPath = argv[0];

  // export-genesis <file>
  if (argc >= 3 && std::string(argv[1]) == "export-genesis") {
    std::string path = argv[2];
    Blockchain &b = Blockchain::getInstance();
    if (!b.loadFromDB()) {
      std::cerr << "❌ Could not load blockchain from DB.\n";
      return 1;
    }
    if (b.exportGenesisBlock(path)) {
      std::cout << "✅ Genesis block exported to " << path << "\n";
      return 0;
    }
    std::cerr << "❌ Failed to export genesis block.\n";
    return 1;
  }

  // import-genesis <file>
  if (argc >= 3 && std::string(argv[1]) == "import-genesis") {
    std::string path = argv[2];
    Blockchain &b = Blockchain::getInstance();
    if (b.importGenesisBlock(path)) {
      b.saveToDB();
      std::cout << "✅ Genesis block imported from " << path << "\n";
      return 0;
    }
    std::cerr << "❌ Failed to import genesis block.\n";
    return 1;
  }

  // mineonce <minerAddress>
  if (argc >= 3 && std::string(argv[1]) == "mineonce") {
    std::string minerAddress = argv[2];
    Blockchain &b = Blockchain::getInstance();

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
        Network::getInstance().broadcastBlock(
            minedBlock); // ✅ reuse existing Network instance
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
    Blockchain &b = Blockchain::getInstance();

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
            Network::getInstance().broadcastBlock(minedBlock); // ✅ no conflict
          }
        } catch (const std::exception &e) {
          std::cerr
              << "⚠️ reloadBlockchainState() skipped due to network error: "
              << e.what() << "\n";
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
      std::cout << "✅ YES: " << static_cast<uint64_t>(p.yes_votes)
                << " | ❌ NO: " << static_cast<uint64_t>(p.no_votes) << "\n";
      std::cout << "📌 Status: " << static_cast<int>(p.status) << "\n\n";
    }
    return 0;
  }
  // === Blockchain stats ===
  if (cmd == "stats" && argc >= 2) {
    Blockchain &b = Blockchain::getInstance();
    std::cout << "\n=== Blockchain Stats ===\n";
    std::cout << "Total Blocks: " << b.getBlockCount() << "\n";
    std::cout << "Difficulty: " << calculateSmartDifficulty(b) << "\n";
    std::cout << "Total Supply: " << b.getTotalSupply() << " AlynCoin\n";
    std::cout << "Total Burned Supply: " << b.getTotalBurnedSupply()
              << " AlynCoin\n";
    std::cout << "Dev Fund Balance: " << b.getBalance("DevFundWallet")
              << " AlynCoin\n";
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
    if (!pass.empty() && pass.size() < 8) {
      std::cerr << "⚠️ Passphrase must be at least 8 characters.\n";
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
        std::ofstream(keyDir + name + "_pass.txt") << Crypto::sha256(pass);
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
    if (!std::filesystem::exists(priv) || !std::filesystem::exists(dil) ||
        !std::filesystem::exists(fal)) {
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
      std::ofstream(DBPaths::getHomePath() + "/.alyncoin/current_wallet.txt")
          << w.getAddress();
      std::cout << "✅ Wallet loaded: " << w.getAddress() << std::endl;
    } catch (const std::exception &e) {
      std::cerr << "❌ Wallet load failed: " << e.what() << std::endl;
      return 1;
    }
    return 0;
  }
  if (cmd == "exportwallet" && argc >= 3) {
    std::string name;
    std::string outPath;
    if (argc >= 4) {
      name = argv[2];
      outPath = argv[3];
    } else {
      outPath = argv[2];
      std::ifstream cur(DBPaths::getHomePath() +
                        "/.alyncoin/current_wallet.txt");
      std::getline(cur, name);
      if (name.empty()) {
        std::cerr << "❌ No wallet name provided and no current wallet set\n";
        return 1;
      }
    }
    Blockchain &bb = Blockchain::getInstance();
    if (!exportWalletToFile(keyDir, bb, name, outPath))
      return 1;
    return 0;
  }
  if (cmd == "importwallet" && argc >= 3) {
    std::string inPath = argv[2];
    if (!importWalletFromFile(keyDir, inPath))
      return 1;
    return 0;
  }
  // === Balance check (normal or forced) ===
  if ((cmd == "balance" || cmd == "balance-force") && argc >= 3) {
    std::string addr = argv[2];
    // Use the no-network singleton to avoid DB locks
    Blockchain &bb = Blockchain::getInstance();
    if (cmd == "balance-force")
      bb.reloadBlockchainState();
    std::cout << "Balance: " << bb.getBalance(addr) << " AlynCoin" << std::endl;
    return 0;
  }
  // === sendl1 / sendl2 with duplicate filter ===
  if ((argc >= 6) &&
      (std::string(argv[1]) == "sendl1" || std::string(argv[1]) == "sendl2")) {
    std::string from = argv[2];
    std::string to = argv[3];
    std::string rawAmount = argv[4];
    std::string metadata = argv[5];

    double amount = -1;
    try {
      amount = std::stod(rawAmount);
    } catch (...) {
      std::cerr << "❌ Invalid amount format: " << rawAmount << "\n";
      return 1;
    }

    // ✅ Allow zero amount only for metadataSink transactions
    if (amount <= 0.0 && to != "metadataSink") {
      std::cerr << "❌ Invalid amount. Zero allowed only when sending to "
                   "metadataSink.\n";
      return 1;
    }

    Blockchain &b = Blockchain::getInstance();

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

    if (dil.publicKey.empty() || fal.publicKey.empty() ||
        dil.privateKey.empty() || fal.privateKey.empty()) {
      std::cerr << "❌ Missing PQ key material for sender: " << from << "\n";
      return 1;
    }

    std::string canonicalSender;
    std::vector<unsigned char> pubDil(dil.publicKey.begin(), dil.publicKey.end());
    if (!pubDil.empty()) {
      canonicalSender = Crypto::deriveAddressFromPub(pubDil);
    } else {
      std::vector<unsigned char> pubFal(fal.publicKey.begin(), fal.publicKey.end());
      if (!pubFal.empty()) {
        canonicalSender = Crypto::deriveAddressFromPub(pubFal);
      }
    }
    if (canonicalSender.empty()) {
      canonicalSender = from;
    }

    Transaction tx(canonicalSender, to, amount, "", metadata, time(nullptr));
    if (std::string(argv[1]) == "sendl2") {
      tx.setMetadata("L2:" + metadata);
    }
    tx.setSenderPublicKeyDilithium(std::string(
        reinterpret_cast<const char*>(dil.publicKey.data()), dil.publicKey.size()));
    tx.setSenderPublicKeyFalcon(std::string(
        reinterpret_cast<const char*>(fal.publicKey.data()), fal.publicKey.size()));

    // Hash-based deduplication for CLI too (mirrors network, prevents resending
    // on retry)
    std::string txHash = tx.getHash();
    if (cliSeenTxHashes.count(txHash)) {
      std::cerr << "⚠️ Transaction already submitted by this CLI session (hash "
                   "dedupe).\n";
      return 1;
    }

    for (const auto &existing : b.getPendingTransactions()) {
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
    if (!tx.getSignatureDilithium().empty() &&
        !tx.getSignatureFalcon().empty()) {
      b.addTransaction(tx);
      b.savePendingTransactionsToDB();
      if (!Network::isUninitialized()) {
        Network::getInstance().broadcastTransaction(tx);
      }
      std::cout << "✅ Transaction broadcasted: " << canonicalSender
                << " (key id: " << from << ") → " << to
                << " (" << amount << " AlynCoin, metadata: " << metadata
                << ")\n";
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
    if (argc >= 5)
      type = static_cast<ProposalType>(std::stoi(argv[4]));

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

    Blockchain &b = Blockchain::getInstance();
    double weight = b.getBalance(from);
    if (DAO::castVote(propID, from, yes, static_cast<uint64_t>(weight))) {
      std::cout << "✅ Vote cast!\n";
    } else {
      std::cerr << "❌ Failed to vote.\n";
    }
    std::exit(0);
  }
  // === Transaction history ===
  if (cmd == "history" && argc >= 3) {
    std::string addr = argv[2];
    Blockchain &b = Blockchain::getInstance();
    std::cout << "🔍 Loading blockchain from DB...\n";
    b.loadFromDB();
    b.reloadBlockchainState();
    std::vector<Transaction> relevant;
    std::unordered_map<std::string, std::string> txType;
    std::unordered_set<std::string> seen;
    auto toLower = [](std::string s) {
      std::transform(s.begin(), s.end(), s.begin(), ::tolower);
      return s;
    };
    std::string addrLower = toLower(addr);
    auto blocks = b.getAllBlocks();
    for (const auto &blk : blocks) {
      std::string blockMiner = toLower(blk.getMinerAddress());
      double reward = blk.getReward();
      for (const auto &tx : blk.getTransactions()) {
        std::string hash =
            tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
        if (!seen.count(hash) && (toLower(tx.getSender()) == addrLower ||
                                  toLower(tx.getRecipient()) == addrLower)) {
          relevant.push_back(tx);
          txType[hash] = "L1";
          seen.insert(hash);
        }
      }
      if (blockMiner == addrLower && reward > 0.0) {
        Transaction rewardTx = Transaction::createSystemRewardTransaction(
            blk.getMinerAddress(), reward, blk.getTimestamp(),
            "mined_" + blk.getHash());
        std::string rewardHash = rewardTx.getHash();
        if (!seen.count(rewardHash)) {
          relevant.push_back(rewardTx);
          txType[rewardHash] = "Mined";
          seen.insert(rewardHash);
        }
      }
    }
    auto rollups = b.getAllRollupBlocks();
    for (const auto &roll : rollups) {
      for (const auto &tx : roll.getTransactions()) {
        std::string hash =
            tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
        if (!seen.count(hash) && (toLower(tx.getSender()) == addrLower ||
                                  toLower(tx.getRecipient()) == addrLower)) {
          relevant.push_back(tx);
          txType[hash] = "L2";
          seen.insert(hash);
        }
      }
    }
    auto allTxs = Transaction::loadAllFromDB();
    for (const auto &tx : allTxs) {
      std::string hash =
          tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
      if (!seen.count(hash) && (toLower(tx.getSender()) == addrLower ||
                                toLower(tx.getRecipient()) == addrLower)) {
        relevant.push_back(tx);
        txType[hash] = "L1";
        seen.insert(hash);
      }
    }
    std::sort(relevant.begin(), relevant.end(),
              [](const Transaction &a, const Transaction &b) {
                return a.getTimestamp() < b.getTimestamp();
              });
    std::cout << "\n=== Transaction History for: " << addr << " ===\n";
    std::cout << "📜 Found " << relevant.size() << " related transactions.\n\n";
    for (const auto &tx : relevant) {
      std::string hash =
          tx.getHash().empty() ? tx.getTransactionHash() : tx.getHash();
      std::string type = txType.count(hash) ? txType[hash] : "Unknown";
      time_t ts = tx.getTimestamp();
      std::tm *tmPtr = std::localtime(&ts);
      char timeStr[64];
      std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", tmPtr);
      std::cout << "🕒 " << timeStr << " [" << type << "]\n"
                << "From: " << tx.getSender() << "\n"
                << "To:   " << tx.getRecipient() << "\n"
                << "💰 Amount: " << tx.getAmount() << " AlynCoin\n";
      if (!tx.getMetadata().empty())
        std::cout << "📎 Metadata: " << tx.getMetadata() << "\n";
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

    Blockchain &b = getBlockchain();
    b.loadFromDB(); // ensure block list is populated
    b.reloadBlockchainState();

    std::vector<std::string> hashes;
    int selected = 0;

    auto blocks = b.getAllBlocks();
    for (auto it = blocks.rbegin(); it != blocks.rend() && selected < count;
         ++it) {
      auto txs = it->getTransactions();
      for (const auto &tx : txs) {
        if (selected >= count)
          break;
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

    std::string result =
        generateRecursiveProofToFile(hashes, addr, selected, outputFile);
    std::cout << result << "\n";
    return 0;
  }

  // === Mined block stats ===
  if (argc == 3 && std::string(argv[1]) == "mychain") {
    std::string addr = argv[2];
    Blockchain &b = Blockchain::getInstance();
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

    Blockchain &b = Blockchain::getInstance();
    Block mined =
        b.minePendingTransactions(minerAddr, dil.privateKey, fal.privateKey);

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
    Blockchain &blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
      std::cerr << "❌ Could not load blockchain from DB.\n";
      return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout << "🔁 Generating Normal Rollup Block...\n";

    std::vector<Transaction> l2Transactions =
        blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
      std::cout << "⚠️ No pending L2 transactions to roll up.\n";
      return 0;
    }

    std::unordered_map<std::string, double> stateBefore =
        blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(blockchain.getRollupChainSize(),
                       blockchain.getLastRollupHash(), l2Transactions);

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
    Blockchain &blockchain = getBlockchain();

    if (!blockchain.loadFromDB()) {
      std::cerr << "❌ Could not load blockchain from DB.\n";
      return 1;
    }

    blockchain.loadPendingTransactionsFromDB();
    std::vector<Transaction> allTxs = blockchain.getPendingTransactions();
    blockchain.setPendingL2TransactionsIfNotInRollups(allTxs);

    std::cout
        << "🔁 Generating Rollup Block with Recursive zk-STARK Proof...\n";

    std::vector<Transaction> l2Transactions =
        blockchain.getPendingL2Transactions();
    if (l2Transactions.empty()) {
      std::cout << "⚠️ No pending L2 transactions to roll up.\n";
      return 0;
    }

    std::unordered_map<std::string, double> stateBefore =
        blockchain.getCurrentState();
    std::unordered_map<std::string, double> stateAfter =
        blockchain.simulateL2StateUpdate(stateBefore, l2Transactions);

    RollupBlock rollup(blockchain.getRollupChainSize(),
                       blockchain.getLastRollupHash(), l2Transactions);

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
      std::cerr
          << "❌ Recursive Rollup Block creation failed: Proof invalid.\n";
    }

    return 0;
  }

  // NFT SPACE //

  // Mint  NFT
  if (cmd == "nft-mint" && argc >= 5) {
    std::string creator = argv[2];
    std::string metadata = argv[3];
    std::string imageHash = argv[4];
    std::string identity = (argc >= 6) ? argv[5] : "";

    std::string privKeyPath = DBPaths::getKeyDir() + creator + "_private.pem";
    if (!std::filesystem::exists(privKeyPath)) {
      std::cerr << "❌ Missing private key file for wallet: " << privKeyPath
                << "\n";
      return 1;
    }

    int64_t ts = std::time(nullptr);
    std::string id = generateNFTID(creator, imageHash, ts);
    std::string message =
        id + creator + creator + metadata + imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keypair = Crypto::loadFalconKeys(creator);

    std::vector<uint8_t> sig =
        Crypto::signWithFalcon(msgHash, keypair.privateKey);

    NFT nft{id, creator, creator, metadata, imageHash, ts, sig};
    nft.creator_identity = identity;
    nft.generateZkStarkProof();

    if (!nft.submitMetadataHashTransaction()) {
      std::cerr << "❌ Metadata transaction failed.\n";
      return 1;
    }

    if (!nft.verifySignature() ||
        !NFTStorage::saveNFT(nft, blockchain.getRawDB())) {
      std::cerr << "❌ Failed to verify or save NFT.\n";
      return 1;
    }

    std::cout << "✅ NFT minted! ID: " << id << "\n";
    return 0;
  }

  // Transfer NFT
  if (cmd == "nft-transfer" && argc >= 4) {
    std::string nftID = argv[2];
    std::string newOwner = argv[3];
    NFT nft;
    if (!NFTStorage::loadNFT(nftID, nft, blockchain.getRawDB())) {
      std::cerr << "❌ NFT not found.\n";
      return 1;
    }

    std::string current = getLoadedWalletAddress();
    if (nft.owner != current || nft.revoked) {
      std::cerr << "❌ Not the owner or NFT is revoked.\n";
      return 1;
    }

    nft.transferHistory.push_back(current);
    nft.owner = newOwner;
    nft.timestamp = std::time(nullptr);

    std::string message = nft.getSignatureMessage();
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keypair = Crypto::loadFalconKeys(current);
    nft.signature = Crypto::signWithFalcon(msgHash, keypair.privateKey);

    if (!nft.verifySignature() ||
        !NFTStorage::saveNFT(nft, blockchain.getRawDB())) {
      std::cerr << "❌ Failed to verify or save transfer.\n";
      return 1;
    }

    std::cout << "✅ NFT transferred.\n";
    return 0;
  }
  // Re-mint NFT (Update Metadata)
  if (cmd == "nft-remint" && argc >= 5) {
    std::string id = argv[2];
    std::string newMetadata = argv[3];
    std::string reason = argv[4];

    std::string currentUser;
    if (argc >= 6) {
      currentUser = argv[5]; // passed by GUI
    } else {
      currentUser = getLoadedWalletAddress(); // fallback for CLI
    }

    if (currentUser.empty()) {
      std::cerr
          << "❌ No wallet loaded. Please load a wallet or pass address.\n";
      return 1;
    }

    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
      std::cerr << "❌ NFT not found.\n";
      return 1;
    }

    if (nft.owner != currentUser || nft.revoked) {
      std::cerr << "❌ You are not the owner of this NFT or it is revoked.\n";
      return 1;
    }

    int newVersion = 1;
    if (!nft.version.empty()) {
      try {
        newVersion = std::stoi(nft.version) + 1;
      } catch (...) {
        newVersion = 1;
      }
    }

    int64_t ts = std::time(nullptr);
    std::string newId = generateNFTID(currentUser, nft.imageHash, ts);
    std::string message = newId + currentUser + currentUser + newMetadata +
                          nft.imageHash + std::to_string(ts);
    auto msgHash = Crypto::sha256ToBytes(message);
    auto keys = Crypto::loadFalconKeys(currentUser);
    std::vector<uint8_t> sig = Crypto::signWithFalcon(msgHash, keys.privateKey);

    NFT updated{newId,         currentUser, currentUser, newMetadata,
                nft.imageHash, ts,          sig};
    updated.version = std::to_string(newVersion);
    updated.creator_identity = nft.creator_identity;
    updated.expiry_timestamp = nft.expiry_timestamp;
    updated.previous_versions = nft.previous_versions;
    updated.previous_versions.push_back(nft.id);

    updated.generateZkStarkProof();

    std::string rehash =
        Crypto::sha256(updated.metadata + updated.imageHash + updated.version);
    if (!submitMetadataHashTransaction(rehash, currentUser, "falcon", true)) {
      std::cerr << "❌ Metadata transaction failed.\n";
      return 1;
    }

    if (!updated.verifySignature() ||
        !NFTStorage::saveNFT(updated, blockchain.getRawDB())) {
      std::cerr << "❌ Failed to verify or save updated NFT.\n";
      return 1;
    }

    std::cout << "✅ NFT re-minted successfully! New ID: " << newId << "\n";
    return 0;
  }
  // Export NFT to File
  if (cmd == "nft-export" && argc >= 3) {
    std::string id = argv[2];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
      std::cerr << "❌ Not found.\n";
      return 1;
    }
    nft.exportToFile();
    return 0;
  }
  // Encrypt Metadata (AES-256)
  if (cmd == "nft-encrypt" && argc >= 5) {
    std::string id = argv[2];
    std::string plaintext = argv[3];
    std::string password = argv[4];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
      std::cerr << "❌ NFT not found.\n";
      return 1;
    }
    nft.encrypted_metadata = AES::encrypt(plaintext, password);
    NFTStorage::saveNFT(nft, blockchain.getRawDB());
    std::cout << "✅ Encrypted metadata stored.\n";
    return 0;
  }

  // Decrypt Metadata (AES-256)
  if (cmd == "nft-decrypt" && argc >= 4) {
    std::string id = argv[2];
    std::string password = argv[3];
    NFT nft;
    if (!NFTStorage::loadNFT(id, nft, blockchain.getRawDB())) {
      std::cerr << "❌ NFT not found.\n";
      return 1;
    }
    if (nft.encrypted_metadata.empty()) {
      std::cout << "⚠️ No encrypted metadata found for this NFT.\n";
      return 0;
    }
    try {
      std::string decrypted = AES::decrypt(nft.encrypted_metadata, password);
      std::cout << "🔓 Decrypted metadata:\n" << decrypted << "\n";
    } catch (const std::exception &e) {
      std::cerr << "❌ Decryption failed: " << e.what() << "\n";
      return 1;
    }
    return 0;
  }

  //  NFT Stats
  if (cmd == "nft-stats") {
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    std::string me = getLoadedWalletAddress();

    if (me.empty()) {
      std::cout
          << "⚠️ No wallet loaded. Please enter your wallet address manually: ";
      std::getline(std::cin, me);
    }

    int total = 0, mine = 0, zk = 0;
    std::map<std::string, int> typeCount;

    for (const auto &nft : all) {
      ++total;
      if (!me.empty() && nft.owner == me)
        ++mine;
      if (!nft.zkStarkProof.empty())
        ++zk;
      if (!nft.nft_type.empty())
        typeCount[nft.nft_type]++;
    }

    std::string topType = "N/A";
    int max = 0;
    for (auto &[type, count] : typeCount) {
      if (count > max) {
        max = count;
        topType = type;
      }
    }

    std::cout << "\n📊 NFT Stats:\n";
    std::cout << "Total: " << total << "\n";
    std::cout << "Mine: "
              << (me.empty() ? "N/A (no wallet provided)"
                             : std::to_string(mine))
              << "\n";
    std::cout << "zk-STARK: " << zk << "\n";
    std::cout << "Most Common Type: " << topType << "\n";
    return 0;
  }
  // View All NFTs / My NFTs
  if (cmd == "nft-my") {
    std::string current = argc >= 3 ? argv[2] : getLoadedWalletAddress();
    if (current.empty()) {
      std::cerr << "❌ No wallet loaded. Please ensure current_wallet.txt is "
                   "set or pass wallet as argument.\n";
      return 1;
    }
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto &nft : all) {
      if (nft.owner == current) {
        std::cout << nft.toJSON() << "\n\n";
      }
    }
    return 0;
  }
  if (cmd == "nft-all") {
    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto &nft : all) {
      std::cout << nft.toJSON() << "\n\n";
    }
    return 0;
  }
  // Verify Image/File Hash (NFT authenticity check)
  if (cmd == "nft-verifyhash" && argc >= 3) {
    std::string filepath = argv[2];
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
      std::cerr << "❌ File not found: " << filepath << "\n";
      return 1;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    std::string contents = buffer.str();
    std::string fileHash = Crypto::sha256(contents);

    auto all = NFTStorage::loadAllNFTs(blockchain.getRawDB());
    for (const auto &nft : all) {
      if (nft.imageHash == fileHash) {
        std::cout << "✅ NFT found for file!\n" << nft.toJSON() << "\n";
        return 0;
      }
    }
    std::cout << "❌ No NFT found matching the file hash.\n";
    return 1;
  }

  // ================= CLI COMMAND HANDLERS END ===================
  if (!cmd.empty() && cmd[0] != '-') {
    static const std::unordered_set<std::string> known = {
        "mineonce",        "mineloop",     "createwallet", "loadwallet",
        "exportwallet",    "importwallet", "balance",      "balance-force",
        "sendl1",          "sendl2",       "dao-submit",   "dao-vote",
        "history",         "mychain",      "mine",         "rollup",
        "recursive-rollup"};
    if (!known.count(cmd)) {
      std::cerr << "Unknown command: " << cmd << "\n";
      print_usage();
      return 1;
    }
  }
  if (network) {
    network->run();
  }

  if (network && !connectIP.empty()) {
    std::string ip;
    short connectPort;
    if (connectIP.find(":") != std::string::npos) {
      size_t colon = connectIP.find(":");
      ip = connectIP.substr(0, colon);
      connectPort = std::stoi(connectIP.substr(colon + 1));
    } else {
      ip = connectIP;
      connectPort = 15671;
    }

    // 🌐 Attempt peer connection
    network->connectToPeer(ip, connectPort);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 📡 Reconnect self to allow reverse sync
    network->connectToPeer("127.0.0.1", port);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 🔄 Trigger sync now that connection is open
    std::cout << "🔁 Triggering sync after peer connect...\n";
    network->intelligentSync();
    if (blockchain.getHeight() <= 1) {
      std::cout << "🔄 [Cold Sync] Attempting to load chain from peers...\n";
      blockchain.loadFromPeers();
    }
  } else if (network) {
    // No explicit --connect, still try syncing
    network->intelligentSync();
    if (blockchain.getHeight() <= 1) {
      std::cout << "🔄 [Cold Sync] Attempting to load chain from peers...\n";
      blockchain.loadFromPeers();
    }
  }
  std::this_thread::sleep_for(std::chrono::seconds(2));

  bool running = true;

  while (running) {
    std::cout << "\n=== AlynCoin Node CLI ===\n";
    std::cout << "1. View Blockchain Stats\n";
    std::cout << "2. Mine Block\n";
    std::cout << "3. Print Blockchain\n";
    std::cout << "4. Start Mining Loop\n";
    std::cout << "5. Sync Blockchain\n";
    std::cout << "6. View Dev Fund Info\n";
    std::cout << "7. Check Balance\n";
    std::cout << "8. Generate Rollup Block\n";
    std::cout << "9. Exit\n";
    std::cout << "10. Run Self-Heal Now 🩺\n";
    std::cout << "12. Export Wallet\n";
    std::cout << "13. Import Wallet\n";
    std::cout << "Choose an option: ";

    int choice;
    std::cin >> choice;
    if (std::cin.fail()) {
      clearInputBuffer();
      std::cout << "Invalid input!\n";
      continue;
    }
    running = handleNodeMenuSelection(choice, blockchain, network, healer, keyDir);
  }

  return 0;
}
