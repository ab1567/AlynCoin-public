#include "../../governance/dao.h"
#include "../../governance/devfund.h"
#include "../../governance/dao_storage.h"
#include "crow_all.h"
#include <nlohmann/json.hpp>
#include <rocksdb/db.h>
#include "db/db_paths.h"

using json = nlohmann::json;

void setupGovernanceAPI(crow::SimpleApp& app) {

    // List all proposals
    CROW_ROUTE(app, "/api/proposals")
    ([] {
        json res;
        res["proposals"] = json::array();

        // Open RocksDB
        rocksdb::DB* db;
        rocksdb::Options options;
        options.create_if_missing = true;
        rocksdb::Status status = rocksdb::DB::Open(options, DBPaths::getGovernanceDB(), &db);
        if (!status.ok()) {
            res["error"] = "Failed to open DB";
            return crow::response{500, res.dump()};
        }

        // Iterate through all keys with "proposal:" prefix
        rocksdb::Iterator* it = db->NewIterator(rocksdb::ReadOptions());
        for (it->Seek("proposal:"); it->Valid() && it->key().starts_with("proposal:"); it->Next()) {
            json proposal_json = json::parse(it->value().ToString());
            res["proposals"].push_back(proposal_json);
        }
        delete it;
        delete db;

        return crow::response{res.dump()};
    });

    // Create new proposal
    CROW_ROUTE(app, "/api/proposal/create").methods("POST"_method)
    ([](const crow::request& req) {
        auto body = json::parse(req.body);
        Proposal proposal;
        proposal.proposal_id = body["proposal_id"];
        proposal.description = body["description"];
        proposal.type = static_cast<ProposalType>(body["type"]);
        proposal.proposer_address = body["proposer_address"];
        proposal.creation_time = std::time(nullptr);
        proposal.deadline_time = proposal.creation_time + body["duration"].get<uint64_t>();
        proposal.status = ProposalStatus::PENDING;
        proposal.yes_votes = 0;
        proposal.no_votes = 0;

        bool result = DAO::createProposal(proposal);

        json res;
        res["status"] = result ? "Created" : "Failed";
        return crow::response{res.dump()};
    });

    // Vote on proposal
    CROW_ROUTE(app, "/api/proposal/vote").methods("POST"_method)
    ([](const crow::request& req) {
        auto body = json::parse(req.body);
        std::string proposal_id = body["proposal_id"];
        bool vote_yes = body["vote"] == "yes";
        uint64_t weight = body["weight"];

        bool result = DAO::castVote(proposal_id, vote_yes, weight);

        json res;
        res["status"] = result ? "Vote Cast" : "Failed";
        return crow::response{res.dump()};
    });

    // Check Proposal Status
    CROW_ROUTE(app, "/api/proposal/status/<string>")
    ([](const crow::request&, const std::string& proposal_id) {
        ProposalStatus status = DAO::checkProposalStatus(proposal_id);

        json res;
        res["proposal_id"] = proposal_id;
        switch (status) {
            case ProposalStatus::PENDING: res["status"] = "Pending"; break;
            case ProposalStatus::APPROVED: res["status"] = "Approved"; break;
            case ProposalStatus::REJECTED: res["status"] = "Rejected"; break;
            case ProposalStatus::EXPIRED: res["status"] = "Expired"; break;
        }
        return crow::response{res.dump()};
    });

    // Get Dev Fund Balance
    CROW_ROUTE(app, "/api/devfund/balance")
    ([] {
        uint64_t balance = DevFund::getBalance();
        json res;
        res["devfund_balance"] = balance;
        return crow::response{res.dump()};
    });
}
