#include <sstream>
#include "dao_storage.h"
#include "../db/rocksdb_wrapper.h"

// Simple serialization of Proposal
static std::string serializeProposal(const Proposal& proposal) {
    std::ostringstream ss;
    ss << proposal.proposal_id << "|"
       << proposal.description << "|"
       << static_cast<int>(proposal.type) << "|"
       << proposal.proposer_address << "|"
       << proposal.yes_votes << "|"
       << proposal.no_votes << "|"
       << proposal.creation_time << "|"
       << proposal.deadline_time << "|"
       << static_cast<int>(proposal.status);
    return ss.str();
}

// Simple deserialization
static Proposal deserializeProposal(const std::string& data) {
    std::istringstream ss(data);
    Proposal p;
    std::string temp;
    std::getline(ss, p.proposal_id, '|');
    std::getline(ss, p.description, '|');
    std::getline(ss, temp, '|'); p.type = static_cast<ProposalType>(std::stoi(temp));
    std::getline(ss, p.proposer_address, '|');
    std::getline(ss, temp, '|'); p.yes_votes = std::stoull(temp);
    std::getline(ss, temp, '|'); p.no_votes = std::stoull(temp);
    std::getline(ss, temp, '|'); p.creation_time = std::stoull(temp);
    std::getline(ss, temp, '|'); p.deadline_time = std::stoull(temp);
    std::getline(ss, temp, '|'); p.status = static_cast<ProposalStatus>(std::stoi(temp));
    return p;
}

bool DAOStorage::storeProposal(const Proposal& proposal) {
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    std::string key = "proposal_" + proposal.proposal_id;
    std::string value = serializeProposal(proposal);
    return db.put(key, value);
}

bool DAOStorage::loadProposal(const std::string& proposal_id, Proposal& proposal) {
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    std::string key = "proposal_" + proposal_id;
    std::string value;
    if (!db.get(key, value)) {
        return false;
    }
    proposal = deserializeProposal(value);
    return true;
}

bool DAOStorage::proposalExists(const std::string& proposal_id) {
    RocksDBWrapper db("/root/AlynCoin/data/governance_db");
    std::string key = "proposal_" + proposal_id;
    return db.exists(key);
}
