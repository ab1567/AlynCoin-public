#ifndef DAO_STORAGE_H
#define DAO_STORAGE_H

#include "dao.h"
#include <string>

namespace DAOStorage {

// Store proposal to RocksDB
bool storeProposal(const Proposal& proposal);

// Load proposal from RocksDB
bool loadProposal(const std::string& proposal_id, Proposal& proposal);

// Check if proposal exists
bool proposalExists(const std::string& proposal_id);

// Track votes to prevent double voting
bool hasVoted(const std::string& proposal_id, const std::string& voter);
bool recordVote(const std::string& proposal_id, const std::string& voter,
                bool vote_yes, uint64_t weight);

std::vector<Proposal> getAllProposals();
}

#endif // DAO_STORAGE_H
