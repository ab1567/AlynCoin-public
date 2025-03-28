#include "dao.h"
#include "dao_storage.h"
#include <ctime>
#include <iostream>

namespace DAO {

// Create a new proposal
bool createProposal(const Proposal& proposal) {
    // Check if already exists
    if (DAOStorage::proposalExists(proposal.proposal_id)) {
        std::cerr << "[DAO] Proposal already exists.\n";
        return false;
    }

    Proposal newProposal = proposal;
    newProposal.creation_time = std::time(nullptr);
    newProposal.status = ProposalStatus::PENDING;

    // Save to RocksDB
    return DAOStorage::storeProposal(newProposal);
}

// Cast a vote on a proposal
bool castVote(const std::string& proposal_id, bool vote_yes, uint64_t vote_weight) {
    Proposal proposal;
    if (!DAOStorage::loadProposal(proposal_id, proposal)) {
        std::cerr << "[DAO] Proposal not found.\n";
        return false;
    }

    uint64_t now = std::time(nullptr);
    if (now > proposal.deadline_time) {
        std::cerr << "[DAO] Voting deadline passed.\n";
        return false;
    }

    if (vote_yes) {
        proposal.yes_votes += vote_weight;
    } else {
        proposal.no_votes += vote_weight;
    }

    // Update proposal
    return DAOStorage::storeProposal(proposal);
}

// Check current status
ProposalStatus checkProposalStatus(const std::string& proposal_id) {
    Proposal proposal;
    if (!DAOStorage::loadProposal(proposal_id, proposal)) {
        return ProposalStatus::EXPIRED; // Treat missing as expired
    }

    uint64_t now = std::time(nullptr);
    if (now > proposal.deadline_time && proposal.status == ProposalStatus::PENDING) {
        // Auto-finalize
        finalizeProposal(proposal_id);
    }

    return proposal.status;
}

// Finalize proposal after deadline
bool finalizeProposal(const std::string& proposal_id) {
    Proposal proposal;
    if (!DAOStorage::loadProposal(proposal_id, proposal)) {
        return false;
    }

    if (proposal.status != ProposalStatus::PENDING) {
        return true; // Already finalized
    }

    // Determine outcome
    if (proposal.yes_votes > proposal.no_votes) {
        proposal.status = ProposalStatus::APPROVED;
    } else {
        proposal.status = ProposalStatus::REJECTED;
    }

    return DAOStorage::storeProposal(proposal);
}

} // namespace DAO
