#ifndef DAO_H
#define DAO_H

#include <string>
#include <cstdint>
#include <vector>

// Enum: Types of proposals
enum class ProposalType {
    PROTOCOL_UPGRADE,
    FUND_ALLOCATION,
    BLACKLIST_APPEAL,
    CUSTOM_ACTION
};

// Enum: Proposal Status
enum class ProposalStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED
};

// Struct: Governance Proposal
struct Proposal {
    std::string proposal_id;       // Unique ID (hash or UUID)
    std::string description;       // Human-readable description
    ProposalType type;             // Type of proposal
    std::string proposer_address;  // Who submitted it
    uint64_t yes_votes;            // Count of YES votes
    uint64_t no_votes;             // Count of NO votes
    uint64_t creation_time;        // UNIX timestamp
    uint64_t deadline_time;        // Voting deadline
    ProposalStatus status;         // Current status

    // ✅ Fund Allocation specific
    double transfer_amount = 0.0;              // Amount to transfer (if FUND_ALLOCATION)
    std::string target_address = "";           // Recipient address
};

// DAO Logic Functions
namespace DAO {
    bool createProposal(const Proposal& proposal);
    bool castVote(const std::string& proposal_id, bool vote_yes, uint64_t vote_weight);
    ProposalStatus checkProposalStatus(const std::string& proposal_id);
    bool finalizeProposal(const std::string& proposal_id);
}

#endif // DAO_H
