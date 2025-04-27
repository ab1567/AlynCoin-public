#include <iostream>
#include <string>
#include "../dao.h"
#include "../dao_storage.h"
#include "../../db/rocksdb_wrapper.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <proposal_id>" << std::endl;
        return 1;
    }

    std::string proposal_id = argv[1];
    std::cout << "Fetching status for proposal ID: " << proposal_id << "..." << std::endl;

    ProposalStatus status = DAO::checkProposalStatus(proposal_id);

    switch (status) {
        case ProposalStatus::PENDING:
            std::cout << "Current Status: Pending" << std::endl;
            std::cout << "Finalizing proposal..." << std::endl;
            if (DAO::finalizeProposal(proposal_id)) {
                std::cout << "Proposal finalized successfully." << std::endl;
            } else {
                std::cout << "Failed to finalize proposal." << std::endl;
            }
            break;
        case ProposalStatus::APPROVED:
            std::cout << "Current Status: Approved. No action needed." << std::endl;
            break;
        case ProposalStatus::REJECTED:
            std::cout << "Current Status: Rejected. No action needed." << std::endl;
            break;
        case ProposalStatus::EXPIRED:
            std::cout << "Current Status: Expired. No action needed." << std::endl;
            break;
        default:
            std::cout << "Proposal not found." << std::endl;
            break;
    }

    return 0;
}
