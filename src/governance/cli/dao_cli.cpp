#include "../../governance/dao.h"
#include "../../governance/dao_storage.h"
#include <iostream>
#include <string>
#include <ctime>
#include <limits>

// CLI: Create Proposal
void createProposalCLI() {
    Proposal proposal;
    std::cout << "Enter Proposal ID: ";
    std::cin >> proposal.proposal_id;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "Enter Description: ";
    std::getline(std::cin, proposal.description);
    std::cout << "Proposal Types:\n";
    std::cout << "1. Protocol Upgrade\n2. Fund Allocation\n3. Blacklist Appeal\n4. Custom\n";
    int typeInput;
    std::cout << "Choose type (1-4): ";
    std::cin >> typeInput;
    proposal.type = static_cast<ProposalType>(typeInput - 1);
    std::cout << "Enter Proposer Address: ";
    std::cin >> proposal.proposer_address;
    uint64_t duration;
    std::cout << "Voting Duration (seconds): ";
    std::cin >> duration;

    proposal.creation_time = std::time(nullptr);
    proposal.deadline_time = proposal.creation_time + duration;
    proposal.status = ProposalStatus::PENDING;
    proposal.yes_votes = 0;
    proposal.no_votes = 0;

    if (DAO::createProposal(proposal)) {
        std::cout << "Proposal Created Successfully!\n";
    } else {
        std::cout << "Failed to create proposal (maybe already exists).\n";
    }
}

// CLI: Vote on Proposal
void voteCLI() {
    std::string proposal_id;
    std::cout << "Enter Proposal ID: ";
    std::cin >> proposal_id;
    std::string voter;
    std::cout << "Enter Your Address: ";
    std::cin >> voter;
    std::string vote;
    std::cout << "Vote (yes/no): ";
    std::cin >> vote;
    uint64_t weight;
    std::cout << "Enter vote weight (tokens): ";
    std::cin >> weight;

    bool vote_yes = (vote == "yes");

    if (DAO::castVote(proposal_id, voter, vote_yes, weight)) {
        std::cout << "Vote Cast Successfully!\n";
    } else {
        std::cout << "Failed to cast vote.\n";
    }
}

// CLI: Check Proposal Status
void checkProposalStatusCLI() {
    std::string proposal_id;
    std::cout << "Enter Proposal ID: ";
    std::cin >> proposal_id;

    ProposalStatus status = DAO::checkProposalStatus(proposal_id);
    std::cout << "Proposal Status: ";
    switch (status) {
        case ProposalStatus::PENDING: std::cout << "Pending\n"; break;
        case ProposalStatus::APPROVED: std::cout << "Approved\n"; break;
        case ProposalStatus::REJECTED: std::cout << "Rejected\n"; break;
        case ProposalStatus::EXPIRED: std::cout << "Expired\n"; break;
    }
}

// Simple interactive menu for DAO operations
int main() {
    while (true) {
        std::cout << "\nDAO CLI Options:\n";
        std::cout << "1. Create Proposal\n";
        std::cout << "2. Vote on Proposal\n";
        std::cout << "3. Check Proposal Status\n";
        std::cout << "4. Exit\n";
        std::cout << "Choice: ";

        int choice;
        if (!(std::cin >> choice)) {
            if (std::cin.eof()) {
                std::cout << "\nEOF detected. Exiting DAO CLI...\n";
                return 0;
            }
            if (std::cin.bad()) {
                std::cerr << "\nFatal input stream error. Exiting DAO CLI.\n";
                return 1;
            }
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid option.\n";
            continue;
        }

        switch (choice) {
        case 1:
            createProposalCLI();
            break;
        case 2:
            voteCLI();
            break;
        case 3:
            checkProposalStatusCLI();
            break;
        case 4:
            return 0;
        default:
            std::cout << "Invalid option.\n";
        }
    }
    return 0;
}
