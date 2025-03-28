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

}

#endif // DAO_STORAGE_H
