#pragma once
#include "identity.h"

bool serializeIdentity(const ZkIdentity& identity, std::string& out);
bool deserializeIdentity(const std::string& data, ZkIdentity& identity);
