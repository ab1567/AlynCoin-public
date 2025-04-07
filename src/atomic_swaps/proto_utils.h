#pragma once

#include "atomic_swap.h"  // ✅ Needed for AtomicSwap

bool serializeSwap(const AtomicSwap &swap, std::string &out);
bool deserializeSwap(const std::string &data, AtomicSwap &out);
