#include "consensus/reward.h"

#include "blockchain.h"
#include "block_reward.h"
#include "constants.h"

#include <algorithm>
#include <cmath>

namespace consensus {
namespace {
constexpr double kTailEmission = 0.25;          // minimum subsidy when halvings taper off
constexpr std::uint64_t kHalvingInterval = 210'000; // blocks per halving epoch
} // namespace

double blockSubsidyForHeight(std::uint64_t height) {
  if (height == 0)
    return INITIAL_REWARD;

  long double reward = static_cast<long double>(INITIAL_REWARD);
  const std::uint64_t epoch = height / kHalvingInterval;
  if (epoch > 0)
    reward *= std::pow(0.5L, static_cast<long double>(epoch));
  reward = std::max<long double>(reward, kTailEmission);
  return static_cast<double>(reward);
}

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore,
                              std::time_t /*currentTimestamp*/) {
  const double remaining = std::max(0.0, MAX_SUPPLY - supplyBefore);
  if (remaining <= 0.0)
    return 0.0;
  return std::min(blockSubsidyForHeight(height), remaining);
}

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore) {
  return calculateBlockSubsidy(chain, height, supplyBefore, std::time(nullptr));
}

double calculateBlockSubsidy(const Blockchain &chain) {
  const double supply = chain.getTotalSupply();
  const auto &history = chain.getChain();
  std::uint64_t height = 0;
  if (!history.empty())
    height = static_cast<std::uint64_t>(history.back().getIndex()) + 1ULL;
  return calculateBlockSubsidy(chain, height, supply, std::time(nullptr));
}

} // namespace consensus
