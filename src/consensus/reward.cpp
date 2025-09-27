#include "consensus/reward.h"

#include "blockchain.h"
#include "block_reward.h"
#include "constants.h"

#include <algorithm>

namespace consensus {
namespace {
// Reward decays smoothly with the circulating supply. By tying the emission to
// totalSupply/MAX_SUPPLY we guarantee a monotonic decrease as supply grows.
inline double supplyDecayReward(double supplyBefore) {
  if (MAX_SUPPLY <= 0.0)
    return 0.0;

  const double ratio = std::clamp(supplyBefore / MAX_SUPPLY, 0.0, 1.0);
  const double reward = INITIAL_REWARD * (1.0 - ratio);
  return std::max(0.0, reward);
}

inline std::uint64_t nextHeight(const Blockchain &chain) {
  const auto &ch = chain.getChain();
  if (ch.empty())
    return 0;
  return static_cast<std::uint64_t>(ch.back().getIndex()) + 1ULL;
}

} // namespace

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore,
                              std::time_t currentTimestamp) {
  (void)height;
  (void)currentTimestamp; // Emission depends purely on irreversible supply.

  const double remaining = std::max(0.0, MAX_SUPPLY - supplyBefore);
  if (remaining <= 0.0)
    return 0.0;

  double reward = supplyDecayReward(supplyBefore);

  return std::min(reward, remaining);
}

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore) {
  return calculateBlockSubsidy(chain, height, supplyBefore,
                               std::time(nullptr));
}

double calculateBlockSubsidy(const Blockchain &chain) {
  const double supply = chain.getTotalSupply();
  const std::uint64_t height = nextHeight(chain);
  return calculateBlockSubsidy(chain, height, supply, std::time(nullptr));
}

} // namespace consensus
