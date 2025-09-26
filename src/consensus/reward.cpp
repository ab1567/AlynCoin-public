#include "consensus/reward.h"

#include "blockchain.h"
#include "block_reward.h"
#include "constants.h"

#include <algorithm>
#include <cmath>

namespace consensus {
namespace {
constexpr double kTailEmission = 0.25; // constant tail reward when network healthy

// Smooth logistic curve that drops rewards as supply approaches the cap.
// We invert the logistic so that early issuance stays close to the base reward
// and then decays smoothly towards zero once supply approaches MAX_SUPPLY.
inline double supplyDamping(double supplyBefore) {
  const double maxSupply = MAX_SUPPLY;
  if (maxSupply <= 0.0)
    return 0.0;

  const double ratio = std::clamp(supplyBefore / maxSupply, 0.0, 1.0);
  constexpr double steepness = 9.0;   // controls how quickly reward decays
  constexpr double midpoint = 0.55;   // inflection around 55 % issued
  const double exponent = -steepness * (ratio - midpoint);
  const double logistic = 1.0 / (1.0 + std::exp(exponent));

  // logistic() grows with ratio, so invert and clamp to keep the scale within
  // [0, 1] while ensuring we never drop below a modest floor. The floor keeps
  // rewards positive until the tail emission logic takes over.
  const double inverted = 1.0 - logistic;
  constexpr double floor = 0.02;
  return std::clamp(inverted, floor, 1.0);
}

inline double cadenceDamping(double gapSeconds) {
  if (gapSeconds <= static_cast<double>(AUTO_MINING_GRACE_PERIOD))
    return 1.0;

  const double minutesSlow = std::clamp(gapSeconds / 60.0, 0.0, 240.0);
  const double damp = std::exp(-minutesSlow / 10.0);
  const double minReward = AUTO_MINING_REWARD / INITIAL_REWARD;
  return std::clamp(damp, minReward, 1.0);
}

inline double minerParticipationBoost(const Blockchain &chain) {
  const int active = std::max(1, chain.getUniqueMinerCount(120));
  if (active <= 1)
    return 1.0;

  // Reward a healthier mesh but cap the boost to avoid runaway inflation.
  const double boost = std::log1p(static_cast<double>(active - 1));
  return std::clamp(1.0 + boost * 0.03, 1.0, 1.20);
}

inline std::uint64_t nextHeight(const Blockchain &chain) {
  const auto &ch = chain.getChain();
  if (ch.empty())
    return 0;
  return static_cast<std::uint64_t>(ch.back().getIndex()) + 1ULL;
}

inline double gapSincePrevious(const Blockchain &chain,
                               std::uint64_t height,
                               std::time_t currentTimestamp) {
  if (height == 0)
    return 0.0;

  const auto &ch = chain.getChain();
  if (ch.empty())
    return 0.0;

  const std::uint64_t prevHeight = height - 1;
  const std::size_t prevIndex = static_cast<std::size_t>(
      std::min<std::uint64_t>(prevHeight, ch.back().getIndex()));

  if (prevIndex >= ch.size())
    return 0.0;

  const std::time_t prevTs = ch[prevIndex].getTimestamp();
  if (prevTs <= 0 || currentTimestamp <= 0)
    return 0.0;

  return std::max(0.0, std::difftime(currentTimestamp, prevTs));
}
} // namespace

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore,
                              std::time_t currentTimestamp) {
  const double remaining = std::max(0.0, MAX_SUPPLY - supplyBefore);
  if (remaining <= 0.0)
    return 0.0;

  // Height based tapering slows issuance after long run.
  const double heightScale = std::clamp(1.0 / std::sqrt(std::max(1.0, static_cast<double>(height))), 0.05, 1.0);
  const double supplyScale = supplyDamping(supplyBefore);
  const double cadenceScale = cadenceDamping(
      gapSincePrevious(chain, height, currentTimestamp));
  const double participation = minerParticipationBoost(chain);

  double reward = INITIAL_REWARD * supplyScale * heightScale * participation;
  reward = std::clamp(reward, AUTO_MINING_REWARD, INITIAL_REWARD);
  reward *= cadenceScale;
  reward = std::min(reward, remaining);

  const double tailFloor = std::min(kTailEmission, remaining);
  if (cadenceScale >= 0.5 && reward < tailFloor)
    reward = tailFloor;

  if (cadenceScale <= (AUTO_MINING_REWARD / INITIAL_REWARD))
    reward = std::min(remaining, AUTO_MINING_REWARD);

  return reward;
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
