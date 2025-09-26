#ifndef ALYNCOIN_CONSENSUS_REWARD_H
#define ALYNCOIN_CONSENSUS_REWARD_H

#include <cstdint>
#include <ctime>

class Blockchain;

namespace consensus {

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore,
                              std::time_t currentTimestamp);

double calculateBlockSubsidy(const Blockchain &chain,
                              std::uint64_t height,
                              double supplyBefore);

double calculateBlockSubsidy(const Blockchain &chain);

double blockSubsidyForHeight(std::uint64_t height);

} // namespace consensus

#endif // ALYNCOIN_CONSENSUS_REWARD_H
