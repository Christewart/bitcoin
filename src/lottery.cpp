#include "lottery.h"

#include "arith_uint256.h"
#include "hash.h"
#include "uint256.h"

#include <algorithm>

/* Execute at each new block header, or after detaching the tip.  */
bool mainstake_lottery(std::vector<MainstakeUtxo> mainstakes, const uint256& block_header_hash, const uint64_t& block_height, MainstakeUtxo& winningUtxo)
{
    /* Filter out mainstakes that have expired.  
    std::remove_if not supported */
    auto to_remove = std::remove_if(mainstakes.begin(), mainstakes.end(),
      [=](MainstakeUtxo const& m) { return block_height >= m.stake_lock_time || m.value <= 0; }
    );
    mainstakes.erase(to_remove,mainstakes.end());
    printf("valid_mainstakes: %d\n", mainstakes.size());
    /* Sort the mainstakes by UTXO.  Note that we would probably store it in a data structure that indexes by UTXO,
    so this step may be unnecessary.  */
    std::sort(mainstakes.begin(), mainstakes.end(),
      [](MainstakeUtxo const& a, MainstakeUtxo const& b) {
          if (UintToArith256(a.tx_id) < UintToArith256(b.tx_id)) return true;
          if (UintToArith256(a.tx_id) > UintToArith256(b.tx_id)) return false;
          return a.output_index < b.output_index;
      }
    );
    /* Create an array of weights.  */
    auto weights = std::vector<uint64_t>();
    std::transform(mainstakes.begin(), mainstakes.end(), std::back_inserter(weights),
      [=](MainstakeUtxo const& m) { return (uint64_t) m.value * ((uint64_t) m.stake_lock_time - (uint64_t) block_height); }
    );
    printf("weight.size() : %d\n", weights.size());
    if (weights.size() == 0) {
      return false;
    }

    /* Create an array of running weights (i.e. running_weight[i] = running_weight[i - 1] + weights[i]).  Also get total lottery ticket weight.  */
    auto running_weights = std::vector<uint64_t>();
    auto total_weight = uint64_t(0);
    std::transform(weights.begin(), weights.end(), std::back_inserter(running_weights),
      [&total_weight](uint64_t weight) {
	printf("weight: %d\n", weight);
        total_weight += weight;
	printf("new total weight: %d\n", total_weight);
        return total_weight;
      }
    );

    /* Initialize lottery RNG.  */
    uint256 rng = Hash(block_header_hash.begin(), block_header_hash.end());
    /* Pick ticket.  The rng should return a value from 0 to arg - 1 inclusive */
    //auto ticket = rng.generate(total_weight);
    //dumb for now, this truncates bytes
    auto ticket = rng.GetUint64(0) % total_weight; 
    /* Locate winner.  std::upper_bound finds the first running weight that is greater than the ticket.  */
    auto winner = std::upper_bound(running_weights.begin(), running_weights.end(), ticket);
    auto winner_index = winner - running_weights.begin();
    /* Return winner.  */
    winningUtxo = mainstakes[winner_index];
    return true;
}
