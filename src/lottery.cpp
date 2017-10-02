#include "arith_uint256.h"
#include "hash.h"
#include "uint256.h"

/* For each sidechainId, we track a separate database table for mainstaked UTXOs
The structure below is filled with the data to be tracked in this database table. */
struct MainstakeUtxo
{
    /* Identify the UTXO.  */
    uint256 tx_id;
    unsigned int output_index;
    /* Amount, in satoshi.  */
    uint64_t value;
    /* Stake lock time, in mainchain blocks.  */
    uint64_t stake_lock_time;
};

/* Execute at each new block header, or after detaching the tip.  */
MainstakeUtxo mainstake_lottery(std::vector<MainstakeUtxo> mainstakes, uint256 block_header_hash, uint64_t block_height)
{
    /* Filter out mainstakes that have expired.  
    std::remove_if not supported
    auto to_remove = std::remove_if(mainstakes.begin(), mainstakes.end(),
      [=](MainstakeUtxo const& m) { return m.stake_lock_time >= block_height; }
    );
    */
    std::vector<MainstakeUtxo> valid_stakes;
    for (auto m : mainstakes) { 
      if (m.stake_lock_time >= block_height) {
        valid_stakes.push_back(m);
      }
    }
    
    /* Sort the mainstakes by UTXO.  Note that we would probably store it in a data structure that indexes by UTXO,
    so this step may be unnecessary.  */
    /*std::sort(valid_stakes.begin(), valid_stakes.end(),
      [](MainstakeUtxo const& a, MainstakeUtxo const& b) {
          if (a.tx_id < b.tx_id) return true;
          if (a.tx_id > b.tx_id) return false;
          return a.output_index < b.output_index;
      }
    );*/
    /* Create an array of weights.  */
    auto weights = std::vector<uint64_t>();
    /*std::transform(mainstakes.begin(), mainstakes.end(), std::back_inserter(weights),
      [=](MainstakeUtxo const& m) { return (uint64_t) m.value * ((uint64_t) m.stake_lock_time - (uint64_t) block_height); }
    );*/
    for (auto m: valid_stakes) { 
      auto weight = ((uint64_t) m.value * ((uint64_t) m.stake_lock_time - (uint64_t) block_height));
      weights.push_back(weight);
    }

    /* Create an array of running weights (i.e. running_weight[i] = running_weight[i - 1] + weights[i]).  Also get total lottery ticket weight.  */
    auto running_weights = std::vector<uint64_t>();
    auto total_weight = uint64_t(0);
    /*std::transform(weights.begin(), weights.end(), std::back_inserter(running_weights),
      [&total_weight](uint128_t weight) {
        total_weight += weight;
        return total_weight;
      }
    );*/
    for (unsigned int i = 0; i < weights.size(); i++) { 
      total_weight += weights[i];
      if (i == 0) {
        running_weights.push_back(weights[i]);
      } else {
        auto newWeight = running_weights[i-1] + weights[i];
        running_weights.push_back(newWeight);
      }
    }

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
    return valid_stakes[winner_index];
}
