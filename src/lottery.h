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

bool mainstake_lottery(std::vector<MainstakeUtxo> mainstakes, const uint256& block_header_hash, const uint64_t& block_height, MainstakeUtxo& winningUtxo);
