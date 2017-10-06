// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
#include "util.h"
#include "clientversion.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
*/

#include "lottery.h"
#include "test/test_bitcoin.h"

#include <stdint.h>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(lottery_tests, BasicTestingSetup)


BOOST_AUTO_TEST_CASE(EmptyLottery) {
  std::vector<MainstakeUtxo> mainstakes;
  uint256 block_header_hash = uint256S("0");
  uint64_t block_height = 0;

  MainstakeUtxo winningUtxo;
  bool result = mainstake_lottery(mainstakes,block_header_hash,block_height, winningUtxo);
  BOOST_CHECK(!result);
}
BOOST_AUTO_TEST_CASE(OneEntryLottery) {
  MainstakeUtxo utxo;
  utxo.tx_id = uint256S("0");
  utxo.output_index = 0;
  utxo.value = 1;
  utxo.stake_lock_time = 1;
  
  std::vector<MainstakeUtxo> mainstakes;
  mainstakes.push_back(utxo);
  
  uint256 block_header_hash = uint256S("0");
  uint64_t block_height = 0;

  MainstakeUtxo winningUtxo;
  bool result = mainstake_lottery(mainstakes,block_header_hash,block_height, winningUtxo);
  BOOST_CHECK(result);
  BOOST_CHECK(winningUtxo.tx_id == utxo.tx_id);
  BOOST_CHECK(winningUtxo.output_index == utxo.output_index);
  BOOST_CHECK(winningUtxo.value == utxo.value);
  BOOST_CHECK(winningUtxo.stake_lock_time == utxo.stake_lock_time);
}
BOOST_AUTO_TEST_SUITE_END()
