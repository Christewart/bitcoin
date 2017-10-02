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

BOOST_AUTO_TEST_CASE(OneEntryLottery) { 
  BOOST_CHECK(true == true);
}
BOOST_AUTO_TEST_SUITE_END()
