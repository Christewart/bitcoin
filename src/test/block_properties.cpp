#include <boost/test/unit_test.hpp>
#include <rapidcheck/boost_test.h>
#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>

#include "test/test_bitcoin.h"
#include "primitives/block.h"
#include "test/gen/block_gen.h"


BOOST_FIXTURE_TEST_SUITE(block_properties, BasicTestingSetup)

RC_BOOST_PROP(blockheader_serialization_symmetry, (CBlockHeader header)) {
  CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
  ss << header;
  CBlockHeader header2; 
  ss >> header2; 
  CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
  ss << header; 
  ss1 << header2;
  RC_ASSERT(ss.str() == ss1.str());
}

BOOST_AUTO_TEST_SUITE_END()
