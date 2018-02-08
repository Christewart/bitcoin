// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "key.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_bitcoin.h"
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <rapidcheck/boost_test.h>
#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>

#include "test/gen/crypto_gen.h"
/** Generator for a new CKey */
BOOST_FIXTURE_TEST_SUITE(key_properties, BasicTestingSetup)

/** Check CKey uniqueness */ 
RC_BOOST_PROP(key_uniqueness, (CKey key1, CKey key2)) {
  RC_ASSERT(!(key1 == key2));
}

/** Verify that a private key generates the correct public key */ 
RC_BOOST_PROP(key_generates_correct_pubkey, (CKey key)) {
  CPubKey pubKey = key.GetPubKey();  
  RC_ASSERT(key.VerifyPubKey(pubKey));
}

/** Serialization symmetry CKey -> CBitcoinSecret -> CKey */ 
RC_BOOST_PROP(key_bitcoinsecret_symmetry, (CKey key)) {
  CBitcoinSecret secret;   
  secret.SetKey(key);
  RC_ASSERT(secret.GetKey() == key);
}

/** Create a CKey using the 'Set' function must give us the same key */ 
RC_BOOST_PROP(key_set_symmetry, (CKey key)) {
  CKey key1;
  key1.Set(key.begin(), key.end(), key.IsCompressed());
  RC_ASSERT(key1 == key); 
}

/** Create a CKey, sign a piece of data, then verify it with the public key */
RC_BOOST_PROP(key_sign_symmetry, (CKey key, uint256 hash)) {
  std::vector<unsigned char> vchSig;
  key.Sign(hash,vchSig,0);
  CPubKey pubKey = key.GetPubKey(); 
  RC_ASSERT(pubKey.Verify(hash,vchSig));
}
BOOST_AUTO_TEST_SUITE_END()
