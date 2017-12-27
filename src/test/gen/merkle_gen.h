#ifndef BITCOIN_TEST_GEN_MERKLE_GEN_H
#define BITCOIN_TEST_GEN_MERKLE_GEN_H

#include "test/gen/crypto_gen.h"
#include "consensus/merkle.h"
#include "uint256.h"
#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/gen/Container.h>
#include <rapidcheck/gen/Create.h>
#include <rapidcheck/gen/Select.h>
#include <rapidcheck/Gen.h>

namespace rc {

  template<>
  struct Arbitrary<MerkleLink> {
    static Gen<MerkleLink> arbitrary() {
      const auto desc = gen::just(MerkleLink::DESCEND);
      const auto ver = gen::just(MerkleLink::VERIFY);
      const auto skip = gen::just(MerkleLink::SKIP);
      return gen::oneOf(desc,ver,skip);
    };
  };

  template<>
  struct Arbitrary<MerkleNode> {
    static Gen<MerkleNode> arbitrary() {
      return rc::gen::map<std::pair<MerkleLink,MerkleLink>>([](std::pair<MerkleLink,MerkleLink> l) {
        return MerkleNode(l.first,l.second);
      });
    };
  };
  
  template<>
  struct Arbitrary<MerkleProof> {
    static Gen<MerkleProof> arbitrary() {
      typedef std::pair<std::vector<MerkleNode>,std::vector<uint256>> t;
      return rc::gen::map<t>([](t tuple) {
        return MerkleProof(std::move(tuple.first),std::move(tuple.second)); 
      });
    };
  };
} //namespace rc

#endif
