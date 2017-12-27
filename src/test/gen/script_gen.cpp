#include "test/gen/script_gen.h"
#include "test/gen/crypto_gen.h"

#include "consensus/merkle.h"
#include "script/script.h"
#include "script/standard.h"
#include "base58.h"
#include "core_io.h"
#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>
#include <rapidcheck/gen/Predicate.h>
#include <rapidcheck/gen/Numeric.h>

/** Generates a P2PK/CKey pair */
rc::Gen<T> P2PKSPK() {
  return rc::gen::map(rc::gen::arbitrary<CKey>(), [](CKey key) {
    const CScript& s = GetScriptForRawPubKey(key.GetPubKey());
    std::vector<CKey> keys;
    keys.push_back(key);
    T tup = std::make_tuple(s,keys);
    return tup;
  });
}
/** Generates a P2PKH/CKey pair */
rc::Gen<T> P2PKHSPK() {
  return rc::gen::map(rc::gen::arbitrary<CKey>(), [](CKey key) {
    CKeyID id = key.GetPubKey().GetID(); 
    std::vector<CKey> keys;
    keys.push_back(key);
    const CScript& s = GetScriptForDestination(id);
    return std::make_tuple(s,keys);
  });
}

/** Generates a MultiSigSPK/CKey(s) pair */
rc::Gen<T> MultisigSPK() {
  return rc::gen::mapcat(multisigKeys(), [](std::vector<CKey> keys) {
    return rc::gen::map(rc::gen::inRange<int>(1,keys.size()),[keys](int requiredSigs) {
      std::vector<CPubKey> pubKeys;
      for(unsigned int i = 0; i < keys.size(); i++) {
        pubKeys.push_back(keys[i].GetPubKey());
      }
      const CScript& s = GetScriptForMultisig(requiredSigs,pubKeys);
      return std::make_tuple(s,keys);
    });
  });
}

rc::Gen<T> RawSPK() {
  return rc::gen::oneOf(P2PKSPK(), P2PKHSPK(), MultisigSPK(),
    P2WPKHSPK());
}

/** Generates a P2SHSPK/CKey(s) */
rc::Gen<T> P2SHSPK() {
  return rc::gen::map(RawSPK(), [](T spk_keys) {
    const CScript redeemScript = std::get<0>(spk_keys);
    const std::vector<CKey> keys = std::get<1>(spk_keys);
    const CScript p2sh = GetScriptForDestination(CScriptID(redeemScript));
    return std::make_tuple(redeemScript,keys);
  });
}


//witness SPKs

rc::Gen<T> P2WPKHSPK() {
  rc::Gen<T> spks = rc::gen::oneOf(P2PKSPK(),P2PKHSPK());
  return rc::gen::map(spks, [](T spk_keys) {
    const CScript p2pk = std::get<0>(spk_keys);
    const std::vector<CKey> keys = std::get<1>(spk_keys);
    const CScript witSPK = GetScriptForWitness(p2pk);
    return std::make_tuple(witSPK, keys);
  });
}

rc::Gen<T> P2WSHSPK() {
  return rc::gen::map(MultisigSPK(), [](T spk_keys) {
    const CScript p2pk = std::get<0>(spk_keys);
    const std::vector<CKey> keys = std::get<1>(spk_keys);
    const CScript witSPK = GetScriptForWitness(p2pk);
    return std::make_tuple(witSPK, keys);
  });
}

/** An arbitrary merkle-branch-verify spk */
/*rc::Gen<T> MBVSPK() {
  //1. The root hash of the Merkle tree;
  //2. The hash values to be verified, a set usually consisting of the double-SHA256 hash of data elements,
  //   but potentially the labels of inner nodes instead, or both;
  //3. The paths from the root to the nodes containing the values under consideration,
  //   expressed as a serialized binary tree structure; and
  //4. The hash values of branches not taken along those paths.

  // script interpreter fails if:
  //   the stack contains less than three (3) items;
  //   the first item on the stack is more than 2 bytes;
  //   the first item on the stack, interpreted as an integer, N, is negative or not minimally encoded;
  //   the second item on the stack is not exactly 32 bytes;
  //   the third item on the stack is not a serialized Merkle tree inclusion proof as specified by BIP98[1]
  //     and requiring exactly floor(N/2) VERIFY hashes; or
  //   the remainder of the stack contains less than floor(N/2) additional items,
  //     together referred to as the input stack elements.

  return rc::gen::map(rc::gen::arbitrary<std::vector<uint256>>(), [](std::vector<uint256> txids) {
    const std::vector<uint256>& verifyHashes = {txids[0]};
    //compute fast merkle root
    const uint256& fastMerkleRoot = ComputeFastMerkleRoot(txids);
    const std::pair<std::vector<uint256>,uint32_t>& branch = ComputeFastMerkleBranch(txids,0);
    CScript& spk = CScript() << CScript(branch.first.begin(), branch.first.end());
    spk << CScript(fastMerkleRoot.begin(), fastMerkleRoot.end());
    spk << CScriptNum(verifyHashes.size());
    return std::make_tuple(spk, std::vector<CKey>());
  });
} */
