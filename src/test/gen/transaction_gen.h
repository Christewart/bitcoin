#ifndef BITCOIN_TEST_GEN_TRANSACTION_GEN_H
#define BITCOIN_TEST_GEN_TRANSACTION_GEN_H

#include "test/gen/crypto_gen.h"
#include "test/gen/script_gen.h"

#include "script/script.h"
#include "primitives/transaction.h" 
#include "amount.h"

#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>
#include <rapidcheck/gen/Predicate.h>

typedef std::tuple<const CTxOut, const CTransaction, const int> SpendingInfo;
/** A signed tx that validly spends a P2PKSPK and the input index */
rc::Gen<SpendingInfo> signedP2PKTx();

/** A signed tx that validly spends a P2PKHSPK and the input index */
rc::Gen<SpendingInfo> signedP2PKHTx();

/** A signed tx that validly spends a Multisig and the input index */
rc::Gen<SpendingInfo> signedMultisigTx();

rc::Gen<SpendingInfo> signedP2SHTx();

namespace rc {
  /** Generator for a COutPoint */ 
  template<>
  struct Arbitrary<COutPoint> {
    static Gen<COutPoint> arbitrary() { 
      return gen::map(gen::tuple(gen::arbitrary<uint256>(), gen::arbitrary<uint32_t>()), [](std::tuple<uint256, uint32_t> outPointPrimitives) {
        uint32_t nIn; 
        uint256 nHashIn; 
        std::tie(nHashIn, nIn) = outPointPrimitives;
        return COutPoint(nHashIn, nIn);
      });
    };
  };

  /** Generator for a CTxIn */
  template<> 
  struct Arbitrary<CTxIn> { 
    static Gen<CTxIn> arbitrary() { 
      return gen::map(gen::tuple(gen::arbitrary<COutPoint>(), gen::arbitrary<CScript>(), gen::arbitrary<uint32_t>()), [](std::tuple<COutPoint, CScript, uint32_t> txInPrimitives) { 
        COutPoint outpoint; 
        CScript script;
        uint32_t sequence; 
        std::tie(outpoint,script,sequence) = txInPrimitives; 
        return CTxIn(outpoint,script,sequence); 
      });
    };
  };
 
  /** Generator for a CAmount */
  template<>
  struct Arbitrary<CAmount> {
    static Gen<CAmount> arbitrary() {
      //why doesn't this generator call work? It seems to cause an infinite loop. 
      //return gen::arbitrary<int64_t>();
      return gen::inRange<int64_t>(std::numeric_limits<int64_t>::min(),std::numeric_limits<int64_t>::max());
    };
  };

  /** Generator for CTxOut */
  template<>
  struct Arbitrary<CTxOut> { 
    static Gen<CTxOut> arbitrary() { 
      return gen::map(gen::tuple(gen::arbitrary<CAmount>(), gen::arbitrary<CScript>()), [](std::tuple<CAmount, CScript> txOutPrimitives) {
        CAmount amount;  
        CScript script;
        std::tie(amount,script) = txOutPrimitives;
        return CTxOut(amount,script);
      });
    };
  };

  /** Generator for a CTransaction */
  template<> 
  struct Arbitrary<CTransaction> { 
    static Gen<CTransaction> arbitrary() { 
      return gen::map(gen::tuple(gen::arbitrary<int32_t>(), 
            gen::nonEmpty<std::vector<CTxIn>>(), gen::nonEmpty<std::vector<CTxOut>>(), gen::arbitrary<uint32_t>()), 
          [](std::tuple<int32_t, std::vector<CTxIn>, std::vector<CTxOut>, uint32_t> txPrimitives) { 
        CMutableTransaction tx;
        int32_t nVersion;
        std::vector<CTxIn> vin;
        std::vector<CTxOut> vout;
        uint32_t locktime;
        std::tie(nVersion, vin, vout, locktime) = txPrimitives;
        tx.nVersion=nVersion;
        tx.vin=vin;
        tx.vout=vout;
        tx.nLockTime=locktime;
        return CTransaction(tx); 
      });
    };
  };

  /** Generator for a CTransactionRef */
  template<>
  struct Arbitrary<CTransactionRef> { 
    static Gen<CTransactionRef> arbitrary() {
      return gen::map(gen::arbitrary<CTransaction>(), [](CTransaction tx) {
          return MakeTransactionRef(tx); 
      });
    };
  };
}
#endif
