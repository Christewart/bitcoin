#include "test/gen/transaction_gen.h"

#include "test/gen/crypto_gen.h"
#include "test/gen/script_gen.h"

#include "script/sign.h"
#include "script/script.h"
#include "primitives/transaction.h"
#include "core_io.h"
#include "keystore.h"

#include <rapidcheck/gen/Arbitrary.h>
#include <rapidcheck/Gen.h>
#include <rapidcheck/gen/Predicate.h>
#include <rapidcheck/gen/Select.h>

CMutableTransaction BuildCreditingTransaction(const CScript& scriptPubKey, int nValue = 0)
{
    CMutableTransaction txCredit;
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin.resize(1);
    txCredit.vout.resize(1);
    txCredit.vin[0].prevout.SetNull();
    txCredit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    txCredit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txCredit.vout[0].scriptPubKey = scriptPubKey;
    txCredit.vout[0].nValue = nValue;

    return txCredit;
}

CMutableTransaction BuildSpendingTransaction(const CScript& scriptSig, const CScriptWitness& scriptWitness, const CMutableTransaction& txCredit)
{
    CMutableTransaction txSpend;
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin.resize(1);
    txSpend.vin[0].scriptWitness = scriptWitness;
    txSpend.vin[0].prevout.hash = txCredit.GetHash();
    txSpend.vin[0].prevout.n = 0;
    txSpend.vin[0].scriptSig = scriptSig;
    txSpend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    txSpend.vout.resize(1);
    txSpend.vout[0].scriptPubKey = CScript();
    txSpend.vout[0].nValue = txCredit.vout[0].nValue;

    return txSpend;
}

/** Helper function to generate a tx that spends a spk */
SpendingInfo sign(SPKCKeyTup spk_keys, CScript redeemScript = CScript()) {
    const int inputIndex = 0;
    const CAmount nValue = 0;
    const CScript spk = std::get<0>(spk_keys);
    const std::vector<CKey> keys = std::get<1>(spk_keys);
    CBasicKeyStore store;
    for (const auto k: keys) {
      store.AddKey(k);
    }
    //add redeem script
    store.AddCScript(redeemScript);
    CMutableTransaction creditingTx = BuildCreditingTransaction(spk,nValue);
    CMutableTransaction spendingTx = BuildSpendingTransaction(CScript(), CScriptWitness(), creditingTx);
    CTransaction spendingTxConst(spendingTx);
    SignatureData sigdata;
    TransactionSignatureCreator creator(&store,&spendingTxConst,inputIndex,0);
    assert(ProduceSignature(creator, spk, sigdata));
    UpdateTransaction(spendingTx,0,sigdata);
    const CTxOut output = creditingTx.vout[0];
    const CTransaction finalTx = CTransaction(spendingTx);
    SpendingInfo tup = std::make_tuple(output,finalTx,inputIndex);
    return tup;
}

/** A signed tx that validly spends a P2PKSPK */
rc::Gen<SpendingInfo> signedP2PKTx() {
  return rc::gen::map(P2PKSPK(), [](SPKCKeyTup spk_key) {
    return sign(spk_key);
  });
}

rc::Gen<SpendingInfo> signedP2PKHTx() {
  return rc::gen::map(P2PKHSPK(), [](SPKCKeyTup spk_key) {
    return sign(spk_key);
  });
}

rc::Gen<SpendingInfo> signedMultisigTx() {
  return rc::gen::map(MultisigSPK(), [](SPKCKeyTup spk_key) {
    return sign(spk_key);
  });
}

rc::Gen<SpendingInfo> signedP2SHTx() {
  return rc::gen::map(RawSPK(), [](SPKCKeyTup spk_keys) {
    const CScript redeemScript = std::get<0>(spk_keys);
    const std::vector<CKey> keys = std::get<1>(spk_keys);
    //hash the spk
    const CScript p2sh = GetScriptForDestination(CScriptID(redeemScript));
    return sign(std::make_tuple(p2sh,keys),redeemScript);
  });
}

rc::Gen<SpendingInfo> signedP2WPKHTx() {
  return rc::gen::map(P2WPKHSPK(), [](SPKCKeyTup spk_keys) {
    return sign(spk_keys);
  });
}

rc::Gen<SpendingInfo> signedP2WSHTx() {
  return rc::gen::map(MultisigSPK(), [](SPKCKeyTup spk_keys) {
   const CScript redeemScript = std::get<0>(spk_keys);
   const std::vector<CKey> keys = std::get<1>(spk_keys);
   const CScript p2wsh = GetScriptForWitness(redeemScript);
   return sign(std::make_tuple(p2wsh,keys),redeemScript);
  });
}

/** Generates an arbitrary validly signed tx */
rc::Gen<SpendingInfo> signedTx() {
  return rc::gen::oneOf(signedP2PKTx(), signedP2PKHTx(),
    signedMultisigTx(), signedP2SHTx(), signedP2WPKHTx(),
    signedP2WSHTx());
}
