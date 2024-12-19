// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
//#include <timedata.h>
#include <util/rbf.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>


BOOST_FIXTURE_TEST_SUITE(wcb, TestingSetup)

struct WorstBlock100Setup: TestChain100Setup {
    WorstBlock100Setup(): TestChain100Setup{ChainType::MAIN} {}
};

//! Number of inputs in the attack transaction.
constexpr size_t INPUTS_COUNT{7'013};

//! Number of outputs in the attack transaction.
constexpr size_t OUTPUTS_COUNT{23'028};

/** Create the scriptpubkey used in outputs to be spent in the attack block. */
CScript AttackPrevScriptPubKey(const CKey& coinbaseKey)
{
    // First a signature check to make sure the attacker doesn't get his coins stolen.
    CScript script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIGVERIFY;

    // Check as many minimally-encoded dummy signatures as possible.
    const static std::vector<unsigned char> dummy_sig = {0x30,0x06,0x02,0x01,0x01,0x02,0x01,0x01,0x01};
    for (auto i = 0; i < 200; ++i) script = script << dummy_sig << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    // Maximize the size of the script.
    while (script.size() < MAX_SCRIPT_SIZE) {
        const auto leftover = MAX_SCRIPT_SIZE - script.size();
        const auto padding_size = std::min(leftover, MAX_SCRIPT_ELEMENT_SIZE);
        const auto compactsize_size = leftover > 253 ? 3 : 1;
        script = script << std::vector<unsigned char>(padding_size - compactsize_size, 1);
    }
    assert(script.size() == MAX_SCRIPT_SIZE);

    return script;
}

/** Create the transaction which spends all the prepared outputs at once. All inputs and all outputs are the same. */
CMutableTransaction CreateAttackTx(const std::vector<COutPoint>& inputs, const CKey attacker_key, const CScript& prev_scriptpubkey,
                                   const CAmount prev_amount, std::vector<CTxOut> outputs)
{
    // Create the unsigned transaction.
    CMutableTransaction attack_tx;
    attack_tx.vout = std::move(outputs);
    attack_tx.vin.reserve(inputs.size());
    for (const auto& outpoint : inputs) attack_tx.vin.emplace_back(outpoint);

    // Provide the one signature which allows the attacker to not get his coins stolen.
    FillableSigningProvider keystore;
    keystore.AddKey(attacker_key);
    SignatureData dummy_sigdata;
    PrecomputedTransactionData dummy_txdata;
    CKeyID keyid = attacker_key.GetPubKey().GetID();
    for (auto i = 0; i < attack_tx.vin.size(); ++i) {
        MutableTransactionSignatureCreator creator(attack_tx, i, prev_amount, &dummy_txdata, SIGHASH_ALL);
        std::vector<unsigned char> sig;
        assert(creator.CreateSig(keystore, sig, keyid, prev_scriptpubkey, SigVersion::BASE));
        attack_tx.vin[i].scriptSig = CScript() << sig;
    }

    return attack_tx;
}

/** Mine a block as expensive as possible to validate. Print the time it took to validate it. Interesting to set
 * different `worker_threads_num` values in setup_common.cpp. */
BOOST_FIXTURE_TEST_CASE(worst_block_test, WorstBlock100Setup)
{
    // We always pay to the same key. We always create 0-value outputs.
    const CKey& attacker_key{coinbaseKey};
    const CScript coinbase_spk{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    const CAmount txouts_value{0};

    // Record the outpoints of the utxos we prepare.
    std::vector<COutPoint> attack_tx_prevouts;
    attack_tx_prevouts.reserve(INPUTS_COUNT);

    // Create the 7'013 outputs we need. Since each output's scriptpubkey has 201 CHECKSIG we can only fit 99
    // such outputs per block. This means we need 71 preparation blocks.
    const CScript attack_prev_spk{AttackPrevScriptPubKey(coinbaseKey)};
    std::vector<CTxOut> prep_txouts{99, CTxOut{txouts_value, attack_prev_spk}};
    for (auto i = 0; attack_tx_prevouts.size() < INPUTS_COUNT; ++i) {
        // Create a block with a 99-outputs transaction.
        std::vector<CTransactionRef> input_transactions = {m_coinbase_txns[i]};
        auto input_outpoints = {COutPoint{input_transactions[0]->GetHash(), 0}};
        auto [tx, _] = CreateValidTransaction(input_transactions, input_outpoints, i, {coinbaseKey}, prep_txouts, {}, {});
        const auto block{CreateAndProcessBlock({tx}, coinbase_spk)};

        // Record the outputs to be referenced in the attack block.
        for (auto j = 0; j < block.vtx[1]->vout.size() && attack_tx_prevouts.size() < INPUTS_COUNT; ++j) {
            attack_tx_prevouts.emplace_back(block.vtx[1]->GetHash(), j);
        }
    }

    // Mine a block with the attack tx.
    std::vector<CTxOut> attack_tx_outs{OUTPUTS_COUNT, CTxOut{0, {}}};
    auto attack_tx = CreateAttackTx(attack_tx_prevouts, attacker_key, attack_prev_spk, txouts_value, std::move(attack_tx_outs));
    auto& chainman{Assert(m_node.chainman)};
    auto block{CreateBlock({attack_tx}, coinbase_spk, chainman->ActiveChainstate())};

    // Record how long it takes to validate the block.
    LOCK(cs_main);
    const auto time_before{SteadyClock::now()};
    BlockValidationState state;
    assert(TestBlockValidity(state, chainman->GetParams(), chainman->ActiveChainstate(), block, chainman->m_blockman.LookupBlockIndex(block.hashPrevBlock), true, true));
    const auto time_after{SteadyClock::now()};
    const auto validation_time{duration_cast<std::chrono::seconds>(time_after - time_before)};
    std::cout << "Block validation took " << validation_time << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()