#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test Taproot softfork (BIPs 340-342)

from decimal import ROUND_HALF_UP, Decimal
from io import BytesIO
from test_framework.util import assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair
from test_framework.address import address_to_scriptpubkey, program_to_witness
from test_framework.key import compute_xonly_pubkey
from test_framework.messages import COIN, COutPoint, CScriptWitness, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxWitness
from test_framework.script import OP_CHECKTEMPLATEVERIFY, CScript, taproot_construct
from test_framework.test_framework import BitcoinTestFramework

def template_hash_for_outputs(outputs, nIn=0, nVin=1, vin_override=None):
    c = CTransaction()
    c.version = 2
    c.vin = vin_override
    if vin_override is None:
        c.vin = [CTxIn()] * nVin
    c.vout = outputs
    #print("template_hash_for_outputs.hex: " + str(c.serialize_with_witness().hex()))
    return c.get_standard_template_hash(nIn)

def get_vout_idx(tx, address):
    vout_index = None
    for detail in tx['details']:
        if detail['address'] == address:
            vout_index = detail['vout']
    if vout_index is None:
        raise "Not found"
    return vout_index

class CtvAmountTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [
            ["-minrelaytxfee=0.00000000"]
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_ctv_output(self, outputs, priv_b, node, amt_output_a, fee=0.00005, nVin=1):
        withdrawl_tx_hash = template_hash_for_outputs(outputs=outputs, nVin = nVin)
        ctv_script = CScript([withdrawl_tx_hash, OP_CHECKTEMPLATEVERIFY])
        xonly_pub = compute_xonly_pubkey(priv_b.get_bytes())[0]
        trinfo = taproot_construct(xonly_pub, scripts=[("ctv_lock", ctv_script)])

        input_a_address = program_to_witness(1, trinfo.output_pubkey)
        input_a_txid = node.sendtoaddress(input_a_address, amt_output_a + fee)
        self.generate(node, 1)
        fund_tx_input_a = node.gettransaction(input_a_txid)
        assert(fund_tx_input_a['confirmations'] == 1)
        input_a_vout_index = get_vout_idx(fund_tx_input_a, input_a_address)

        ctv_outpoint = COutPoint(hash=int(input_a_txid, 16), n=input_a_vout_index)
        return (ctv_outpoint, ctv_script, trinfo)
    
    def setup_withdrawl_tx(self, ctv_outpoint, ctv_script, trinfo, outputs):
        withdrawl_tx = CTransaction()
        withdrawl_tx.vin = [
            CTxIn(outpoint=ctv_outpoint)
        ]
        withdrawl_tx.vout = outputs
        withdrawl_tx.wit = CTxWitness()

        leaf_version = b'\xc1' if trinfo.negflag else b'\xc0'
        scriptWit = CScriptWitness()
        scriptWit.stack = [ctv_script, leaf_version + trinfo.internal_pubkey]

        txInWit0 = CTxInWitness()
        txInWit0.scriptWitness = scriptWit
        txInWit1 = CTxInWitness()
        txInWit1.scriptWitness = CScriptWitness()

        withdrawl_tx.wit.vtxinwit = [txInWit0, txInWit1]
        return withdrawl_tx
    
    def unsatisfiable_ctv_output(self, node):
        amt = Decimal(COIN)
        amt_btc = amt / amt
        priv_b, pub_b = generate_keypair()
        target_address = node.getnewaddress()
        # commit to the correct amount in the CTV hash
        target_output = CTxOut(nValue = int(amt), scriptPubKey= address_to_scriptpubkey(target_address))
        # send the incorrect amount to the output leading to an unsatifiable output script
        incorrect_amount = amt_btc - Decimal(0.0001)
        (ctv_outpoint, ctv_script, trinfo) = self.setup_ctv_output(outputs=[target_output],
                                                                   priv_b=priv_b,
                                                                   node=node,
                                                                   amt_output_a=float(incorrect_amount))
        # now try to create a withdrawl tx, note we use the correct 'target output' as as parameter
        # however since we _funded_ the CTV output incorrect, we cannot ever spend it.
        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint=ctv_outpoint,ctv_script=ctv_script,trinfo=trinfo, outputs=[target_output])
        
        # in this case, we fail in validation logic since 0.99999 BTC < 1 BTC
        assert_raises_rpc_error(code = -26 ,
                                fun= lambda: node.sendrawtransaction(withdrawl_tx.serialize().hex()), 
                                message="bad-txns-in-belowout")
        
        # now lets try to fund the transaction with more money to make sure we don't fail basic amount sanity checks
        fully_funded_withdrawl_tx_result = node.fundrawtransaction(withdrawl_tx.serialize_with_witness().hex())
        fully_funded_withdrawl_tx = CTransaction()
        fully_funded_withdrawl_tx.deserialize(BytesIO(bytes.fromhex(fully_funded_withdrawl_tx_result['hex'])))
        
        # now we fail because we have an incorrect OP_CTV hash, we've added a change output and 
        # the number of inputs we've committed to are incorrect
        assert(len(fully_funded_withdrawl_tx.vin) == 2)
        assert(len(fully_funded_withdrawl_tx.vout) == 2)
        assert_raises_rpc_error(code = -26 ,
                                fun= lambda: node.sendrawtransaction(fully_funded_withdrawl_tx.serialize().hex()), 
                                message="mandatory-script-verify-flag-failed (Script failed an OP_CHECKTEMPLATEVERIFY operation)")
        
        # Thinking about this more, it seems like it would be a very poor choice to commit to exactly 1 input
        # using the OP_CTV opcode as this makes it impossible to recover funds in a situation where you sent the incorrect amount.
        # If you always commit to > 1 input, and you don't commit to a specific scriptSig in the non OP_CTV input,
        # you should be able to create custom output amounts to satisify the OP_CTV script.

        # here is an example of what i'm talking about
        # only difference from our original setup is nVin=2 rather than nVin=1
        # notably, we are still funding the OP_CTV input with the incorrect amount
        (ctv_outpoint, ctv_script, trinfo) = self.setup_ctv_output(outputs=[target_output],
                                                            priv_b=priv_b,
                                                            node=node,
                                                            amt_output_a= float(incorrect_amount),
                                                            nVin=2)
        
        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint=ctv_outpoint,ctv_script=ctv_script,trinfo=trinfo, outputs=[target_output])

        # create an output with the exact amount + fee we need to satisify the OP_CTV script
        rescue_address = node.getnewaddress()
        fee = Decimal(0.00000001)
        rescue_amt = ((amt_btc - incorrect_amount) + fee).quantize(Decimal('0.00000001'), rounding=ROUND_HALF_UP)

        rescue_txid = node.sendtoaddress(rescue_address, rescue_amt)
        rescue_tx = node.gettransaction(rescue_txid)

        rescue_vout_idx = get_vout_idx(rescue_tx,rescue_address)
        rescue_outpoint = COutPoint(int(rescue_txid,16), rescue_vout_idx)

        # confirm the rescue output
        self.generate(node,1)
        # add rescue outpoint to the withdrawl tx
        withdrawl_tx.vin.append(CTxIn(outpoint=rescue_outpoint))
        assert(len(withdrawl_tx.vout) == 1)
        assert(len(withdrawl_tx.vin) == 2)
        # now lets try to fund the transaction with a second input to satisfy the OP_CTV script
        
        utxos_to_sign = [
            {
                "txid": rescue_txid,
                "vout": rescue_outpoint.n,
                # For a P2WPKH from sendtoaddress, the wallet likely knows the scriptPubKey and amount.
                # But providing it doesn't hurt.
                "scriptPubKey": address_to_scriptpubkey(rescue_address).hex(),
                "amount": float(rescue_amt)
            }
        ]
        rescue_withdrawl_tx_result = node.signrawtransactionwithwallet(withdrawl_tx.serialize_with_witness().hex(), 
                                                                       prevtxs=utxos_to_sign)

        rescue_withdrawl_tx = CTransaction()
        rescue_withdrawl_tx.deserialize(BytesIO(bytes.fromhex(rescue_withdrawl_tx_result['hex'])))

        # now we satsify the OP_CTV script because we have 2 inputs, and the correct amount
        # to satisfy the OP_CTV output, and only 1 output (CTV output)
        # the exccess funds are used for a miners fee (beware!)
        assert(len(rescue_withdrawl_tx.vin) == 2)
        for out in rescue_withdrawl_tx.vout:
            print(out)
        assert(len(rescue_withdrawl_tx.vout) == 1)

        node.sendrawtransaction(rescue_withdrawl_tx.serialize().hex())



    def run_test(self):
        self.log.info("Hello world!")
        node = self.nodes[0]
        self.generate(node, 101)
        self.wait_until(lambda: node.getblockcount() == 101, timeout=5)

        # https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki#forwarding-addresses

        # OP_AMOUNTVERIFY:
        # An opcode which verifies the exact amount that is being spent in the transaction, the amount paid as fees,
        # or made available in a given output could be used to make safer OP_CHECKTEMPLATEVERIFY addresses.
        # For instance, if the OP_CHECKTEMPLATEVERIFY program P expects exactly S satoshis,
        # sending S-1 satoshis would result in a frozen UTXO and sending S+n satoshis would result in n satoshis being paid to fee.
        # A range check could restrict the program to only apply for expected values and default to a keypath otherwise, e.g.:
        # IF OP_AMOUNTVERIFY <N> OP_GREATER <PK> CHECKSIG ELSE <H> OP_CHECKTEMPLATEVERIFY

        # The issue is that reusing addresses in this way can lead to loss of funds.
        # Suppose one creates a template address which forwards 1 BTC to cold storage.
        # Creating an output to this address with less than 1 BTC will be frozen permanently.
        # Paying more than 1 BTC will lead to the funds in excess of 1BTC to be paid as a large miner fee.
        # CHECKTEMPLATEVERIFY could commit to the exact amount of bitcoin provided by the inputs/amount of fee paid,
        # but as this is a user error and not a malleability issue this is not done. Future soft-forks could introduce
        # opcodes which allow conditionalizing which template or script branches may be used based on inspecting the
        # amount of funds available in a transaction

        # first lets showcase an unsatisfiable ctv output due to us sending funds less
        # than the required amount committed to in the OP_CTV output
        self.unsatisfiable_ctv_output(node)
        


if __name__ == '__main__':
    CtvAmountTest(__file__).main()