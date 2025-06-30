#!/usr/bin/env python3
# Copyright (c) 2019-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
# Test Taproot softfork (BIPs 340-342)

from test_framework.address import program_to_witness
from test_framework.key import compute_xonly_pubkey
from test_framework.messages import COutPoint, CTransaction, CTxIn
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

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()

    def setup_ctv_output(self, signature_tx, ctv_inputs, priv_b, node, amt_output_a):
        withdrawl_tx_hash = template_hash_for_outputs(outputs=signature_tx.vout, nVin=2, vin_override=ctv_inputs)
        ctv_script = CScript([withdrawl_tx_hash, OP_CHECKTEMPLATEVERIFY])
        xonly_pub = compute_xonly_pubkey(priv_b.get_bytes())[0]
        trinfo = taproot_construct(xonly_pub, scripts=[("ctv_lock", ctv_script)])

        input_a_address = program_to_witness(1, trinfo.output_pubkey)
        input_a_txid = node.sendtoaddress(input_a_address, amt_output_a)
        self.generate(node, 1)
        fund_tx_input_a = node.gettransaction(input_a_txid)
        input_a_vout_index = get_vout_idx(fund_tx_input_a, input_a_address)

        ctv_outpoint = COutPoint(hash=int(input_a_txid, 16), n=input_a_vout_index)

        return (ctv_outpoint, ctv_script, trinfo)
    def run_test(self):
        self.log.info("Hello world!")
        self.generate(self.nodes[0], 101)
        self.wait_until(lambda: self.nodes[0].getblockcount() == 101, timeout=5)
        # Test whether the above test framework is working
        self.log.info("Test simple op_1")

        # https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki#forwarding-addresses

        # OP_AMOUNTVERIFY:
        # An opcode which verifies the exact amount that is being spent in the transaction, the amount paid as fees,
        # or made available in a given output could be used to make safer OP_CHECKTEMPLATEVERIFY addresses.
        # For instance, if the OP_CHECKTEMPLATEVERIFY program P expects exactly S satoshis,
        # sending S-1 satoshis would result in a frozen UTXO and sending S+n satoshis would result in n satoshis being paid to fee.
        # A range check could restrict the program to only apply for expected values and default to a keypath otherwise, e.g.:
        # IF OP_AMOUNTVERIFY <N> OP_GREATER <PK> CHECKSIG ELSE <H> OP_CHECKTEMPLATEVERIFY


if __name__ == '__main__':
    CtvAmountTest(__file__).main()