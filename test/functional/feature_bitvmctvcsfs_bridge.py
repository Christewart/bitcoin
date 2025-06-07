#!/usr/bin/env python3
# Copyright (c) 2014-2025 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test for taproot sighash algorithm with pegins and issuances

from io import BytesIO
from test_framework.util import assert_raises_rpc_error
from test_framework.key import compute_xonly_pubkey
from test_framework.address import address_to_scriptpubkey, program_to_witness, scripthash_to_p2sh
from test_framework.script_util import script_to_p2sh_script
from test_framework.messages import COIN, COutPoint, CScriptWitness, CTransaction, CTxIn, CTxInWitness, CTxOut, CTxWitness
from test_framework.script import OP_0, OP_1, OP_2DROP, OP_CHECKSIG, OP_CHECKTEMPLATEVERIFY, OP_TRUE, CScript, hash160, taproot_construct
from test_framework.wallet_util import bytes_to_wif, generate_keypair
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

def get_vout_idx_by_scriptpubkey(tx, target_script):
    vout_index = None
    for idx,o in enumerate(tx.vout):
        if o.scriptPubKey == target_script:
            return idx
    if vout_index is None:
        raise "Not found"
    return vout_index


def setup_inputs_and_signature(node, withdrawl_addr, amt_output_a, amt_output_b):
    priv_b, pub_b = generate_keypair()
    redeem_script = CScript([pub_b, OP_CHECKSIG])
    script_b = script_to_p2sh_script(redeem_script)
    scripthash = hash160(redeem_script)
    input_b_address = scripthash_to_p2sh(scripthash)

    input_b_txid = node.sendtoaddress(input_b_address, amt_output_b)
    fund_tx_input_b = node.gettransaction(input_b_txid)
    input_b_vout_index = get_vout_idx(tx=fund_tx_input_b, address=input_b_address)

    outpoint_b = COutPoint(hash=int(input_b_txid, 16), n=input_b_vout_index)
    input_b = CTxIn(outpoint_b, scriptSig=CScript([redeem_script]))

    spend_tx = CTransaction()
    spend_tx.vin = [input_b]
    spend_tx.vout = [
        CTxOut(
            nValue=(amt_output_a + amt_output_b) * COIN - 500,
            scriptPubKey=address_to_scriptpubkey(withdrawl_addr),
        )
    ]

    sign_result = node.signrawtransactionwithkey(
        spend_tx.serialize().hex(),
        [bytes_to_wif(priv_b.get_bytes())],
        [
            {
                'txid': input_b_txid,
                'vout': input_b_vout_index,
                'scriptPubKey': script_b.hex(),
                'redeemScript': redeem_script.hex(),
                'amount': amt_output_b,
            }
        ],
        sighashtype="NONE|ANYONECANPAY",
    )

    signature_tx = CTransaction()
    signature_tx.deserialize(BytesIO(bytes.fromhex(sign_result['hex'])))

    signature = signature_tx.vin[0].scriptSig[0:(len(signature_tx.serialize()) - len(spend_tx.serialize()))]
    print("signature_good: " + signature.hex())
    return priv_b, redeem_script, input_b_txid, input_b_vout_index, signature, signature_tx


def setup_inputs_and_signature_scriptsig_hack(node, withdrawl_addr, amt_output_a, amt_output_b):
    priv_b, pub_b = generate_keypair()
    redeem_script = CScript([pub_b, OP_CHECKSIG])
    script_b = script_to_p2sh_script(redeem_script)
    scripthash = hash160(redeem_script)
    input_b_address = scripthash_to_p2sh(scripthash)

    input_b_txid = node.sendtoaddress(input_b_address, amt_output_b)
    fund_tx_input_b = node.gettransaction(input_b_txid)
    input_b_vout_index = get_vout_idx(tx=fund_tx_input_b, address=input_b_address)

    outpoint_b = COutPoint(hash=int(input_b_txid, 16), n=input_b_vout_index)
    input_b = CTxIn(outpoint_b, scriptSig=CScript([pub_b, OP_CHECKSIG]))

    spend_tx = CTransaction()
    spend_tx.vin = [input_b]
    spend_tx.vout = [
        CTxOut(
            nValue=(amt_output_a + amt_output_b) * COIN - 500,
            scriptPubKey=address_to_scriptpubkey(withdrawl_addr),
        )
    ]

    # first produce the digital signature that satisfies the pubkey embedded in the redeem script
    # this is different than the signature that satisfies the OP_CHECKSIG operation
    # embedded in the script signature as the 'scriptCode's are different.
    sign_result_output_script = node.signrawtransactionwithkey(
        spend_tx.serialize().hex(),
        [bytes_to_wif(priv_b.get_bytes())],
        [
            {
                'txid': input_b_txid,
                'vout': input_b_vout_index,
                'scriptPubKey': script_b.hex(),
                'redeemScript': redeem_script.hex(),
                'amount': amt_output_b,
            }
        ],
        sighashtype="NONE|ANYONECANPAY",
    )

    #print(sign_result_output_script)
    signature_tx = CTransaction()
    signature_tx.deserialize(BytesIO(bytes.fromhex(sign_result_output_script['hex'])))

    ss = signature_tx.vin[0].scriptSig
    output_signature = ss[1:(len(signature_tx.serialize()) - len(spend_tx.serialize()) - 1)]

    # next attempt to produce the digital signature that satisfies the pubkey embedded in the script signature
    # this is different than the signature that satisfies the OP_CHECKSIG operation
    # embedded in the redeem script as the 'scriptCode's are different.
    # note: I currently cannot get this to work. I really wish the 'signrawtransactionwithkey'
    # RPC would just give me back the signature it produced rather than attempting to
    # place it in the right place in the transaction...
    # Currently this is erroring out in various places in bitcoin core due to 
    # this being a very weird nonstandard script...
    sign_result_scriptsig = node.signrawtransactionwithkey(
        spend_tx.serialize().hex(),
        [bytes_to_wif(priv_b.get_bytes())],
        [
            {
                'txid': input_b_txid,
                'vout': input_b_vout_index,
                'scriptPubKey': CScript([pub_b, OP_CHECKSIG, output_signature, redeem_script]).hex()
            }
        ],
        sighashtype="NONE|ANYONECANPAY",
    )
    #print("errors: " + str(sign_result_scriptsig['errors']))
    input_sig_tx = CTransaction()
    input_sig_tx.deserialize(BytesIO(bytes.fromhex(sign_result_scriptsig['hex'])))
    input_signature = input_sig_tx.vin[0].scriptSig[1:(len(input_sig_tx.serialize()) - len(spend_tx.serialize()) - 1)]
    #print("input_sig_tx: " + input_sig_tx.serialize().hex())
    #print("input_signature: " + input_signature.hex())
    custom_scriptsig = CScript([input_signature, pub_b, OP_CHECKSIG, output_signature, redeem_script])
    signature_tx.vin[0].scriptSig = custom_scriptsig
    return priv_b, custom_scriptsig, input_b_txid, input_b_vout_index, output_signature, signature_tx


class BitVMCTVCSFSBridge(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1"]]
        
    
    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

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
    
    def setup_withdrawl_tx(self, ctv_outpoint, outpoint_b, signature_tx, ctv_script, trinfo):
        withdrawl_tx = CTransaction()
        withdrawl_tx.vin = [
            CTxIn(outpoint=ctv_outpoint),
            CTxIn(outpoint_b, scriptSig=signature_tx.vin[0].scriptSig),
        ]
        withdrawl_tx.vout = signature_tx.vout
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


    def test_withdrawl_tx(self, node, withdrawl_tx, should_fail):
        if should_fail:
            assert_raises_rpc_error(code=-25, 
                                    message="bad-txns-inputs-missingorspent", 
                                    fun=lambda: node.sendrawtransaction(withdrawl_tx.serialize_with_witness().hex()))
        else:
            withdrawl_txid = node.sendrawtransaction(withdrawl_tx.serialize_with_witness().hex())
            self.generate(node, 1)
            confs = node.gettransaction(withdrawl_txid)['confirmations']
            assert confs == 1
    
    def run_happy_path_ctv_bitvm_bridge(self, node):
        withdrawl_addr = node.getnewaddress()
        amt_output_a = 50
        amt_output_b = 1

        priv_b, redeem_script, input_b_txid, input_b_vout_index, signature, signature_tx = \
            setup_inputs_and_signature(node, withdrawl_addr, amt_output_a, amt_output_b)

        outpoint_b = COutPoint(hash=int(input_b_txid, 16), n=input_b_vout_index)
        ctv_inputs = [CTxIn(), signature_tx.vin[0]]
        (ctv_outpoint, ctv_script, trinfo) = self.setup_ctv_output(signature_tx,ctv_inputs,priv_b, node, amt_output_a)

        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint, outpoint_b, signature_tx, ctv_script, trinfo)
        self.test_withdrawl_tx(node,withdrawl_tx,should_fail=False)
    
    def steal_bitvm_bridge_funds(self,node):
        withdrawl_address = node.getnewaddress()
        amt_output_a = 50
        amt_output_b = 1

        priv_b, redeem_script, input_b_txid, input_b_vout_index, signature, signature_tx = \
            setup_inputs_and_signature(node, withdrawl_address, amt_output_a, amt_output_b)

        outpoint_b = COutPoint(hash=int(input_b_txid, 16), n=input_b_vout_index)

        ctv_inputs = [CTxIn(), signature_tx.vin[0]]
        (ctv_outpoint, ctv_script, trinfo) = self.setup_ctv_output(signature_tx,ctv_inputs,priv_b, node, amt_output_a)

        attack_script = CScript([OP_2DROP, OP_TRUE])
        attack_output = CTxOut(COIN, attack_script)
        
        unsigned_raw_attack_tx = CTransaction()
        unsigned_raw_attack_tx.vout = [attack_output]
        funded_unsigned_attack_tx = node.fundrawtransaction(unsigned_raw_attack_tx.serialize_with_witness().hex())
        signed_attack_tx_json = node.signrawtransactionwithwallet(funded_unsigned_attack_tx['hex'])

        assert(signed_attack_tx_json['complete'])
        signed_attack_tx_hex = signed_attack_tx_json['hex']
        signed_attack_tx = CTransaction()
        signed_attack_tx.deserialize(BytesIO(bytes.fromhex(signed_attack_tx_hex)))
        attack_input_txid = node.sendrawtransaction(signed_attack_tx_hex)
        self.generate(node, 1)
        
        input_attack_vout_index = get_vout_idx_by_scriptpubkey(tx=signed_attack_tx, target_script=attack_script)
        attack_outpoint = COutPoint(hash=int(attack_input_txid, 16), n=input_attack_vout_index)

        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint, attack_outpoint, signature_tx, ctv_script, trinfo)
        
        self.test_withdrawl_tx(node,withdrawl_tx, should_fail=False)

        # now try honest withdrawl, should fail because utxo has been spent already with the attack utxo
        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint, outpoint_b, signature_tx, ctv_script, trinfo)
        self.test_withdrawl_tx(node,withdrawl_tx, should_fail=True)
    
    def commit_scriptsig_ctv(self,node):
        withdrawl_addr = node.getnewaddress()
        amt_output_a = 50
        amt_output_b = 1
        
        priv_b, redeem_script, input_b_txid, input_b_vout_index, signature, signature_tx = \
            setup_inputs_and_signature_scriptsig_hack(node, withdrawl_addr, amt_output_a, amt_output_b)
        
        print("signature: " + signature.hex())
        print("signature_tx: " + signature_tx.serialize_with_witness().hex())
        
        outpoint_b = COutPoint(hash=int(input_b_txid, 16), n=input_b_vout_index)

        ctv_inputs = [CTxIn(), signature_tx.vin[0]]
        (ctv_outpoint, ctv_script, trinfo) = self.setup_ctv_output(signature_tx,ctv_inputs,priv_b, node, amt_output_a)

        attack_script = CScript([OP_2DROP, OP_TRUE])
        attack_output = CTxOut(COIN, attack_script)
        
        unsigned_raw_attack_tx = CTransaction()
        unsigned_raw_attack_tx.vout = [attack_output]
        funded_unsigned_attack_tx = node.fundrawtransaction(unsigned_raw_attack_tx.serialize_with_witness().hex())
        signed_attack_tx_json = node.signrawtransactionwithwallet(funded_unsigned_attack_tx['hex'])

        assert(signed_attack_tx_json['complete'])
        signed_attack_tx_hex = signed_attack_tx_json['hex']
        signed_attack_tx = CTransaction()
        signed_attack_tx.deserialize(BytesIO(bytes.fromhex(signed_attack_tx_hex)))
        attack_input_txid = node.sendrawtransaction(signed_attack_tx_hex)
        self.generate(node, 1)
        
        input_attack_vout_index = get_vout_idx_by_scriptpubkey(tx=signed_attack_tx, target_script=attack_script)
        attack_outpoint = COutPoint(hash=int(attack_input_txid, 16), n=input_attack_vout_index)

        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint, attack_outpoint, signature_tx, ctv_script, trinfo)
        
        # try to withdraw via the "attack" script, this should fail on input 0 validation 
        # since we now are committing to OP_CHECKSIG in the CTV script
        self.test_withdrawl_tx(node,withdrawl_tx, should_fail=True)

        # now try honest withdrawl, should not fail because we committed to the OP_CHECKSIG operation 
        # in the scriptSig for the OP_CTV script
        withdrawl_tx = self.setup_withdrawl_tx(ctv_outpoint, outpoint_b, signature_tx, ctv_script, trinfo)
        self.test_withdrawl_tx(node,withdrawl_tx, should_fail=False)

    def run_test(self):
        self.log.info("Starting test case!")
        node = self.nodes[0]
        block_count = 200
        self.generate(node, block_count)
        self.wait_until(lambda: node.getblockcount() == block_count, timeout=5)

        # Runs the happy path test case as described by Robin Linus here
        # https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591?u=chris_stewart_5
        self.run_happy_path_ctv_bitvm_bridge(node)
        self.log.info("Done run_happy_path_ctv_bitvm_bridge")
        
        # This test case steals the bitvm bridge funds as described by ajtowns here
        # https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8?u=chris_stewart_5
        self.steal_bitvm_bridge_funds(node)
        self.log.info("Done steal_bitvm_bridge_funds")

        # This test case commits to the scriptPubKey in the scriptSig as described by instagibbs here
        # https://delvingbitcoin.org/t/how-ctv-csfs-improves-bitvm-bridges/1591/8
        # This currently doesn't work, if you want to see how it fails uncomment the next 2 lines
        # the reason it doesn't work is because of limitations with signrawtransactionwithkey
        # To work around this limitation a lot of hacking would be required or writing the sighash
        # algorithm in python.
        #self.commit_scriptsig_ctv(node)
        #self.log.info("Done steal_bitvm_bridge_funds")




if __name__ == '__main__':
    BitVMCTVCSFSBridge(__file__).main()