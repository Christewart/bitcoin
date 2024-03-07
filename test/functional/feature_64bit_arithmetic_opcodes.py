#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test for taproot sighash algorithm with pegins and issuances
from test_framework.util import assert_raises_rpc_error
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_uint256, sha256, tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import OP_0, OP_0NOTEQUAL, OP_1ADD, OP_1NEGATE, OP_1SUB, OP_2, OP_3, OP_8, OP_ABS, OP_ADD, OP_CHECKLOCKTIMEVERIFY, OP_DEPTH, OP_DIV, OP_DROP, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_LESSTHAN, OP_LESSTHANOREQUAL, OP_MAX, OP_MIN, OP_MUL, OP_NEGATE, OP_NOT, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_PICK, OP_ROLL, OP_SIZE, OP_SUB, OP_WITHIN, CScript, CScriptNum, CScriptOp, OP_1, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_VERIFY, taproot_construct, SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, LEAF_VERSION_TAPSCRIPT_64BIT
from test_framework.address import output_key_to_p2tr

VALID_SIGHASHES_ECDSA = [
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY + SIGHASH_ALL,
    SIGHASH_ANYONECANPAY + SIGHASH_NONE,
    SIGHASH_ANYONECANPAY + SIGHASH_SINGLE
]

VALID_SIGHASHES_TAPROOT = [SIGHASH_DEFAULT] + VALID_SIGHASHES_ECDSA

class Arithmetic64bitTest(BitcoinTestFramework):

    def add_options(self, parser):
        # idk why but 'createwallet' rpc fails if i don't set this
        # this log occurs in the bitcoind logs saying the wallet is not enabled
        # 2023-09-09T18:17:52.261789Z [init] [wallet/init.cpp:132] [Construct] Wallet disabled!
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1


    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.setup_nodes()


    def get_utxo(self, fund_tx, idx):
        spent = None
        # Coin selection
        for utxo in self.nodes[0].listunspent():
            if utxo["txid"] == ser_uint256(fund_tx.vin[idx].prevout.hash)[::-1].hex() and utxo["vout"] == fund_tx.vin[idx].prevout.n:
                spent = utxo

        assert (spent is not None)
        assert (len(fund_tx.vin) == 2)
        return spent

    def create_taproot_utxo(self, scripts = None):
        # modify the transaction to add one output that should spend previous taproot
        # Create a taproot prevout
        addr = self.nodes[0].getnewaddress()

        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]
        tap = taproot_construct(pub, LEAF_VERSION_TAPSCRIPT_64BIT, scripts)
        spk = tap.scriptPubKey
        addr = output_key_to_p2tr(tap.output_pubkey)

        raw_hex = self.nodes[0].createrawtransaction([], [{addr: 1.2}])

        fund_tx = self.nodes[0].fundrawtransaction(raw_hex, False, )["hex"]

        # Createrawtransaction might rearrage txouts
        prev_vout = None
        for i, out in enumerate(tx_from_hex(fund_tx).vout):
            if spk == out.scriptPubKey:
                prev_vout = i
        signed_raw_tx = self.nodes[0].signrawtransactionwithwallet(fund_tx)
        self.nodes[0].sendrawtransaction(signed_raw_tx['hex'])
        tx = tx_from_hex(signed_raw_tx['hex'])
        tx.rehash()
        self.nodes[0].generate(nblocks=1, invalid_call=False)
        last_blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash())
        assert (tx.hash in last_blk['tx'])

        return tx, prev_vout, spk, sec, pub, tap

    def tapscript_satisfy_test(self, script, inputs = None, fail=None,
                               add_prevout=False, add_spk = False,
                               seq = 0, add_out_spk = None,add_out_value = None,
       ver = 2, locktime = 0, add_num_outputs=False, add_weight=False):
        if inputs is None:
            inputs = []
        # Create a taproot utxo
        scripts = [("s0", script)]
        prev_tx, prev_vout, spk, sec, pub, tap = self.create_taproot_utxo(scripts)

        tx = CTransaction()

        tx.version = ver
        tx.nLockTime = locktime
        # Spend the pegin and taproot tx together
        in_total = prev_tx.vout[prev_vout].nValue #.getAmount()
        fees = 1000
        tap_in_pos = 0

        tx.vin.append(CTxIn(COutPoint(prev_tx.sha256, prev_vout), nSequence=seq))
        tx.vout.append(CTxOut(nValue = in_total - fees, scriptPubKey = spk)) # send back to self
        #tx.vout.append(CTxOut(fees))


        tx.wit.vtxinwit.append(CTxInWitness())


        suffix_annex = []
        control_block = bytes([tap.leaves["s0"].version + tap.negflag]) + tap.internal_pubkey + tap.leaves["s0"].merklebranch
        # Add the prevout to the top of inputs. The witness script will check for equality.
        if add_prevout:
            inputs = [prev_vout.to_bytes(4, 'little'), ser_uint256(prev_tx.sha256)]
        if add_spk:
            ver = CScriptOp.decode_op_n(int.from_bytes(spk[0:1], 'little'))
            inputs = [CScriptNum.encode(CScriptNum(ver))[1:], spk[2:len(spk)]] # always segwit

        if add_out_value is not None:
            value = tx.vout[add_out_value].nValue.vchCommitment
            if len(value) == 9:
                inputs = [value[0:1], value[1:9][::-1]]
            else:
                inputs = [value[0:1], value[1:33]]
        if add_out_spk is not None:
            out_spk  = tx.vout[add_out_spk].scriptPubKey
            if len(out_spk) == 0:
                # Python upstream encoding CScriptNum interesting behaviour where it also encodes the length
                # This assumes the implicit wallet behaviour of using segwit outputs.
                # This is useful while sending scripts, but not while using CScriptNums in constructing scripts
                inputs = [CScriptNum.encode(CScriptNum(-1))[1:], sha256(out_spk)]
            else:
                ver = CScriptOp.decode_op_n(int.from_bytes(out_spk[0:1], 'little'))
                inputs = [CScriptNum.encode(CScriptNum(ver))[1:], out_spk[2:len(out_spk)]] # always segwit
        if add_num_outputs:
            num_outs = len(tx.vout)
            inputs = [CScriptNum.encode(CScriptNum(num_outs))[1:]]
        if add_weight:
            # Add a dummy input and check the overall weight
            inputs = [int(5).to_bytes(8, 'little')]
            wit = inputs + [bytes(tap.leaves["s0"].script), control_block] + suffix_annex
            tx.wit.vtxinwit[tap_in_pos].scriptWitness.stack = wit

            exp_weight = self.nodes[0].decoderawtransaction(tx.serialize().hex())["weight"]
            inputs = [exp_weight.to_bytes(8, 'little')]
        wit = inputs + [bytes(tap.leaves["s0"].script), control_block] + suffix_annex
        tx.wit.vtxinwit[tap_in_pos].scriptWitness.stack = wit

        if fail:
            assert_raises_rpc_error(-26, fail, self.nodes[0].sendrawtransaction, tx.serialize().hex())
            return

        self.nodes[0].sendrawtransaction(hexstring = tx.serialize().hex())
        self.nodes[0].generate(1, invalid_call=False)
        last_blk = self.nodes[0].getblock(self.nodes[0].getbestblockhash())
        tx.rehash()
        assert (tx.hash in last_blk['tx'])

    def run_test(self):
        self.log.info("Starting test case!")
        self.generate(self.nodes[0], 101)
        self.wait_until(lambda: self.nodes[0].getblockcount() == 101, timeout=5)
        # Test whether the above test framework is working
        self.log.info("Test simple op_1")
        self.tapscript_satisfy_test(CScript([OP_1]))

        # short handle to convert int to 8 byte LE
        def le8(x, signed=True):
            return int(x).to_bytes(8, 'little', signed=signed)
        
        def encode(num):
            if (num >= -1 and num <= 16):
                return CScriptOp.encode_op_n(num)
            else:
                return CScriptNum.encode(CScriptNum(num))[1:]

        def encodeWit(num):
            if (num > 0 and num <= 16):
                return int(num).to_bytes(1, 'little', signed=True)
            else:
                # need to drop the push ops in CScriptNum as the witness
                # has already been 'evaluated' (pushed) by the interpreter
                return CScriptNum.encode(CScriptNum(num))[1:]

        def check_add(a, b, c, fail=None):
            script = CScript([OP_ADD, encode(c), OP_EQUAL])
            scriptWit = [encodeWit(a), encodeWit(b)]
            self.tapscript_satisfy_test(script, inputs = scriptWit, fail=fail)

        def check_sub(a, b, c, fail=None):
            script = CScript([OP_SUB, encode(c), OP_EQUAL])
            scriptWit = [encodeWit(a), encodeWit(b)]
            self.tapscript_satisfy_test(script, inputs = scriptWit, fail=fail)

        def check_mul(a, b, c, fail=None):
            script = CScript([OP_MUL, encode(c), OP_EQUAL])
            scriptWit = [encodeWit(a), encodeWit(b)]
            self.tapscript_satisfy_test(script, inputs = scriptWit, fail=fail)

        def check_div(a, b, q, r, fail=None):
            script = CScript([OP_DIV, encode(q), OP_EQUALVERIFY, encode(r), OP_EQUAL])
            scriptWit = [encodeWit(a), encodeWit(b)]
            self.tapscript_satisfy_test(script, inputs = scriptWit, fail=fail)

        def check_le(a, b, res, fail=None):
            self.tapscript_satisfy_test(CScript([OP_LESSTHAN, res, OP_EQUAL]), inputs = [CScriptNum.encode(CScriptNum(a)), CScriptNum.encode(CScriptNum(b))], fail=fail)

        def check_leq(a, b, res, fail=None):
            self.tapscript_satisfy_test(CScript([OP_LESSTHANOREQUAL, res, OP_EQUAL]), inputs = [CScriptNum.encode(CScriptNum(a)), CScriptNum.encode(CScriptNum(b))], fail=fail)

        def check_ge(a, b, res, fail=None):
            self.tapscript_satisfy_test(CScript([OP_GREATERTHAN, res, OP_EQUAL]), inputs = [CScriptNum.encode(CScriptNum(a)), CScriptNum.encode(CScriptNum(b))], fail=fail)

        def check_geq(a, b, res, fail=None):
            self.tapscript_satisfy_test(CScript([OP_GREATERTHANOREQUAL, res, OP_EQUAL]), inputs = [CScriptNum.encode(CScriptNum(a)), CScriptNum.encode(CScriptNum(b))], fail=fail)

        def check_neg(a, res, fail=None):
            script = CScript([OP_NEGATE, encode(res), OP_EQUAL])
            scriptWit = [encodeWit(a)]
            self.tapscript_satisfy_test(script, inputs = scriptWit, fail=fail)

        max = (2**63)-1
        min = (-2**63)+1

        # Arithematic opcodes
        self.log.info("Check Arithmetic opcodes")
        check_add(5, 5, 10)
        check_add(-5, -5, -10)
        check_add(-5, 5, 0)
        check_add(14231, -123213, 14231 - 123213)
        check_add(max, 1, max + 1)
        check_add(5, max, (2**63) + 4)
        check_add(-5, max, max - 5)

        # Subtraction
        check_sub(5, 6, -1)
        check_sub(-5, 6, -11)
        check_sub(-5, -5, 0)
        check_sub(14231, -123213, 14231 + 123213)
        check_sub(max, 4, 2**63 - 5)
        check_sub(-5, max, -5 - max)
        check_sub(max, -4, max + 4)

        # Multiplication
        check_mul(5, 6, 30)
        check_mul(-5, 6, -30)
        check_mul(-5, 0, 0)
        check_mul(-5, -6, 30)
        check_mul(14231, -123213, -14231 * 123213)
        check_mul(2**32, 2**31 - 1, 2**63 - 2**32)
        check_mul(2**32, 2**31, 2**63)
        check_mul(-2**32, 2**31, -2**63)# no  overflow
        check_mul(-2**32, 2**32, -2**64)

        # Division
        check_div(5, 6, 0, 5)
        check_div(4, 2, 2, 0)
        check_div(-5, 6, -1, 1) # r must be in 0<=r<a
        check_div(5, -6, 0, 5) # r must be in 0<=r<a
        check_div(-5, 0, 0, 0, fail="Arithmetic opcode error") # only fails if b = 0
        check_div(6213123213513, 621, 6213123213513//621, 6213123213513 % 621)
        check_div(2**62, 2**31, 2**31, 0)

        self.log.info("Done checking arithmetic op codes, checking comparison op codes...")
        # Less than test
        # Comparison tests
        # Less than
        check_le(5, 6, 1)
        check_le(5, 5, 0)
        check_le(6, 5, 0)

        # Less than equal
        check_leq(5, 6, 1)
        check_leq(5, 5, 1)
        check_leq(6, 5, 0)

        # Greater than
        check_ge(5, 6, 0)
        check_ge(5, 5, 0)
        check_ge(6, 5, 1)

        # Greater than equal
        check_geq(5, 6, 0)
        check_geq(5, 5, 1)
        check_geq(6, 5, 1)

        # equal
        check_neg(5, -5)
        check_neg(-5, 5)
        check_neg(5, 4, fail="Script evaluated without error but finished with a false/empty top stack element")

        check_neg(min, max)

        # out of bounds
        check_add(max + 1, 1, max + 2, fail="mandatory-script-verify-flag-failed (unknown error)") # 2**63 is out of bounds
        check_add(min - 1, 1, min + 1, fail="mandatory-script-verify-flag-failed (unknown error)") # -2**63 is out of bounds
        check_neg(max + 1, 0, fail="mandatory-script-verify-flag-failed (unknown error)")
        check_neg(min - 1, 0, fail="mandatory-script-verify-flag-failed (unknown error)")

        x = 100000000000
        y = 200000000000
        # implicit conversion tests

        # 2 input opcodes
        self.tapscript_satisfy_test(CScript([CScriptNum(y), CScriptNum(y), OP_NUMEQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(x), CScriptNum(y), OP_NUMNOTEQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(y), CScriptNum(y), OP_NUMEQUALVERIFY, OP_1]))
        self.tapscript_satisfy_test(CScript([CScriptNum(x), CScriptNum(y), OP_NUMEQUALVERIFY]), fail="Script failed an OP_NUMEQUALVERIFY operation")
        self.tapscript_satisfy_test(CScript([CScriptNum(x), CScriptNum(y), OP_MIN, CScriptNum(x), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(x), CScriptNum(y), OP_MAX, CScriptNum(y), OP_EQUAL]))

        # 1 input opcodes
        self.tapscript_satisfy_test(CScript([CScriptNum(x), OP_1ADD, CScriptNum(x + 1), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(max), OP_1ADD, CScriptNum(max + 1), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(min), OP_1ADD, CScriptNum(min + 1), OP_EQUAL]))

        self.tapscript_satisfy_test(CScript([CScriptNum(x), OP_1SUB, CScriptNum(x - 1), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(max), OP_1SUB, CScriptNum(max - 1), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(min), OP_1SUB, CScriptNum(min - 1), OP_EQUAL]))

        self.tapscript_satisfy_test(CScript([CScriptNum(max), OP_ABS, CScriptNum(max), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(min), OP_ABS, CScriptNum(max), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([CScriptNum(min + 1), OP_ABS, CScriptNum(max - 1), OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_0, OP_ABS, OP_0, OP_EQUAL]))

        self.tapscript_satisfy_test(CScript([OP_0, OP_NOT]))
        self.tapscript_satisfy_test(CScript([OP_1, OP_NOT, OP_0, OP_EQUAL]))

        self.tapscript_satisfy_test(CScript([OP_0, OP_0NOTEQUAL, OP_NOT]))
        self.tapscript_satisfy_test(CScript([OP_1, OP_0NOTEQUAL]))

        self.tapscript_satisfy_test(CScript([CScriptNum(max), OP_SIZE, OP_8, OP_EQUALVERIFY, OP_DROP, OP_1]))

        self.tapscript_satisfy_test(CScript([OP_DEPTH, OP_0, OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_1, OP_DEPTH, OP_1, OP_EQUALVERIFY]))

        self.tapscript_satisfy_test(CScript([OP_1, OP_0, OP_PICK, OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_1, OP_1, OP_PICK]), fail="Operation not valid with the current stack size")
        self.tapscript_satisfy_test(CScript([OP_1NEGATE, OP_PICK]), fail="Operation not valid with the current stack size")

        self.tapscript_satisfy_test(CScript([OP_2, OP_1, OP_1, OP_ROLL, OP_2, OP_EQUALVERIFY]))
        self.tapscript_satisfy_test(CScript([OP_2, OP_1, OP_0, OP_ROLL, OP_1, OP_EQUALVERIFY, OP_2, OP_EQUAL]))

        self.tapscript_satisfy_test(CScript([OP_3, OP_2, OP_1, OP_WITHIN, OP_0, OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_2, OP_1, OP_3, OP_WITHIN, OP_1, OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_2, OP_2, OP_3, OP_WITHIN, OP_1, OP_EQUAL]))
        self.tapscript_satisfy_test(CScript([OP_2, OP_3, OP_WITHIN, OP_1, OP_EQUAL]), fail="Operation not valid with the current stack size")

        self.tapscript_satisfy_test(CScript([CScriptNum(100), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1]),locktime=100)
        self.tapscript_satisfy_test(CScript([CScriptNum(101), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1]),locktime=100, fail="Locktime requirement not satisfied")
        # come back and implement these
        # self.tapscript_satisfy_test(CScript([OP_0, OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]),seq=2)
        # self.tapscript_satisfy_test(CScript([le8(101), OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1]),locktime=100, fail="Locktime requirement not satisfied")

        # comeback and add OP_CHECKSGIADD test
if __name__ == '__main__':
    Arithmetic64bitTest(__file__).main()
