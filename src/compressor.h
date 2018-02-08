// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>

bool CompressScript(const CScript& script, std::vector<unsigned char> &out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const std::vector<unsigned char> &out);

uint64_t CompressAmount(uint64_t nAmount);
uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
template<typename S>
class ScriptCompressionWrapper
{
private:
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    S &script;
public:
    explicit ScriptCompressionWrapper(S &scriptIn) : script(scriptIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        std::vector<unsigned char> compr;
        if (CompressScript(script, compr)) {
            s << CharArray(compr);
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << CharArray(script);
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<unsigned char> vch(GetSpecialScriptSize(nSize), 0x00);
            s >> CharArray(vch);
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> CharArray(script);
        }
    }
};

template<typename I>
class AmountCompressionWrapper
{
    I& m_val;
public:
    explicit AmountCompressionWrapper(I& val) : m_val(val) {}
    template<typename Stream> void Serialize(Stream& s) const
    {
        s << VARINT(CompressAmount(m_val));
    }
    template<typename Stream> void Unserialize(Stream& s)
    {
        uint64_t v;
        s >> VARINT(v);
        m_val = DecompressAmount(v);
    }
};

template<typename S> ScriptCompressionWrapper<S> ScriptCompress(S& s) { return ScriptCompressionWrapper<S>(s); }
template<typename I> AmountCompressionWrapper<I> AmountCompress(I& i) { return AmountCompressionWrapper<I>(i); }

/** wrapper for CTxOut that provides a more compact serialization */
template<typename O>
class TxOutCompressionWrapper
{
private:
    O &txout;
public:
    TxOutCompressionWrapper(O &txoutIn) : txout(txoutIn) { }
    SERIALIZE_METHODS(TxOutCompressionWrapper<O>, obj) {
        READWRITE(AmountCompress(obj.txout.nValue), ScriptCompress(obj.txout.scriptPubKey));
    }
};

template<typename O> TxOutCompressionWrapper<O> TxOutCompress(O& o) { return TxOutCompressionWrapper<O>(o); }

#endif // BITCOIN_COMPRESSOR_H
