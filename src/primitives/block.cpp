// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <streams.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    // * Get Proof-of-Work Hash function was using Scrypt, now using Dash's X11.
    std::vector<unsigned char> vch(80);
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
    ss << *this;
    return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
}

uint256 CBlockHeader::GetSaltedMerkle() const
{
    // * Get Proof-of-Work Salted Merkle Tree Root using X11.
    std::vector<unsigned char> vch(80);
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
    ss << this->hashMerkleRoot << this->nMerkleSalt;
    return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
}

std::string CBlockHeader::ToString() const
{
    return strprintf("CBlockHeader(hashPrevBlock=%s, hashMerkleRoot=%s, hashBlock=%s, nTime=%u, nBits=%08x, nMerkleSalt=%u, nNonce=%u)",
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        GetHash().ToString(),
        nTime, nBits, nMerkleSalt, nNonce);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nMerkleSalt=%u, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nMerkleSalt, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
