// Copyright (c) 2019 The Thincoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <pow.h>
#include <validation.h>
#include <miner.h>
#include <uint256.h>

#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(interblock_tests, TestChain100Setup)

bool BetweenWithWrapping(arith_uint256 min, arith_uint256 value, arith_uint256 max)
{
    if (min <= max && (value < min || value > max))
        return false;
    else if (max < min && (value < min && value > max))
        return false;

    return true;
}

uint256 GetSaltedMerkle(uint256 merkleRoot, uint32_t merkleSalt)
{
    std::vector<unsigned char> vch(36);
    CVectorWriter ss(SER_NETWORK, PROTOCOL_VERSION, vch, 0);
    ss << merkleRoot << merkleSalt;
    return HashX11((const char *)vch.data(), (const char *)vch.data() + vch.size());
}

BOOST_AUTO_TEST_CASE(InterblockHash_validity)
{
    // Check validation from no skipping to its allowed maximum value
    for(unsigned int skip = 0; skip <= MAX_SKIP; ++skip)
    {
        // Check every block from regtest
        for(unsigned int i = skip + 1; chainActive[i + skip + 1] != nullptr; ++i)
        {
            // Get current block and previous block with skipping
            CBlockIndex *pblock = chainActive[i];
            CBlockIndex *pprev  = chainActive[i - skip - 1];
            CBlockIndex *pnext  = chainActive[i + skip + 1];
            // printf("skip: %d, i: %d\n", skip, i);
            // printf("%s\n%s\n", pprev->ToString().c_str(), pblock->ToString().c_str());
            arith_uint256 bnTarget, targetLowBound, targetUpBound, skipLowTarget, skipMidTarget, skipUpTarget;
            arith_uint256 MAX_VERIFIABLE = UintToArith256(uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

            // Validate current block's validity
            arith_uint256 blockSaltedMerkle = UintToArith256(pblock->GetBlockSaltedMerkle());
            arith_uint256 blockPoW = UintToArith256(pblock->GetBlockPoWHash());
            bnTarget.SetCompact(pblock->nBits);
            targetLowBound = blockSaltedMerkle;
            targetUpBound  = targetLowBound + bnTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, blockPoW, targetUpBound));
            targetUpBound  = blockPoW;
            targetLowBound = targetLowBound - bnTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, blockSaltedMerkle, targetUpBound));

            BOOST_WARN(MAX_VERIFIABLE / (skip + 1) < bnTarget);
            skipLowTarget  = bnTarget * skip;
            skipMidTarget  = bnTarget * (skip + 1);
            skipUpTarget   = bnTarget * (skip + 2);
            // printf("skp: %s + %s = %s\n", skipLowTarget.ToString().c_str(), bnTarget.ToString().c_str(), skipUpTarget.ToString().c_str());

            // Validate previous blocks' hash valid range of PoW with skip
            arith_uint256 prevSaltedMerkle = UintToArith256(pprev->GetBlockSaltedMerkle());
            arith_uint256 prevPoW = UintToArith256(pprev->GetBlockPoWHash());
            targetLowBound = blockSaltedMerkle - skipMidTarget;
            targetUpBound  = blockSaltedMerkle + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), prevSaltedMerkle.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevSaltedMerkle, targetUpBound));
            targetLowBound = blockPoW - skipUpTarget;
            targetUpBound  = blockPoW + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), prevSaltedMerkle.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevSaltedMerkle, targetUpBound));
            targetLowBound = blockSaltedMerkle - skipLowTarget;
            targetUpBound  = blockSaltedMerkle + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), prevPoW.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevPoW, targetUpBound));
            targetLowBound = blockPoW - skipMidTarget;
            targetUpBound  = blockPoW + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), prevPoW.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevPoW, targetUpBound));

            // Validate next blocks' hash valid range of PoW with skip
            arith_uint256 nextSaltedMerkle = UintToArith256(pnext->GetBlockSaltedMerkle());
            arith_uint256 nextPoW = UintToArith256(pnext->GetBlockPoWHash());
            targetLowBound = blockSaltedMerkle - skipMidTarget;
            targetUpBound  = blockSaltedMerkle + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), nextSaltedMerkle.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextSaltedMerkle, targetUpBound));
            targetLowBound = blockPoW - skipMidTarget;
            targetUpBound  = blockPoW + skipLowTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), nextSaltedMerkle.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextSaltedMerkle, targetUpBound));
            targetLowBound = blockSaltedMerkle - skipMidTarget;
            targetUpBound  = blockSaltedMerkle + skipUpTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), nextPoW.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextPoW, targetUpBound));
            targetLowBound = blockPoW - skipMidTarget;
            targetUpBound  = blockPoW + skipMidTarget;
            // printf("%s < %s < %s ?\n", targetLowBound.ToString().c_str(), nextPoW.ToString().c_str(), targetUpBound.ToString().c_str());
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextPoW, targetUpBound));
        }
    }
}

BOOST_AUTO_TEST_CASE(InterblockTransaction_validity)
{
    // Check validation from no skipping to its allowed maximum value
    for(unsigned int skip = 0; skip <= MAX_SKIP; ++skip)
    {
        // Check every block from regtest
        for(unsigned int i = skip + 1; chainActive[i + skip + 1] != nullptr; ++i)
        {
            // Get current block and previous block with skipping
            CBlockIndex *pblock = chainActive[i];
            CBlockIndex *pprev  = chainActive[i - skip - 1];
            CBlockIndex *pnext  = chainActive[i + skip + 1];
            // printf("skip: %d, i: %d\n", skip, i);
            // printf("%s\n%s\n", pprev->ToString().c_str(), pblock->ToString().c_str());
            arith_uint256 bnTarget, targetLowBound, targetUpBound, skipLowTarget, skipMidTarget, skipUpTarget;
            arith_uint256 MAX_VERIFIABLE = UintToArith256(uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

            // Get their CBlock counterpart in order to access their transactions
            CBlock prevblock, nextblock;
            BOOST_ASSERT(ReadBlockFromDisk(prevblock, pprev, Params().GetConsensus()));
            BOOST_ASSERT(ReadBlockFromDisk(nextblock, pnext, Params().GetConsensus()));

            // Get their coinbase transaction, which is always located at index 0
            const CTransaction *pprevcb = prevblock.vtx[0].get();
            const CTransaction *pnextcb = nextblock.vtx[0].get();

            // Get their merkle branch
            std::vector<uint256> prevbranch = BlockMerkleBranch(prevblock, 0);
            std::vector<uint256> nextbranch = BlockMerkleBranch(nextblock, 0);

            // Get their merkle tree root
            uint256 prevmerkleroot = ComputeMerkleRootFromBranch(pprevcb->GetHash(), prevbranch, 0);
            uint256 nextmerkleroot = ComputeMerkleRootFromBranch(pnextcb->GetHash(), nextbranch, 0);

            // Get the computed salted merkle
            arith_uint256 prevSaltedMerkle = UintToArith256(GetSaltedMerkle(prevmerkleroot, prevblock.nMerkleSalt));
            arith_uint256 nextSaltedMerkle = UintToArith256(GetSaltedMerkle(nextmerkleroot, nextblock.nMerkleSalt));

            // Compute necessary data to determine the valid range
            arith_uint256 blockSaltedMerkle = UintToArith256(pblock->GetBlockSaltedMerkle());
            arith_uint256 blockPoW = UintToArith256(pblock->GetBlockPoWHash());
            bnTarget.SetCompact(pblock->nBits);
            BOOST_WARN(MAX_VERIFIABLE / (skip + 1) < bnTarget);
            skipLowTarget  = bnTarget * skip;
            skipMidTarget  = bnTarget * (skip + 1);
            skipUpTarget   = bnTarget * (skip + 2);

            // Validate previous blocks' hash valid range of salted merkle with skip
            targetLowBound = blockSaltedMerkle - skipMidTarget;
            targetUpBound  = blockSaltedMerkle + skipMidTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevSaltedMerkle, targetUpBound));
            targetLowBound = blockPoW - skipUpTarget;
            targetUpBound  = blockPoW + skipMidTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, prevSaltedMerkle, targetUpBound));

            // Validate next blocks' hash valid range of salted merkle with skip
            targetLowBound = blockSaltedMerkle - skipMidTarget;
            targetUpBound  = blockSaltedMerkle + skipMidTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextSaltedMerkle, targetUpBound));
            targetLowBound = blockPoW - skipMidTarget;
            targetUpBound  = blockPoW + skipLowTarget;
            BOOST_ASSERT(BetweenWithWrapping(targetLowBound, nextSaltedMerkle, targetUpBound));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()