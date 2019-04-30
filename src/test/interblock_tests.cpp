// Copyright (c) 2019 The Thincoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
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

BOOST_AUTO_TEST_SUITE_END()