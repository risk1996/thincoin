// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>
#include <memory>

#include <chainparamsseeds.h>

#include <pow.h>
#include <arith_uint256.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nMerkleSalt, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime       = nTime;
    genesis.nBits       = nBits;
    genesis.nMerkleSalt = nMerkleSalt;
    genesis.nNonce      = nNonce;
    genesis.nVersion    = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nMerkleSalt, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "NHK 1/May/2019 Emperor Naruhito ascends the throne";
    const CScript genesisOutputScript = CScript() << ParseHex("04e4869ea5eb6bdd725152d34de7006d2efa0bc821655b44dd167988b9be484f2d866e078a7ee4f285284bc3287b7e8cc33812fa99e203ddbe8b848c6744efebb7") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nMerkleSalt, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 140000; // halving every ~4 years
        consensus.nInitialSubsidy = 100 * COIN;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan = 7 * 24 * 60 * 60; // retarget every 7 days (1 week)
        consensus.nPowTargetSpacing = 15 * 60; // block expected every 15 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 2016; // 75% of 2688
        consensus.nMinerConfirmationWindow = 2688; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x66f49ad85624c33e4fd61aa45c54012509ed4a53308908dd07f56346c7939273"); //1441280

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0xe7;
        pchMessageStart[3] = 0xd6;
        nDefaultPort = 7814;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1556721739, 727958, 447776, 0x1e0ffff0, 1, consensus.nInitialSubsidy);
        // uint256 prevPoW = uint256S("0x8000000000000000000000000000000000000000000000000000000000000000");
        // while (!CheckSaltedMerkle(genesis.GetSaltedMerkle(), genesis.nBits, prevPoW, consensus)) ++genesis.nMerkleSalt;
        // while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, genesis.GetSaltedMerkle(), consensus)) ++genesis.nNonce;
        // printf("=== Main Params ===\n");
        // printf("Salt  : %d\n", genesis.nMerkleSalt);
        // printf("Nonce : %d\n", genesis.nNonce);
        // printf("Hash  : %s\n", genesis.GetHash().ToString().c_str());
        // printf("PoW   : %s\n", genesis.GetPoWHash().ToString().c_str());
        // printf("Merkle: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("SMTR  : %s\n", genesis.GetSaltedMerkle().ToString().c_str());
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d"));
        assert(genesis.hashMerkleRoot == uint256S("0x917df366245351d7955cacf9c5d5f12f07df8d25d1ec46f0e17bab2437065b10"));

        // Note that of those with the service bits flag, most only support a subset of possible options
        // vSeeds.emplace_back("<domain_name>.<tld>");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,15);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,200);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "thc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = { {
            {0, uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d")},
        } };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 140000; // halving every ~4 years
        consensus.nInitialSubsidy = 100 * COIN;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 7 * 24 * 60 * 60; // retarget every 7 days (1 week)
        consensus.nPowTargetSpacing = 15 * 60; // block expected every 15 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 504; // 75% for testchains
        consensus.nMinerConfirmationWindow = 672; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x1efb29c8187d5a496a33377941d1df415169c3ce5d8c05d055f25b683ec3f9a3"); //612653

        pchMessageStart[0] = 0xf8;
        pchMessageStart[1] = 0xe7;
        pchMessageStart[2] = 0xe6;
        pchMessageStart[3] = 0xd5;
        nDefaultPort = 17812;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1556721739, 727958, 447776, 0x1e0ffff0, 1, consensus.nInitialSubsidy);
        // uint256 prevPoW = uint256S("0x8000000000000000000000000000000000000000000000000000000000000000");
        // while (!CheckSaltedMerkle(genesis.GetSaltedMerkle(), genesis.nBits, prevPoW, consensus)) ++genesis.nMerkleSalt;
        // while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, genesis.GetSaltedMerkle(), consensus)) ++genesis.nNonce;
        // printf("=== TestNet Params ===\n");
        // printf("Salt  : %d\n", genesis.nMerkleSalt);
        // printf("Nonce : %d\n", genesis.nNonce);
        // printf("Hash  : %s\n", genesis.GetHash().ToString().c_str());
        // printf("PoW   : %s\n", genesis.GetPoWHash().ToString().c_str());
        // printf("Merkle: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("SMTR  : %s\n", genesis.GetSaltedMerkle().ToString().c_str());
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d"));
        assert(genesis.hashMerkleRoot == uint256S("0x917df366245351d7955cacf9c5d5f12f07df8d25d1ec46f0e17bab2437065b10"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        // vSeeds.emplace_back("<domain_name>.<tld>");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,100);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,226);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,183);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tthc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = { {
            {0, uint256S("0x9e06448aaabfd0e2cde4f9a1a6f639702b90f4d24714465f1357820c632f5e1d")},
        } };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nInitialSubsidy = 100 * COIN;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256S("0x00");
        consensus.BIP65Height = 100000000;
        consensus.BIP66Height = 100000000;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 7 * 24 * 60 * 60; // retarget every 7 days (1 week)
        consensus.nPowTargetSpacing = 15 * 60; // block expected every 15 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 36; // 75% for testchains
        consensus.nMinerConfirmationWindow = 48; // Faster than normal for regtest (48 instead of 672)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xf7;
        pchMessageStart[1] = 0xe6;
        pchMessageStart[2] = 0xe5;
        pchMessageStart[3] = 0xd4;
        nDefaultPort = 17811;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1556721739, 727958, 144, 0x1f7fffff, 1, consensus.nInitialSubsidy);
        // uint256 prevPoW = uint256S("0x8000000000000000000000000000000000000000000000000000000000000000");
        // while (!CheckSaltedMerkle(genesis.GetSaltedMerkle(), genesis.nBits, prevPoW, consensus)) ++genesis.nMerkleSalt;
        // while (!CheckProofOfWork(genesis.GetPoWHash(), genesis.nBits, genesis.GetSaltedMerkle(), consensus)) ++genesis.nNonce;
        // printf("=== RegTest Params ===\n");
        // printf("Salt  : %d\n", genesis.nMerkleSalt);
        // printf("Nonce : %d\n", genesis.nNonce);
        // printf("Hash  : %s\n", genesis.GetHash().ToString().c_str());
        // printf("PoW   : %s\n", genesis.GetPoWHash().ToString().c_str());
        // printf("Merkle: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        // printf("SMTR  : %s\n", genesis.GetSaltedMerkle().ToString().c_str());
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xabb901180f42e0e3bc20fa3b25262baad2d1b30ce70b3998c41fe3e7cbfbfff3"));
        assert(genesis.hashMerkleRoot == uint256S("0x917df366245351d7955cacf9c5d5f12f07df8d25d1ec46f0e17bab2437065b10"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = { {
            {0, uint256S("0xabb901180f42e0e3bc20fa3b25262baad2d1b30ce70b3998c41fe3e7cbfbfff3")},
        } };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,100);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,226);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1,183);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "rthc";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
