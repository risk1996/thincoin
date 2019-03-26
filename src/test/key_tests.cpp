// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <base58.h>
#include <script/script.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>
#include <test/test_bitcoin.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1 = "7ivnST1SpqkcJhg5T9E2FbFJVMwcjQu2zeJPFswnF9pJbZPsKLP";
static const std::string strSecret2 = "7hnJeVJWE5dYfDyrsT459uP9UhWV2TJu8XUEQeuQ25yrbnk2n2S";
static const std::string strSecret1C = "Wg4PZKnxzABUq8XUePJUXQA8CBS4iCUfoRdjEfrnhTunfU4b9NKY";
static const std::string strSecret2C = "WazxtTvFzjSJjiHy7fzZLJCkRFo8hR816DVCBQJGbnywvJQgdcLu";
static const std::string addr1 = "TWMo9atXzWmhP3LhNZNz3XVEeK2C5n4zxw";
static const std::string addr2 = "TYSHmBkeRTwtq2VuJ1MTLiTQwzVAFkp4ds";
static const std::string addr1C = "TTt84T94tLqEkfRQsheHouDEc5MiepQfRe";
static const std::string addr2C = "TJASD8gMKcZJYZrR7bu8EhTd5rJiFsaVKE";

static const std::string strAddressBad = "Lbi6bpMhSwp2CXkivEeUK9wzyQEFzHDfSr";


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

// void generate_new_keys()
// {
//     CKey k1, k2;
//     k1.MakeNewKey(false);
//     k2.MakeNewKey(false);

//     CBitcoinSecret bsk1, bsk2;
//     bsk1.SetKey(k1);
//     bsk2.SetKey(k2);

//     CPubKey pk1 = k1.GetPubKey();
//     CPubKey pk2 = k2.GetPubKey();

//     printf("%s %s\n", bsk1.ToString().c_str(), EncodeDestination(CTxDestination(pk1.GetID())).c_str());
//     printf("%s %s\n", bsk2.ToString().c_str(), EncodeDestination(CTxDestination(pk2.GetID())).c_str());

//     CKey k1c, k2c;
//     k1c.Set(k1.begin(), k1.end(), true);
//     k2c.Set(k2.begin(), k2.end(), true);

//     CBitcoinSecret bsk1c, bsk2c;
//     bsk1c.SetKey(k1c);
//     bsk2c.SetKey(k2c);

//     CPubKey pk1c = k1c.GetPubKey();
//     CPubKey pk2c = k2c.GetPubKey();

//     printf("%s %s\n", bsk1c.ToString().c_str(), EncodeDestination(CTxDestination(pk1c.GetID())).c_str());
//     printf("%s %s\n", bsk2c.ToString().c_str(), EncodeDestination(CTxDestination(pk2c.GetID())).c_str());
// }

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    CKey key1  = bsecret1.GetKey();
    BOOST_CHECK(key1.IsCompressed() == false);
    CKey key2  = bsecret2.GetKey();
    BOOST_CHECK(key2.IsCompressed() == false);
    CKey key1C = bsecret1C.GetKey();
    BOOST_CHECK(key1C.IsCompressed() == true);
    CKey key2C = bsecret2C.GetKey();
    BOOST_CHECK(key2C.IsCompressed() == true);

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(DecodeDestination(addr1)  == CTxDestination(pubkey1.GetID()));
    BOOST_CHECK(DecodeDestination(addr2)  == CTxDestination(pubkey2.GetID()));
    BOOST_CHECK(DecodeDestination(addr1C) == CTxDestination(pubkey1C.GetID()));
    BOOST_CHECK(DecodeDestination(addr2C) == CTxDestination(pubkey2C.GetID()));

    for (int n=0; n<16; n++)
    {
        std::string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C));

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    std::string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3044022059a064b56670d8563f42d4d96155de73a4c06c0378902f503470bbb0e8ff0f4a02205ef32c008b045487252bcf7f6f37a5021851f7c719b079059b650f232583f26b"));
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("304402204a67150e14e7f2785f31e94bff7209ed86ca1233b07556c37f3e84554595f23502207364165476492a7d4a73d6fe5c7698fad764c5663fdc55ccc90f33bce5553d3e"));
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1b59a064b56670d8563f42d4d96155de73a4c06c0378902f503470bbb0e8ff0f4a5ef32c008b045487252bcf7f6f37a5021851f7c719b079059b650f232583f26b"));
    BOOST_CHECK(detsigc == ParseHex("1f59a064b56670d8563f42d4d96155de73a4c06c0378902f503470bbb0e8ff0f4a5ef32c008b045487252bcf7f6f37a5021851f7c719b079059b650f232583f26b"));
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c4a67150e14e7f2785f31e94bff7209ed86ca1233b07556c37f3e84554595f2357364165476492a7d4a73d6fe5c7698fad764c5663fdc55ccc90f33bce5553d3e"));
    BOOST_CHECK(detsigc == ParseHex("204a67150e14e7f2785f31e94bff7209ed86ca1233b07556c37f3e84554595f2357364165476492a7d4a73d6fe5c7698fad764c5663fdc55ccc90f33bce5553d3e"));
}

BOOST_AUTO_TEST_SUITE_END()
