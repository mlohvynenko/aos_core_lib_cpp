/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include <core/common/tests/mocks/certprovidermock.hpp>
#include <core/common/tests/utils/log.hpp>
#include <core/common/tools/heapallocator.hpp>
#include <core/iam/tests/mocks/certloadermock.hpp>
#include <core/sm/imagemanager/keyprovider.hpp>

using namespace testing;

namespace aos::sm::imagemanager {

namespace {

constexpr auto cCertType  = "diskencryption";
constexpr auto cKeyURL    = "pkcs11:token=aoscore;object=diskencryption?module-path=/lib/softhsm.so&pin-source=/pin";
constexpr auto cDataLabel = "aos-layer-key";

std::vector<uint8_t> MakeKey(uint8_t seed, size_t size = 32)
{
    std::vector<uint8_t> key(size);

    for (size_t i = 0; i < size; i++) {
        key[i] = static_cast<uint8_t>(seed + i);
    }

    return key;
}

Action<Error(const String&, const Array<uint8_t>&, const Array<uint8_t>&, CertInfo&)> ReturnCert(const char* keyURL)
{
    return Invoke([keyURL](const String&, const Array<uint8_t>&, const Array<uint8_t>&, CertInfo& info) {
        info.mKeyURL = keyURL;

        return ErrorEnum::eNone;
    });
}

Action<Error(const String&, const String&, Array<uint8_t>&)> ReturnData(const std::vector<uint8_t>& data)
{
    return Invoke([data](const String&, const String&, Array<uint8_t>& out) {
        return out.Assign(Array<uint8_t>(data.data(), data.size()));
    });
}

// Allocator that can be switched to fail, to exercise out-of-memory paths.
class SwitchAllocator : public AllocatorItf {
public:
    void* Allocate(size_t size) override { return mFail ? nullptr : mHeap.Allocate(size); }
    void  Free(void* data) override { mHeap.Free(data); }

    bool mFail = false;

private:
    HeapAllocator mHeap;
};

} // namespace

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class LocalDataKeyProviderTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        ASSERT_TRUE(mProvider.Init(mAllocator, mCertProvider, mCertLoader, cCertType).IsNone());
    }

    HeapAllocator mAllocator;

    StrictMock<iamclient::CertProviderMock> mCertProvider;
    StrictMock<crypto::CertLoaderMock>      mCertLoader;

    KeyProvider mProvider;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(LocalDataKeyProviderTest, GetKeyReadsDataObjectFromTokenOfTheCert)
{
    const auto expectedKey = MakeKey(1);

    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _))
        .WillOnce(Invoke(
            [](const String& certType, const Array<uint8_t>& issuer, const Array<uint8_t>& serial, CertInfo& info) {
                EXPECT_STREQ(certType.CStr(), cCertType);
                EXPECT_TRUE(issuer.IsEmpty());
                EXPECT_TRUE(serial.IsEmpty());

                info.mKeyURL = cKeyURL;

                return ErrorEnum::eNone;
            }));

    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _))
        .WillOnce(Invoke([&](const String& url, const String& label, Array<uint8_t>& out) {
            EXPECT_STREQ(url.CStr(), cKeyURL);
            EXPECT_STREQ(label.CStr(), cDataLabel);

            return out.Assign(Array<uint8_t>(expectedKey.data(), expectedKey.size()));
        }));

    StaticArray<uint8_t, crypto::cKeySize> key;

    ASSERT_TRUE(mProvider.GetKey(key).IsNone());

    EXPECT_EQ(std::vector<uint8_t>(key.begin(), key.end()), expectedKey);
}

TEST_F(LocalDataKeyProviderTest, GetKeyDoesNotUseCertPrivateKey)
{
    // StrictMock: any LoadPrivKeyByURL / LoadCertsChainByURL call would fail the test, as the cert is only
    // used to locate the token.
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _)).WillOnce(ReturnData(MakeKey(2)));

    StaticArray<uint8_t, crypto::cKeySize> key;

    ASSERT_TRUE(mProvider.GetKey(key).IsNone());
}

TEST_F(LocalDataKeyProviderTest, KeyIsCachedAfterFirstFetch)
{
    const auto expectedKey = MakeKey(3);

    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).Times(1).WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _)).Times(1).WillOnce(ReturnData(expectedKey));

    StaticArray<uint8_t, crypto::cKeySize> first, second;

    ASSERT_TRUE(mProvider.GetKey(first).IsNone());
    ASSERT_TRUE(mProvider.GetKey(second).IsNone());

    EXPECT_EQ(std::vector<uint8_t>(first.begin(), first.end()), expectedKey);
    EXPECT_EQ(std::vector<uint8_t>(second.begin(), second.end()), expectedKey);
}

TEST_F(LocalDataKeyProviderTest, GetCertFailureIsReturnedAndRetried)
{
    const auto expectedKey = MakeKey(4);

    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _))
        .WillOnce(Return(ErrorEnum::eNotFound))
        .WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _)).WillOnce(ReturnData(expectedKey));

    StaticArray<uint8_t, crypto::cKeySize> key;

    EXPECT_TRUE(mProvider.GetKey(key).Is(ErrorEnum::eNotFound));
    EXPECT_TRUE(key.IsEmpty());

    // A failed fetch must not be cached: the next call tries again.
    ASSERT_TRUE(mProvider.GetKey(key).IsNone());
    EXPECT_EQ(std::vector<uint8_t>(key.begin(), key.end()), expectedKey);
}

TEST_F(LocalDataKeyProviderTest, LoadDataFailureIsReturnedAndRetried)
{
    const auto expectedKey = MakeKey(5);

    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).Times(2).WillRepeatedly(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _))
        .WillOnce(Return(ErrorEnum::eNotFound))
        .WillOnce(ReturnData(expectedKey));

    StaticArray<uint8_t, crypto::cKeySize> key;

    EXPECT_TRUE(mProvider.GetKey(key).Is(ErrorEnum::eNotFound));
    EXPECT_TRUE(key.IsEmpty());

    ASSERT_TRUE(mProvider.GetKey(key).IsNone());
    EXPECT_EQ(std::vector<uint8_t>(key.begin(), key.end()), expectedKey);
}

TEST_F(LocalDataKeyProviderTest, GetKeyFailsIfOutputBufferIsTooSmall)
{
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadDataByURL(_, _, _)).WillOnce(ReturnData(MakeKey(6, 32)));

    StaticArray<uint8_t, 16> tooSmall;

    EXPECT_TRUE(mProvider.GetKey(tooSmall).Is(ErrorEnum::eNoMemory));
}

TEST(LocalDataKeyProviderInitTest, InitFailsIfCertTypeIsTooLong)
{
    HeapAllocator                           allocator;
    StrictMock<iamclient::CertProviderMock> certProvider;
    StrictMock<crypto::CertLoaderMock>      certLoader;
    KeyProvider                             provider;

    const std::string tooLong(cCertTypeLen + 1, 'a');

    EXPECT_TRUE(provider.Init(allocator, certProvider, certLoader, tooLong.c_str()).Is(ErrorEnum::eNoMemory));
}

TEST(LocalDataKeyProviderInitTest, GetKeyFailsIfAllocatorIsOutOfMemory)
{
    SwitchAllocator                         allocator;
    StrictMock<iamclient::CertProviderMock> certProvider;
    StrictMock<crypto::CertLoaderMock>      certLoader;
    KeyProvider                             provider;

    ASSERT_TRUE(provider.Init(allocator, certProvider, certLoader, cCertType).IsNone());

    allocator.mFail = true;

    StaticArray<uint8_t, 32> key;

    // neither GetCert nor LoadDataByURL is reached (StrictMock): the temporary CertInfo can't be allocated.
    EXPECT_TRUE(provider.GetKey(key).Is(ErrorEnum::eNoMemory));
}

} // namespace aos::sm::imagemanager
