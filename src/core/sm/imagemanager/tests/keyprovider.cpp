/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>

#include <gmock/gmock.h>

#include <core/common/tests/mocks/certprovidermock.hpp>
#include <core/common/tests/mocks/cryptomock.hpp>
#include <core/common/tests/utils/log.hpp>
#include <core/common/tools/heapallocator.hpp>
#include <core/iam/tests/mocks/certloadermock.hpp>
#include <core/sm/imagemanager/keyprovider.hpp>

using namespace testing;

namespace aos::sm::imagemanager {

namespace {

constexpr auto cCertType = "diskencryption";
// the id/label embedded in this URL are what LoadPrivKeyByURL uses to resolve the layer key itself: this
// "diskencryption" cert module is dedicated to pointing at it, not at a real TLS keypair.
constexpr auto cKeyURL
    = "pkcs11:token=aoscore;object=aos-layer-key;id=%00%01%02?module-path=/lib/softhsm.so&pin-source=/pin";

Action<Error(const String&, const Array<uint8_t>&, const Array<uint8_t>&, CertInfo&)> ReturnCert(const char* keyURL)
{
    return Invoke([keyURL](const String&, const Array<uint8_t>&, const Array<uint8_t>&, CertInfo& info) {
        info.mKeyURL = keyURL;

        return ErrorEnum::eNone;
    });
}

Action<RetWithError<SharedPtr<crypto::PrivateKeyItf>>(const String&)> ReturnKey(
    const SharedPtr<crypto::PrivateKeyItf>& key)
{
    return Invoke([key](const String&) -> RetWithError<SharedPtr<crypto::PrivateKeyItf>> {
        return {key, ErrorEnum::eNone};
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

        mKey = MakeShared<StrictMock<crypto::PrivateKeyMock>>(&mAllocator);
        ASSERT_TRUE(mKey);
    }

    HeapAllocator mAllocator;

    StrictMock<iamclient::CertProviderMock>       mCertProvider;
    StrictMock<crypto::CertLoaderMock>            mCertLoader;
    SharedPtr<StrictMock<crypto::PrivateKeyMock>> mKey;

    KeyProvider mProvider;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(LocalDataKeyProviderTest, GetKeyReadsSecretKeyFromTokenOfTheCert)
{
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _))
        .WillOnce(Invoke(
            [](const String& certType, const Array<uint8_t>& issuer, const Array<uint8_t>& serial, CertInfo& info) {
                EXPECT_STREQ(certType.CStr(), cCertType);
                EXPECT_TRUE(issuer.IsEmpty());
                EXPECT_TRUE(serial.IsEmpty());

                info.mKeyURL = cKeyURL;

                return ErrorEnum::eNone;
            }));

    EXPECT_CALL(mCertLoader, LoadPrivKeyByURL(_))
        .WillOnce(Invoke([&](const String& url) -> RetWithError<SharedPtr<crypto::PrivateKeyItf>> {
            EXPECT_STREQ(url.CStr(), cKeyURL);

            return {mKey, ErrorEnum::eNone};
        }));

    auto [key, err] = mProvider.GetKey();

    ASSERT_TRUE(err.IsNone());
    EXPECT_EQ(key.Get(), mKey.Get());
}

TEST_F(LocalDataKeyProviderTest, GetKeyDoesNotUseCertsChain)
{
    // StrictMock: a LoadCertsChainByURL call would fail the test, as the cert is only used to locate the
    // token/key.
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadPrivKeyByURL(_)).WillOnce(ReturnKey(mKey));

    auto [key, err] = mProvider.GetKey();

    ASSERT_TRUE(err.IsNone());
}

TEST_F(LocalDataKeyProviderTest, KeyIsCachedAfterFirstFetch)
{
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).Times(1).WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadPrivKeyByURL(_)).Times(1).WillOnce(ReturnKey(mKey));

    auto [first, firstErr]   = mProvider.GetKey();
    auto [second, secondErr] = mProvider.GetKey();

    ASSERT_TRUE(firstErr.IsNone());
    ASSERT_TRUE(secondErr.IsNone());
    EXPECT_EQ(first.Get(), mKey.Get());
    EXPECT_EQ(second.Get(), mKey.Get());
}

TEST_F(LocalDataKeyProviderTest, GetCertFailureIsReturnedAndRetried)
{
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _))
        .WillOnce(Return(ErrorEnum::eNotFound))
        .WillOnce(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadPrivKeyByURL(_)).WillOnce(ReturnKey(mKey));

    auto [failedKey, failedErr] = mProvider.GetKey();
    EXPECT_TRUE(failedErr.Is(ErrorEnum::eNotFound));
    EXPECT_FALSE(failedKey);

    // A failed fetch must not be cached: the next call tries again.
    auto [key, err] = mProvider.GetKey();
    ASSERT_TRUE(err.IsNone());
    EXPECT_EQ(key.Get(), mKey.Get());
}

TEST_F(LocalDataKeyProviderTest, LoadKeyFailureIsReturnedAndRetried)
{
    EXPECT_CALL(mCertProvider, GetCert(_, _, _, _)).Times(2).WillRepeatedly(ReturnCert(cKeyURL));
    EXPECT_CALL(mCertLoader, LoadPrivKeyByURL(_))
        .WillOnce(Return(RetWithError<SharedPtr<crypto::PrivateKeyItf>>(nullptr, ErrorEnum::eNotFound)))
        .WillOnce(ReturnKey(mKey));

    auto [failedKey, failedErr] = mProvider.GetKey();
    EXPECT_TRUE(failedErr.Is(ErrorEnum::eNotFound));
    EXPECT_FALSE(failedKey);

    auto [key, err] = mProvider.GetKey();
    ASSERT_TRUE(err.IsNone());
    EXPECT_EQ(key.Get(), mKey.Get());
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

    // neither GetCert nor LoadPrivKeyByURL is reached (StrictMock): the temporary CertInfo can't be
    // allocated.
    auto [key, err] = provider.GetKey();
    EXPECT_TRUE(err.Is(ErrorEnum::eNoMemory));
}

} // namespace aos::sm::imagemanager
