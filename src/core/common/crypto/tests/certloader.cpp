/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <core/common/crypto/certloader.hpp>
#include <core/common/pkcs11/pkcs11.hpp>
#include <core/common/tests/crypto/providers/cryptofactory.hpp>
#include <core/common/tests/crypto/softhsmenv.hpp>
#include <core/common/tests/utils/log.hpp>
#include <core/common/tools/fs.hpp>
#include <core/common/tools/heapallocator.hpp>

namespace aos::crypto {

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

using namespace testing;

class CertloaderTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        ASSERT_TRUE(fs::WriteStringToFile(mPINSource, mPIN, 0664).IsNone());

        ASSERT_TRUE(mCryptoFactory.Init(mAllocator).IsNone());
        mCryptoProvider = &mCryptoFactory.GetCryptoProvider();

        ASSERT_TRUE(mSoftHSMEnv.Init(mAllocator, mPIN, mLabel).IsNone());

        ASSERT_TRUE(
            mCertLoader.Init(mAllocator, mCryptoFactory.GetCryptoProvider(), mSoftHSMEnv.GetManager()).IsNone());

        mLibrary = mSoftHSMEnv.GetLibrary();
        mSlotID  = mSoftHSMEnv.GetSlotID();
    }

    void TearDown() override { ASSERT_TRUE(fs::Remove(mPINSource).IsNone()); }

    void ImportCertificateChainToPKCS11(const Array<uint8_t>& caID, const Array<uint8_t>& clientID)
    {
        Error                             err = ErrorEnum::eNone;
        SharedPtr<pkcs11::SessionContext> session;

        Tie(session, err) = mSoftHSMEnv.OpenUserSession(mPIN, true);
        ASSERT_TRUE(err.IsNone());

        // read certificates
        StaticArray<uint8_t, cCertDERSize> derBlob;
        x509::Certificate                  caCert, clientCert;

        ASSERT_TRUE(fs::ReadFile(CERTIFICATES_DIR "/ca.cer.der", derBlob).IsNone());
        ASSERT_TRUE(mCryptoProvider->DERToX509Cert(derBlob, caCert).IsNone());

        ASSERT_TRUE(fs::ReadFile(CERTIFICATES_DIR "/client.cer.der", derBlob).IsNone());
        ASSERT_TRUE(mCryptoProvider->DERToX509Cert(derBlob, clientCert).IsNone());

        // import certificates
        ASSERT_TRUE(
            pkcs11::Utils(mAllocator, session, *mCryptoProvider).ImportCertificate(caID, mLabel, caCert).IsNone());
        ASSERT_TRUE(pkcs11::Utils(mAllocator, session, *mCryptoProvider)
                        .ImportCertificate(clientID, mLabel, clientCert)
                        .IsNone());
    }

    void WriteDataObject(const String& label, const Array<uint8_t>& value)
    {
        Error                             err = ErrorEnum::eNone;
        SharedPtr<pkcs11::SessionContext> session;

        Tie(session, err) = mSoftHSMEnv.OpenUserSession(mPIN, true);
        ASSERT_TRUE(err.IsNone());

        CK_OBJECT_CLASS dataClass = CKO_DATA;
        CK_BBOOL        trueVal   = CK_TRUE;

        StaticArray<pkcs11::ObjectAttribute, 5> templ;

        ASSERT_TRUE(
            templ.PushBack({CKA_CLASS, Array<uint8_t>(reinterpret_cast<uint8_t*>(&dataClass), sizeof(dataClass))})
                .IsNone());
        ASSERT_TRUE(templ.PushBack({CKA_TOKEN, Array<uint8_t>(reinterpret_cast<uint8_t*>(&trueVal), sizeof(trueVal))})
                        .IsNone());
        ASSERT_TRUE(templ.PushBack({CKA_PRIVATE, Array<uint8_t>(reinterpret_cast<uint8_t*>(&trueVal), sizeof(trueVal))})
                        .IsNone());
        ASSERT_TRUE(
            templ
                .PushBack({CKA_LABEL,
                    Array<uint8_t>(const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(label.Get())), label.Size())})
                .IsNone());
        ASSERT_TRUE(
            templ.PushBack({CKA_VALUE, Array<uint8_t>(const_cast<uint8_t*>(value.Get()), value.Size())}).IsNone());

        pkcs11::ObjectHandle handle    = 0;
        Error                createErr = ErrorEnum::eNone;

        Tie(handle, createErr) = session->CreateObject(templ);
        ASSERT_TRUE(createErr.IsNone());
    }

    void GeneratePrivateKey(const Array<uint8_t>& id)
    {
        Error                             err = ErrorEnum::eNone;
        SharedPtr<pkcs11::SessionContext> session;

        Tie(session, err) = mSoftHSMEnv.OpenUserSession(mPIN, true);
        ASSERT_TRUE(err.IsNone());

        pkcs11::PrivateKey key;

        Tie(key, err)
            = pkcs11::Utils(mAllocator, session, *mCryptoProvider).GenerateRSAKeyPairWithLabel(id, mLabel, 2048);
        ASSERT_TRUE(err.IsNone());
    }

    static constexpr auto mLabel     = "cryptoutils";
    static constexpr auto mPIN       = "admin";
    static constexpr auto mPINSource = "pin.txt";

    // mAllocator must be declared (and therefore destroyed) after any member that allocates from it, since
    // members are destroyed in reverse declaration order.
    HeapAllocator mAllocator;

    DefaultCryptoFactory mCryptoFactory;
    CryptoProviderItf*   mCryptoProvider = nullptr;
    test::SoftHSMEnv     mSoftHSMEnv;

    pkcs11::SlotID                    mSlotID = 0;
    SharedPtr<pkcs11::LibraryContext> mLibrary;
    CertLoader                        mCertLoader;
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(CertloaderTest, ParseScheme)
{
    const char* url1 = "pkcs11:token=aoscore;object=diskencryption;id=2e2769b6-be2c-43ff-b16d-25985a04e6b2?module-path="
                       "/usr/lib/softhsm/libsofthsm2.so";
    const char* url2 = "file:/usr/share/.ssh/rsa.pub";
    const char* url3 = "file/usr/share/.ssh/rsa.pub";

    StaticString<30> scheme;

    ASSERT_EQ(ParseURLScheme(url1, scheme), ErrorEnum::eNone);
    EXPECT_EQ(scheme, "pkcs11");

    ASSERT_EQ(ParseURLScheme(url2, scheme), ErrorEnum::eNone);
    EXPECT_EQ(scheme, "file");

    ASSERT_EQ(ParseURLScheme(url3, scheme), ErrorEnum::eNotFound);
}

TEST_F(CertloaderTest, ParseFileURL)
{
    const char* url1 = "file:/usr/share/.ssh/rsa.pub";
    const char* url2 = "pkcs11:token=aoscore";

    StaticString<cFilePathLen> path;

    ASSERT_EQ(ParseFileURL(url1, path), ErrorEnum::eNone);
    EXPECT_EQ(path, "/usr/share/.ssh/rsa.pub");

    ASSERT_NE(ParseFileURL(url2, path), ErrorEnum::eNone);
}

TEST_F(CertloaderTest, ParsePKCS11URLAllValues)
{
    const auto url1 = "pkcs11:token=aoscore;object=diskencryption;id=%00%01%02%03%04%05%06%07?module-path="
                      "/usr/lib/softhsm/libsofthsm2.so&pin-source="
        + std::string(mPINSource);

    StaticString<cFilePathLen>            library;
    StaticString<pkcs11::cLabelLen>       token;
    StaticString<pkcs11::cLabelLen>       label;
    StaticArray<uint8_t, pkcs11::cIDSize> id;
    StaticString<pkcs11::cPINLen>         userPIN;
    uint8_t                               expectedID[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    ASSERT_EQ(ParsePKCS11URL(url1.c_str(), library, token, label, id, userPIN), ErrorEnum::eNone);

    EXPECT_EQ(library, "/usr/lib/softhsm/libsofthsm2.so");
    EXPECT_EQ(token, "aoscore");
    EXPECT_EQ(label, "diskencryption");
    EXPECT_EQ(userPIN, mPIN);
    EXPECT_EQ(id, Array(expectedID, ArraySize(expectedID)));
}

TEST_F(CertloaderTest, ParsePKCS11URLRequiredValuesOnly)
{
    const char* url1 = "pkcs11:object=diskencryption;id=%AA%BB%CC";

    StaticString<cFilePathLen>      library;
    StaticString<pkcs11::cLabelLen> token;
    StaticString<pkcs11::cLabelLen> label;
    uuid::UUID                      id;
    StaticString<pkcs11::cPINLen>   userPIN;
    uint8_t                         expectedID[] = {0xAA, 0xBB, 0xCC};

    ASSERT_EQ(ParsePKCS11URL(url1, library, token, label, id, userPIN), ErrorEnum::eNone);

    EXPECT_EQ(library, "");
    EXPECT_EQ(token, "");
    EXPECT_EQ(label, "diskencryption");
    EXPECT_EQ(userPIN, "");
    EXPECT_EQ(id, Array(expectedID, ArraySize(expectedID)));
}

TEST_F(CertloaderTest, ParsePKCS11URLPinValue)
{
    const auto url = "pkcs11:token=aoscore;object=diskencryption;id=%00%01%02%03%04%05%06%07?module-path="
                     "/usr/lib/softhsm/libsofthsm2.so&pin-value="
        + std::string(mPIN);

    StaticString<cFilePathLen>      library;
    StaticString<pkcs11::cLabelLen> token;
    StaticString<pkcs11::cLabelLen> label;
    uuid::UUID                      id;
    StaticString<pkcs11::cPINLen>   userPIN;

    ASSERT_EQ(ParsePKCS11URL(url.c_str(), library, token, label, id, userPIN), ErrorEnum::eNone);

    EXPECT_EQ(userPIN, mPIN);
}

TEST_F(CertloaderTest, ParsePKCS11URLPinSource)
{
    const auto url = "pkcs11:token=aoscore;object=diskencryption;id=%00%01%02%03%04%05%06%07?module-path="
                     "/usr/lib/softhsm/libsofthsm2.so&pin-source="
        + std::string(mPINSource);

    StaticString<cFilePathLen>      library;
    StaticString<pkcs11::cLabelLen> token;
    StaticString<pkcs11::cLabelLen> label;
    uuid::UUID                      id;
    StaticString<pkcs11::cPINLen>   userPIN;

    ASSERT_EQ(ParsePKCS11URL(url.c_str(), library, token, label, id, userPIN), ErrorEnum::eNone);

    EXPECT_EQ(userPIN, mPIN);
}

TEST_F(CertloaderTest, ParsePKCS11URLPinValueAndPinSource)
{
    const auto url = "pkcs11:token=aoscore;object=diskencryption;id=%00%01%02%03%04%05%06%07?module-path="
                     "/usr/lib/softhsm/libsofthsm2.so&pin-source="
        + std::string(mPINSource) + "&pin-value=" + std::string(mPIN);

    StaticString<cFilePathLen>      library;
    StaticString<pkcs11::cLabelLen> token;
    StaticString<pkcs11::cLabelLen> label;
    uuid::UUID                      id;
    StaticString<pkcs11::cPINLen>   userPIN;

    ASSERT_NE(ParsePKCS11URL(url.c_str(), library, token, label, id, userPIN), ErrorEnum::eNone);
}

TEST_F(CertloaderTest, FindPKCS11CertificateChain)
{
    constexpr uint8_t caID[]     = {0x00, 0x01, 0x02};
    constexpr uint8_t clientID[] = {0x00, 0x01, 0x03};

    ImportCertificateChainToPKCS11(Array(caID, ArraySize(caID)), Array(clientID, ArraySize(clientID)));

    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%00%01%03?module-"
                     "path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    SharedPtr<x509::CertificateChain> chain;
    Error                             error = ErrorEnum::eNone;

    Tie(chain, error) = mCertLoader.LoadCertsChainByURL(url.c_str());
    ASSERT_TRUE(error.IsNone());
    ASSERT_TRUE(chain);
    ASSERT_EQ(chain->Size(), 2);

    // check client certificate
    StaticString<cCertSubjSize> subject;
    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[0].mSubject, subject).IsNone());
    EXPECT_EQ(std::string(subject.CStr()), std::string("CN=Aos Core"));

    StaticString<cCertIssuerSize> issuer;
    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[0].mIssuer, issuer).IsNone());
    EXPECT_EQ(std::string(issuer.CStr()), std::string("CN=Aos Cloud"));

    // check CA certificate
    EXPECT_EQ((*chain)[1].mSubject, (*chain)[1].mIssuer);

    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[1].mIssuer, issuer).IsNone());
    EXPECT_EQ(std::string(issuer.CStr()), std::string("CN=Aos Cloud"));
}

TEST_F(CertloaderTest, FindPKCS11CertificateChainBadURL)
{
    constexpr uint8_t caID[]     = {0x00, 0x01, 0x02};
    constexpr uint8_t clientID[] = {0x00, 0x01, 0x03};

    ImportCertificateChainToPKCS11(Array(caID, ArraySize(caID)), Array(clientID, ArraySize(clientID)));

    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%00%01%04?module-"
                     "path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    SharedPtr<x509::CertificateChain> chain;
    Error                             error = ErrorEnum::eNone;

    Tie(chain, error) = mCertLoader.LoadCertsChainByURL(url.c_str());
    ASSERT_TRUE(error.Is(ErrorEnum::eNotFound));
}

TEST_F(CertloaderTest, FindPKCS11PrivateKey)
{
    constexpr uint8_t id[] = {0xAA, 0xBB, 0xCC};

    GeneratePrivateKey(Array(id, ArraySize(id)));

    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%AA%BB%CC?module-"
                     "path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    SharedPtr<PrivateKeyItf> privKey;
    Error                    error = ErrorEnum::eNone;

    Tie(privKey, error) = mCertLoader.LoadPrivKeyByURL(url.c_str());
    ASSERT_TRUE(error.IsNone());
    ASSERT_TRUE(privKey);
}

TEST_F(CertloaderTest, FindPKCS11PrivateKeyBadURL)
{
    constexpr uint8_t id[] = {0xAA, 0xBB, 0xCC};

    GeneratePrivateKey(Array(id, ArraySize(id)));

    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%AA%BB%FF?module-"
                     "path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    SharedPtr<PrivateKeyItf> privKey;
    Error                    error = ErrorEnum::eNone;

    Tie(privKey, error) = mCertLoader.LoadPrivKeyByURL(url.c_str());
    ASSERT_TRUE(error.Is(ErrorEnum::eNotFound));
}

TEST_F(CertloaderTest, FindCertificatesFromFile)
{
    const char* url = "file:" CERTIFICATES_DIR "/client-ca-chain.pem";

    SharedPtr<x509::CertificateChain> chain;
    Error                             error = ErrorEnum::eNone;

    Tie(chain, error) = mCertLoader.LoadCertsChainByURL(url);
    ASSERT_TRUE(error.IsNone());
    ASSERT_TRUE(chain);
    ASSERT_EQ(chain->Size(), 2);

    // check client certificate
    StaticString<cCertSubjSize> subject;
    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[0].mSubject, subject).IsNone());
    EXPECT_EQ(std::string(subject.CStr()), std::string("CN=Aos Core"));

    StaticString<cCertIssuerSize> issuer;
    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[0].mIssuer, issuer).IsNone());
    EXPECT_EQ(std::string(issuer.CStr()), std::string("CN=Aos Cloud"));

    // check CA certificate
    EXPECT_EQ((*chain)[1].mSubject, (*chain)[1].mIssuer);

    ASSERT_TRUE(mCryptoProvider->ASN1DecodeDN((*chain)[1].mIssuer, issuer).IsNone());
    EXPECT_EQ(std::string(issuer.CStr()), std::string("CN=Aos Cloud"));
}

TEST_F(CertloaderTest, LoadDataByURL)
{
    constexpr uint8_t value[]
        = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    WriteDataObject("aos-layer-key", Array(value, ArraySize(value)));

    // the URL's own object/id identify a cert/key and are irrelevant to LoadDataByURL (only token/library/PIN
    // are used), but ParsePKCS11URL requires them to be present syntactically.
    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%00%01%02?module-path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    StaticArray<uint8_t, ArraySize(value)> data;

    ASSERT_TRUE(mCertLoader.LoadDataByURL(url.c_str(), "aos-layer-key", data).IsNone());
    EXPECT_EQ(data, Array(value, ArraySize(value)));
}

TEST_F(CertloaderTest, LoadDataByURLNotFound)
{
    const auto url = "pkcs11:token=cryptoutils;object=cryptoutils;id=%00%01%02?module-path=" SOFTHSM2_LIB "&pin-source="
        + std::string(mPINSource);

    StaticArray<uint8_t, 32> data;

    ASSERT_TRUE(mCertLoader.LoadDataByURL(url.c_str(), "no-such-label", data).Is(ErrorEnum::eNotFound));
}

TEST_F(CertloaderTest, LoadDataByURLUnsupportedScheme)
{
    StaticArray<uint8_t, 32> data;

    ASSERT_TRUE(
        mCertLoader.LoadDataByURL("file:/tmp/aos-layer-key", "aos-layer-key", data).Is(ErrorEnum::eNotSupported));
}

TEST_F(CertloaderTest, LoadDataByURLBadScheme)
{
    StaticArray<uint8_t, 32> data;

    // no ":" at all, so ParseURLScheme itself fails.
    ASSERT_FALSE(mCertLoader.LoadDataByURL("not-a-url", "aos-layer-key", data).IsNone());
}

TEST_F(CertloaderTest, LoadDataByURLBadPKCS11URL)
{
    StaticArray<uint8_t, 32> data;

    // "object" and "id" are mandatory for ParsePKCS11URL, even though LoadDataByURL itself ignores them.
    ASSERT_FALSE(mCertLoader.LoadDataByURL("pkcs11:token=cryptoutils", "aos-layer-key", data).IsNone());
}

TEST_F(CertloaderTest, LoadDataByURLOpenSessionFailure)
{
    const auto url = "pkcs11:token=no-such-token;object=cryptoutils;id=%00%01%02?module-path=" SOFTHSM2_LIB
                     "&pin-source="
        + std::string(mPINSource);

    StaticArray<uint8_t, 32> data;

    ASSERT_FALSE(mCertLoader.LoadDataByURL(url.c_str(), "aos-layer-key", data).IsNone());
}

} // namespace aos::crypto
