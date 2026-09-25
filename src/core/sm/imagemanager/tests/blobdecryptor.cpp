/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include <core/common/crypto/certloader.hpp>
#include <core/common/crypto/tests/gcmtestvector.hpp>
#include <core/common/tests/crypto/providers/cryptofactory.hpp>
#include <core/common/tests/crypto/softhsmenv.hpp>
#include <core/common/tests/mocks/certprovidermock.hpp>
#include <core/common/tests/mocks/cryptomock.hpp>
#include <core/common/tests/utils/log.hpp>
#include <core/common/tools/fs.hpp>
#include <core/common/tools/heapallocator.hpp>
#include <core/sm/imagemanager/blobdecryptor.hpp>
#include <core/sm/imagemanager/keyprovider.hpp>

using namespace testing;

namespace aos::sm::imagemanager {

namespace {

constexpr auto cTestDir = "/tmp/blobdecryptor_test";
constexpr auto cIVLen   = crypto::AESCipherItf::cGCMIVSize;
constexpr auto cTagLen  = crypto::AESCipherItf::cGCMTagSize;

class KeyProviderMock : public SymmetricKeyProviderItf {
public:
    MOCK_METHOD(RetWithError<SharedPtr<crypto::PrivateKeyItf>>, GetKey, (), (override));
};

using Bytes = std::vector<uint8_t>;

Bytes Pattern(size_t size, uint8_t seed)
{
    Bytes result(size);

    for (size_t i = 0; i < size; i++) {
        result[i] = static_cast<uint8_t>(seed + i * 31);
    }

    return result;
}

void WriteBytes(const std::string& path, const Bytes& data)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

Bytes ReadBytes(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);

    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

Bytes Concat(const Bytes& first, const Bytes& second)
{
    Bytes result(first);

    result.insert(result.end(), second.begin(), second.end());

    return result;
}

} // namespace

/***********************************************************************************************************************
 * Suite: mocked key - covers BlobDecryptor's own responsibilities (splitting the IV off the file, staging
 * output, renaming into place only on success) without a real PKCS11 module. The actual AES-GCM
 * encrypt/decrypt/tamper-detection behavior lives in pkcs11::AESPrivateKey and is exercised end-to-end by
 * the round-trip suite below, against a real PKCS11 module.
 **********************************************************************************************************************/

class BlobDecryptorTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        ASSERT_TRUE(mDecryptor.Init(mAllocator, mKeyProvider).IsNone());

        mKey = MakeShared<StrictMock<crypto::PrivateKeyMock>>(&mAllocator);
        ASSERT_TRUE(mKey);
    }

    void TearDown() override
    {
        (void)fs::Remove(mEncryptedPath.c_str());
        (void)fs::Remove(mDecryptedPath.c_str());
    }

    const std::string mEncryptedPath = "/tmp/blobdecryptor_test_layer.tar.gz.enc";
    const std::string mDecryptedPath = "/tmp/blobdecryptor_test_layer.tar.gz.dec";

    HeapAllocator mAllocator;

    StrictMock<KeyProviderMock>                   mKeyProvider;
    SharedPtr<StrictMock<crypto::PrivateKeyMock>> mKey;

    BlobDecryptor mDecryptor;
};

TEST_F(BlobDecryptorTest, SplitsIVAndCallsKeyDecrypt)
{
    const auto iv         = Pattern(cIVLen, 1);
    const auto ciphertext = Pattern(1000, 2);
    const auto tag        = Pattern(cTagLen, 3);
    const auto plain      = Pattern(1000, 4);

    WriteBytes(mEncryptedPath, Concat(Concat(iv, ciphertext), tag));

    EXPECT_CALL(mKeyProvider, GetKey())
        .WillOnce(Return(RetWithError<SharedPtr<crypto::PrivateKeyItf>>(mKey, ErrorEnum::eNone)));

    EXPECT_CALL(*mKey, Decrypt(_, _, _))
        .WillOnce(
            Invoke([&](const Array<uint8_t>& cipher, const crypto::DecryptionOptions& options, Array<uint8_t>& result) {
                const auto& gcmOptions = options.GetValue<crypto::GCMDecryptionOptions>();

                EXPECT_EQ(gcmOptions.mIV, Array<uint8_t>(iv.data(), iv.size()));
                EXPECT_EQ(cipher, Array<uint8_t>(Concat(ciphertext, tag).data(), ciphertext.size() + tag.size()));

                EXPECT_TRUE(result.Assign(Array<uint8_t>(plain.data(), plain.size())).IsNone());

                return ErrorEnum::eNone;
            }));

    ASSERT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());
    EXPECT_EQ(ReadBytes(mDecryptedPath), plain);
}

TEST_F(BlobDecryptorTest, GetKeyFailureIsReturned)
{
    EXPECT_CALL(mKeyProvider, GetKey())
        .WillOnce(Return(RetWithError<SharedPtr<crypto::PrivateKeyItf>>(nullptr, ErrorEnum::eNotFound)));

    // Decrypt must not be reached (StrictMock on mKey): there's no key to call it on. No encrypted file is
    // even needed on disk: GetKey is checked before anything is read.
    EXPECT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eNotFound));
}

TEST_F(BlobDecryptorTest, EncryptedFileTooShortIsRejectedWithoutCallingKey)
{
    EXPECT_CALL(mKeyProvider, GetKey())
        .WillOnce(Return(RetWithError<SharedPtr<crypto::PrivateKeyItf>>(mKey, ErrorEnum::eNone)));

    // shorter than IV + tag: rejected by BlobDecryptor's own size check, key->Decrypt (StrictMock) unreached.
    WriteBytes(mEncryptedPath, Pattern(cIVLen + cTagLen - 1, 5));

    EXPECT_FALSE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());
}

TEST_F(BlobDecryptorTest, KeyDecryptFailureIsReturnedAndLeavesNoOutput)
{
    WriteBytes(mEncryptedPath, Pattern(cIVLen + cTagLen, 6));

    EXPECT_CALL(mKeyProvider, GetKey())
        .WillOnce(Return(RetWithError<SharedPtr<crypto::PrivateKeyItf>>(mKey, ErrorEnum::eNone)));
    EXPECT_CALL(*mKey, Decrypt(_, _, _)).WillOnce(Return(ErrorEnum::eInvalidChecksum));

    EXPECT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eInvalidChecksum));
    EXPECT_FALSE(std::filesystem::exists(mDecryptedPath));
}

/***********************************************************************************************************************
 * Suite: real PKCS11 key (SoftHSM), through the same CertLoader/KeyProvider/BlobDecryptor chain production
 * code uses - encrypts with an independent software implementation, decrypts through the real PKCS11 path
 * with a non-extractable key, matching how the key is actually provisioned.
 **********************************************************************************************************************/

class BlobDecryptorRoundTripTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        std::filesystem::remove_all(cTestDir);
        std::filesystem::create_directories(cTestDir);

        ASSERT_TRUE(fs::WriteStringToFile(mPINSource.c_str(), mPIN, 0664).IsNone());

        ASSERT_TRUE(mCryptoFactory.Init(mAllocator).IsNone());
        mCryptoProvider = &mCryptoFactory.GetCryptoProvider();

        ASSERT_TRUE(mSoftHSMEnv.Init(mAllocator, mPIN, mTokenLabel).IsNone());
        ASSERT_TRUE(mCertLoader.Init(mAllocator, *mCryptoProvider, mSoftHSMEnv.GetManager()).IsNone());
        ASSERT_TRUE(mKeyProvider.Init(mAllocator, mCertProvider, mCertLoader, cCertType).IsNone());
        ASSERT_TRUE(mDecryptor.Init(mAllocator, mKeyProvider).IsNone());

        // this cert module is dedicated to the layer key: its key URL's own id/label directly identify the
        // CKO_SECRET_KEY object imported by ImportSecretKey below (see LoadPrivKeyByURL/FindPrivateKey).
        const auto url = "pkcs11:token=" + std::string(mTokenLabel) + ";object=" + std::string(cKeyLabel)
            + ";id=%00%01%02?module-path=" SOFTHSM2_LIB "&pin-source=" + mPINSource;

        EXPECT_CALL(mCertProvider, GetCert(_, _, _, _))
            .WillRepeatedly(Invoke([url](const String&, const Array<uint8_t>&, const Array<uint8_t>&, CertInfo& info) {
                info.mKeyURL = url.c_str();

                return ErrorEnum::eNone;
            }));
    }

    void TearDown() override
    {
        std::filesystem::remove_all(cTestDir);
        (void)fs::Remove(mPINSource.c_str());
    }

    // Imports a raw AES key into the token as a non-extractable, non-sensitive-value-readable CKO_SECRET_KEY,
    // matching how the key is actually provisioned: Decrypt must work without ever reading it back.
    void ImportSecretKey(const Bytes& key)
    {
        Error                             err = ErrorEnum::eNone;
        SharedPtr<pkcs11::SessionContext> session;

        Tie(session, err) = mSoftHSMEnv.OpenUserSession(mPIN, true);
        ASSERT_TRUE(err.IsNone());

        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        CK_KEY_TYPE     keyType  = CKK_AES;
        CK_BBOOL        trueVal  = CK_TRUE;
        CK_BBOOL        falseVal = CK_FALSE;

        constexpr uint8_t idBytes[] = {0x00, 0x01, 0x02};

        StaticArray<uint8_t, pkcs11::cIDSize> id = Array<uint8_t>(idBytes, ArraySize(idBytes));

        // capped at pkcs11::cObjectAttributesCount (10): CreateObject's own internal conversion buffer is
        // sized to that, regardless of this array's own capacity. CKA_ENCRYPT is left out to make room for
        // CKA_ID: this key is only ever used to decrypt.
        StaticArray<pkcs11::ObjectAttribute, pkcs11::cObjectAttributesCount> templ;

        auto pushBytes = [&](pkcs11::AttributeType type, const void* data, size_t size) {
            ASSERT_TRUE(
                templ.PushBack({type, Array<uint8_t>(reinterpret_cast<uint8_t*>(const_cast<void*>(data)), size)})
                    .IsNone());
        };

        pushBytes(CKA_CLASS, &keyClass, sizeof(keyClass));
        pushBytes(CKA_KEY_TYPE, &keyType, sizeof(keyType));
        pushBytes(CKA_TOKEN, &trueVal, sizeof(trueVal));
        pushBytes(CKA_PRIVATE, &trueVal, sizeof(trueVal));
        // non-extractable, sensitive: this is the production posture. AESPrivateKey must still be able to
        // decrypt with it, since it never reads CKA_VALUE.
        pushBytes(CKA_EXTRACTABLE, &falseVal, sizeof(falseVal));
        pushBytes(CKA_SENSITIVE, &trueVal, sizeof(trueVal));
        pushBytes(CKA_DECRYPT, &trueVal, sizeof(trueVal));
        // must match the "diskencryption" cert module's key URL id/label, since that's what LoadPrivKeyByURL
        // searches for.
        pushBytes(CKA_ID, id.Get(), id.Size());
        pushBytes(CKA_LABEL, cKeyLabel, strlen(cKeyLabel));

        ASSERT_TRUE(templ.PushBack({CKA_VALUE, Array<uint8_t>(const_cast<uint8_t*>(key.data()), key.size())}).IsNone());

        pkcs11::ObjectHandle handle    = 0;
        Error                createErr = ErrorEnum::eNone;

        Tie(handle, createErr) = session->CreateObject(templ);
        ASSERT_TRUE(createErr.IsNone());
    }

    // Produces the encrypted blob layout: IV | AES-256-GCM ciphertext | authentication tag, using the
    // software crypto provider - independent of the PKCS11 decrypt path under test.
    void Encrypt(const Bytes& key, const Bytes& iv, const Bytes& plain, Bytes& blob)
    {
        auto [cipher, err] = mCryptoProvider->CreateAESEncoder(
            "GCM", Array<uint8_t>(key.data(), key.size()), Array<uint8_t>(iv.data(), iv.size()));
        ASSERT_TRUE(err.IsNone());

        auto outBuf = std::make_unique<StaticArray<uint8_t, cFileChunkSize>>();

        blob = iv;

        constexpr size_t cChunk = 4096;

        for (size_t offset = 0; offset < plain.size(); offset += cChunk) {
            ASSERT_TRUE(cipher
                            ->EncryptBlock(
                                Array<uint8_t>(plain.data() + offset, std::min(cChunk, plain.size() - offset)), *outBuf)
                            .IsNone());

            blob.insert(blob.end(), outBuf->begin(), outBuf->end());
        }

        ASSERT_TRUE(cipher->Finalize(*outBuf).IsNone());
        ASSERT_TRUE(outBuf->IsEmpty());

        StaticArray<uint8_t, cTagLen> tag;

        ASSERT_TRUE(cipher->GetTag(tag).IsNone());

        blob.insert(blob.end(), tag.begin(), tag.end());
    }

    Error DecryptBlob(const Bytes& blob)
    {
        WriteBytes(mEncryptedPath, blob);

        return mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str());
    }

    static constexpr auto cCertType = "diskencryption";
    static constexpr auto cKeyLabel = "aos-layer-key";

    const std::string mEncryptedPath = std::string(cTestDir) + "/layer.tar.gz.enc";
    const std::string mDecryptedPath = std::string(cTestDir) + "/layer.tar.gz.dec";

    static constexpr auto mTokenLabel = "blobdecryptor-roundtrip";
    static constexpr auto mPIN        = "admin";
    const std::string     mPINSource  = std::string(cTestDir) + "/pin.txt";

    // mAllocator must be declared first: members are destroyed in reverse declaration order.
    HeapAllocator mAllocator;

    crypto::DefaultCryptoFactory mCryptoFactory;
    crypto::CryptoProviderItf*   mCryptoProvider {};
    test::SoftHSMEnv             mSoftHSMEnv;
    crypto::CertLoader           mCertLoader;

    StrictMock<iamclient::CertProviderMock> mCertProvider;
    KeyProvider                             mKeyProvider;
    BlobDecryptor                           mDecryptor;
};

TEST_F(BlobDecryptorRoundTripTest, DecryptsWhatWasEncrypted)
{
    const auto key = Pattern(32, 20);

    ImportSecretKey(key);

    const std::vector<size_t> sizes {0, 1, 15, 16, 17, 1000, cFileChunkSize, 3 * cFileChunkSize + 123};

    for (const auto size : sizes) {
        SCOPED_TRACE("plaintext size " + std::to_string(size));

        const auto plain = Pattern(size, 21);
        const auto iv    = Pattern(cIVLen, static_cast<uint8_t>(size));

        Bytes blob;

        ASSERT_NO_FATAL_FAILURE(Encrypt(key, iv, plain, blob));

        ASSERT_TRUE(DecryptBlob(blob).IsNone());

        EXPECT_EQ(ReadBytes(mDecryptedPath), plain);
    }
}

TEST_F(BlobDecryptorRoundTripTest, DecryptsBlobProducedByAnIndependentGCMImplementation)
{
    // The layout an external tool has to produce: IV | ciphertext | tag, i.e. IV followed by the output of
    // e.g. Python's AESGCM(key).encrypt(iv, plain, None). The vector is a published AES-256-GCM known answer.
    const Bytes iv(
        aos::crypto::testvectors::cGCMIV, aos::crypto::testvectors::cGCMIV + sizeof(aos::crypto::testvectors::cGCMIV));
    const Bytes cipher(aos::crypto::testvectors::cGCMCipher,
        aos::crypto::testvectors::cGCMCipher + sizeof(aos::crypto::testvectors::cGCMCipher));
    const Bytes tag(aos::crypto::testvectors::cGCMTag,
        aos::crypto::testvectors::cGCMTag + sizeof(aos::crypto::testvectors::cGCMTag));
    const Bytes key(aos::crypto::testvectors::cGCMKey,
        aos::crypto::testvectors::cGCMKey + sizeof(aos::crypto::testvectors::cGCMKey));
    const Bytes plain(aos::crypto::testvectors::cGCMPlain,
        aos::crypto::testvectors::cGCMPlain + sizeof(aos::crypto::testvectors::cGCMPlain));

    ImportSecretKey(key);

    ASSERT_TRUE(DecryptBlob(Concat(Concat(iv, cipher), tag)).IsNone());

    EXPECT_EQ(ReadBytes(mDecryptedPath), plain);
}

TEST_F(BlobDecryptorRoundTripTest, WrongKeyIsRejectedAndLeavesNoOutput)
{
    const auto key   = Pattern(32, 30);
    const auto plain = Pattern(1000, 33);

    ImportSecretKey(Pattern(32, 31));

    Bytes blob;

    ASSERT_NO_FATAL_FAILURE(Encrypt(key, Pattern(cIVLen, 32), plain, blob));

    EXPECT_FALSE(DecryptBlob(blob).IsNone());
    EXPECT_FALSE(std::filesystem::exists(mDecryptedPath));
}

TEST_F(BlobDecryptorRoundTripTest, ModifiedBlobIsRejectedAndLeavesNoOutput)
{
    const auto key   = Pattern(32, 40);
    const auto plain = Pattern(1000, 42);

    ImportSecretKey(key);

    Bytes blob;

    ASSERT_NO_FATAL_FAILURE(Encrypt(key, Pattern(cIVLen, 41), plain, blob));

    struct Case {
        const char*                 mName;
        std::function<void(Bytes&)> mModify;
    };

    const std::vector<Case> cases {
        {"IV", [](Bytes& b) { b[0] ^= 0x01; }},
        {"first ciphertext byte", [](Bytes& b) { b[cIVLen] ^= 0x01; }},
        {"ciphertext in the middle", [](Bytes& b) { b[b.size() / 2] ^= 0x80; }},
        {"last ciphertext byte", [](Bytes& b) { b[b.size() - cTagLen - 1] ^= 0x01; }},
        {"tag", [](Bytes& b) { b[b.size() - 1] ^= 0x01; }},
        {"truncated by one byte", [](Bytes& b) { b.pop_back(); }},
        {"extra trailing byte", [](Bytes& b) { b.push_back(0); }},
    };

    for (const auto& test : cases) {
        SCOPED_TRACE(test.mName);

        auto modified = blob;

        test.mModify(modified);

        std::filesystem::remove(mDecryptedPath);

        EXPECT_FALSE(DecryptBlob(modified).IsNone());
        EXPECT_FALSE(std::filesystem::exists(mDecryptedPath)) << "unauthenticated plaintext was left behind";
    }
}

TEST_F(BlobDecryptorRoundTripTest, BlobWithoutRoomForTagIsRejected)
{
    ImportSecretKey(Pattern(32, 52));

    // IV followed by fewer bytes than an authentication tag
    EXPECT_FALSE(DecryptBlob(Concat(Pattern(cIVLen, 50), Pattern(cTagLen - 1, 51))).IsNone());
    EXPECT_FALSE(std::filesystem::exists(mDecryptedPath));
}

TEST_F(BlobDecryptorRoundTripTest, BlobHasIVCiphertextTagLayout)
{
    const auto plain = Pattern(100, 22);

    Bytes blob;

    ASSERT_NO_FATAL_FAILURE(Encrypt(Pattern(32, 23), Pattern(cIVLen, 24), plain, blob));

    // GCM doesn't pad: IV + as many ciphertext bytes as plaintext + tag
    EXPECT_EQ(blob.size(), cIVLen + plain.size() + cTagLen);
    EXPECT_EQ(Bytes(blob.begin(), blob.begin() + cIVLen), Pattern(cIVLen, 24));
}

} // namespace aos::sm::imagemanager
