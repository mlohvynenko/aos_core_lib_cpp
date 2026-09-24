/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/resource.h>

#include <algorithm>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include <core/common/crypto/cryptohelper.hpp>
#include <core/common/crypto/tests/gcmtestvector.hpp>
#include <core/common/tests/crypto/providers/cryptofactory.hpp>
#include <core/common/tests/mocks/certprovidermock.hpp>
#include <core/common/tests/mocks/cryptomock.hpp>
#include <core/common/tests/utils/log.hpp>
#include <core/common/tools/heapallocator.hpp>
#include <core/iam/tests/mocks/certloadermock.hpp>
#include <core/sm/imagemanager/blobdecryptor.hpp>

using namespace testing;

namespace aos::sm::imagemanager {

namespace {

constexpr auto cTestDir = "/tmp/localblobdecryptor_test";
constexpr auto cAlg     = "AES256/GCM";
constexpr auto cIVLen   = crypto::AESCipherItf::cGCMIVSize;
constexpr auto cTagLen  = crypto::AESCipherItf::cGCMTagSize;
constexpr auto cCACert  = CERTIFICATES_DIR "/ca.pem";

class KeyProviderMock : public SymmetricKeyProviderItf {
public:
    MOCK_METHOD(Error, GetKey, (Array<uint8_t>&), (override));
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

Bytes ToBytes(const Array<uint8_t>& array)
{
    return {array.begin(), array.end()};
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

Action<Error(Array<uint8_t>&)> ReturnKey(const Bytes& key)
{
    return Invoke([key](Array<uint8_t>& out) { return out.Assign(Array<uint8_t>(key.data(), key.size())); });
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

// Limits the size of files the process can write while the object is alive, to exercise write-failure paths.
class FileSizeLimit {
public:
    explicit FileSizeLimit(rlim_t size)
    {
        getrlimit(RLIMIT_FSIZE, &mOld);

        auto limit     = mOld;
        limit.rlim_cur = size;

        mOldHandler = signal(SIGXFSZ, SIG_IGN);
        setrlimit(RLIMIT_FSIZE, &limit);
    }

    ~FileSizeLimit()
    {
        setrlimit(RLIMIT_FSIZE, &mOld);
        signal(SIGXFSZ, mOldHandler);
    }

private:
    rlimit       mOld {};
    sighandler_t mOldHandler {};
};

} // namespace

/***********************************************************************************************************************
 * Suite: mocked crypto helper
 **********************************************************************************************************************/

class BlobDecryptorTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        std::filesystem::remove_all(cTestDir);
        std::filesystem::create_directories(cTestDir);

        ASSERT_TRUE(mDecryptor.Init(mAllocator, mCryptoHelper, mKeyProvider).IsNone());
    }

    void TearDown() override { std::filesystem::remove_all(cTestDir); }

    const std::string mEncryptedPath = std::string(cTestDir) + "/layer.tar.gz.enc";
    const std::string mDecryptedPath = std::string(cTestDir) + "/layer.tar.gz.dec";

    HeapAllocator mAllocator;

    StrictMock<crypto::CryptoHelperMock> mCryptoHelper;
    StrictMock<KeyProviderMock>          mKeyProvider;

    BlobDecryptor mDecryptor;
};

TEST_F(BlobDecryptorTest, SplitsIVFromCiphertextAndPassesDecryptInfo)
{
    const auto iv         = Pattern(cIVLen, 1);
    const auto ciphertext = Pattern(64 + cTagLen, 2);
    const auto key        = Pattern(32, 3);

    WriteBytes(mEncryptedPath, Concat(iv, ciphertext));

    EXPECT_CALL(mKeyProvider, GetKey(_)).WillOnce(ReturnKey(key));

    Bytes seenCiphertext;

    EXPECT_CALL(mCryptoHelper, Decrypt(_, _, _))
        .WillOnce(
            Invoke([&](const String& encryptedPath, const String& decryptedPath, const crypto::DecryptInfo& info) {
                EXPECT_STREQ(decryptedPath.CStr(), mDecryptedPath.c_str());

                // must decrypt the IV-stripped ciphertext, not the original file
                EXPECT_STRNE(encryptedPath.CStr(), mEncryptedPath.c_str());

                EXPECT_STREQ(info.mBlockAlg.CStr(), cAlg);
                EXPECT_EQ(ToBytes(info.mBlockIV), iv);
                EXPECT_EQ(ToBytes(info.mBlockKey), key);

                seenCiphertext = ReadBytes(encryptedPath.CStr());

                return ErrorEnum::eNone;
            }));

    ASSERT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());

    EXPECT_EQ(seenCiphertext, ciphertext);
}

TEST_F(BlobDecryptorTest, CiphertextIsCopiedExactlyForAllSizes)
{
    const auto iv  = Pattern(cIVLen, 4);
    const auto key = Pattern(32, 5);

    // Around the IV/tag sizes and around the streaming chunk boundaries.
    const std::vector<size_t> sizes {
        0, 1, 15, 16, 17, cFileChunkSize - 1, cFileChunkSize, cFileChunkSize + 1, 3 * cFileChunkSize + 7};

    for (const auto size : sizes) {
        SCOPED_TRACE("ciphertext size " + std::to_string(size));

        const auto ciphertext = Pattern(size, 6);
        const auto original   = Concat(iv, ciphertext);

        WriteBytes(mEncryptedPath, original);

        EXPECT_CALL(mKeyProvider, GetKey(_)).WillOnce(ReturnKey(key));

        Bytes seenIV, seenCiphertext;

        EXPECT_CALL(mCryptoHelper, Decrypt(_, _, _))
            .WillOnce(Invoke([&](const String& encryptedPath, const String&, const crypto::DecryptInfo& info) {
                seenIV         = ToBytes(info.mBlockIV);
                seenCiphertext = ReadBytes(encryptedPath.CStr());

                return ErrorEnum::eNone;
            }));

        ASSERT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());

        EXPECT_EQ(seenIV, iv);
        EXPECT_EQ(seenCiphertext, ciphertext);

        // the original encrypted file is left untouched
        EXPECT_EQ(ReadBytes(mEncryptedPath), original);
    }
}

TEST_F(BlobDecryptorTest, FileShorterThanIVFails)
{
    for (const size_t size : {0, 1, 11}) {
        SCOPED_TRACE("file size " + std::to_string(size));

        WriteBytes(mEncryptedPath, Pattern(size, 7));

        // no key lookup and no decryption must be attempted (StrictMock)
        EXPECT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eInvalidArgument));
    }
}

TEST_F(BlobDecryptorTest, MissingEncryptedFileFails)
{
    EXPECT_FALSE(mDecryptor.Decrypt((mEncryptedPath + ".missing").c_str(), mDecryptedPath.c_str()).IsNone());
}

TEST_F(BlobDecryptorTest, EncryptedPathTooLongForCiphertextSuffixFails)
{
    // no key lookup and no decryption must be attempted (StrictMock): building the ".ct" sibling path fails
    // before either is reached.
    const std::string longPath = std::string(cTestDir) + "/" + std::string(600, 'a');

    WriteBytes(longPath, Concat(Pattern(cIVLen, 13), Pattern(32, 14)));

    EXPECT_FALSE(mDecryptor.Decrypt(longPath.c_str(), mDecryptedPath.c_str()).IsNone());
}

TEST_F(BlobDecryptorTest, CiphertextPathIsDirectoryFails)
{
    WriteBytes(mEncryptedPath, Concat(Pattern(cIVLen, 15), Pattern(32, 16)));

    // pre-create the ".ct" sibling path as a directory, so opening it for writing fails.
    std::filesystem::create_directory(mEncryptedPath + ".ct");

    EXPECT_CALL(mKeyProvider, GetKey(_)).Times(0);

    EXPECT_FALSE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());
}

TEST_F(BlobDecryptorTest, KeyProviderFailureIsReturnedAndTemporaryFileRemoved)
{
    WriteBytes(mEncryptedPath, Concat(Pattern(cIVLen, 8), Pattern(32, 9)));

    EXPECT_CALL(mKeyProvider, GetKey(_)).WillOnce(Return(ErrorEnum::eNotFound));

    EXPECT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eNotFound));

    // only the original file remains in the directory
    std::vector<std::string> files;

    for (const auto& entry : std::filesystem::directory_iterator(cTestDir)) {
        files.push_back(entry.path().string());
    }

    EXPECT_THAT(files, ElementsAre(mEncryptedPath));
}

TEST_F(BlobDecryptorTest, CryptoHelperFailureIsReturned)
{
    WriteBytes(mEncryptedPath, Concat(Pattern(cIVLen, 10), Pattern(32, 11)));

    EXPECT_CALL(mKeyProvider, GetKey(_)).WillOnce(ReturnKey(Pattern(32, 12)));
    EXPECT_CALL(mCryptoHelper, Decrypt(_, _, _)).WillOnce(Return(ErrorEnum::eInvalidChecksum));

    EXPECT_TRUE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eInvalidChecksum));
}

TEST_F(BlobDecryptorTest, CiphertextWriteFailureIsReturned)
{
    // large enough to span more than one chunk-copy iteration in SplitIV.
    WriteBytes(mEncryptedPath, Concat(Pattern(cIVLen, 17), Pattern(256 * 1024, 18)));

    // no key lookup and no decryption must be attempted (StrictMock): the ciphertext copy fails first.
    FileSizeLimit limit(64 * 1024);

    EXPECT_FALSE(mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).IsNone());
}

TEST_F(BlobDecryptorTest, OutOfMemoryDuringCiphertextCopyFails)
{
    SwitchAllocator                      allocator;
    StrictMock<crypto::CryptoHelperMock> cryptoHelper;
    StrictMock<KeyProviderMock>          keyProvider;
    BlobDecryptor                        decryptor;

    ASSERT_TRUE(decryptor.Init(allocator, cryptoHelper, keyProvider).IsNone());

    WriteBytes(mEncryptedPath, Concat(Pattern(cIVLen, 19), Pattern(32, 20)));

    allocator.mFail = true;

    // no key lookup and no decryption must be attempted (StrictMock): the chunk buffer can't be allocated.
    EXPECT_TRUE(decryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str()).Is(ErrorEnum::eNoMemory));
}

/***********************************************************************************************************************
 * Suite: real crypto helper (encrypt with the crypto provider, decrypt with LocalBlobDecryptor)
 **********************************************************************************************************************/

class BlobDecryptorRoundTripTest : public Test {
protected:
    void SetUp() override
    {
        tests::utils::InitLog();

        std::filesystem::remove_all(cTestDir);
        std::filesystem::create_directories(cTestDir);

        ASSERT_TRUE(mCryptoFactory.Init(mAllocator).IsNone());

        mCryptoProvider = &mCryptoFactory.GetCryptoProvider();

        ASSERT_TRUE(
            mCryptoHelper.Init(mAllocator, mCertProvider, *mCryptoProvider, mCertLoader, "http://discovery", cCACert)
                .IsNone());

        ASSERT_TRUE(mDecryptor.Init(mAllocator, mCryptoHelper, mKeyProvider).IsNone());
    }

    void TearDown() override { std::filesystem::remove_all(cTestDir); }

    // Produces the encrypted blob layout: IV | AES-256-GCM ciphertext | authentication tag.
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

    // Decrypts a blob and returns the error; the decrypted output must not exist unless it succeeded.
    Error DecryptBlob(const Bytes& blob, const Bytes& key)
    {
        WriteBytes(mEncryptedPath, blob);

        EXPECT_CALL(mKeyProvider, GetKey(_)).WillOnce(ReturnKey(key));

        return mDecryptor.Decrypt(mEncryptedPath.c_str(), mDecryptedPath.c_str());
    }

    const std::string mEncryptedPath = std::string(cTestDir) + "/layer.tar.gz.enc";
    const std::string mDecryptedPath = std::string(cTestDir) + "/layer.tar.gz.dec";

    // mAllocator must be declared first: members are destroyed in reverse declaration order.
    HeapAllocator mAllocator;

    crypto::DefaultCryptoFactory mCryptoFactory;
    crypto::CryptoProviderItf*   mCryptoProvider {};

    StrictMock<iamclient::CertProviderMock> mCertProvider;
    StrictMock<crypto::CertLoaderMock>      mCertLoader;
    StrictMock<KeyProviderMock>             mKeyProvider;

    crypto::CryptoHelper mCryptoHelper;
    BlobDecryptor        mDecryptor;
};

TEST_F(BlobDecryptorRoundTripTest, DecryptsWhatWasEncrypted)
{
    const auto key = Pattern(32, 20);

    // Around the tag size and around the chunk boundaries the decoder streams the file with (the trailing tag is
    // held back while reading).
    const std::vector<size_t> sizes {0, 1, 15, 16, 17, 1000, cFileChunkSize - 17, cFileChunkSize - 16,
        cFileChunkSize - 15, cFileChunkSize, cFileChunkSize + 1, 3 * cFileChunkSize + 123};

    for (const auto size : sizes) {
        SCOPED_TRACE("plaintext size " + std::to_string(size));

        const auto plain = Pattern(size, 21);
        const auto iv    = Pattern(cIVLen, static_cast<uint8_t>(size));

        Bytes blob;

        ASSERT_NO_FATAL_FAILURE(Encrypt(key, iv, plain, blob));

        ASSERT_TRUE(DecryptBlob(blob, key).IsNone());

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

    ASSERT_TRUE(DecryptBlob(Concat(Concat(iv, cipher), tag), key).IsNone());

    EXPECT_EQ(ReadBytes(mDecryptedPath), plain);
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

TEST_F(BlobDecryptorRoundTripTest, WrongKeyIsRejectedAndLeavesNoOutput)
{
    const auto key   = Pattern(32, 30);
    const auto plain = Pattern(1000, 33);

    Bytes blob;

    ASSERT_NO_FATAL_FAILURE(Encrypt(key, Pattern(cIVLen, 32), plain, blob));

    EXPECT_FALSE(DecryptBlob(blob, Pattern(32, 31)).IsNone());
    EXPECT_FALSE(std::filesystem::exists(mDecryptedPath));
}

TEST_F(BlobDecryptorRoundTripTest, ModifiedBlobIsRejectedAndLeavesNoOutput)
{
    const auto key   = Pattern(32, 40);
    const auto plain = Pattern(3 * cFileChunkSize + 5, 42);

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

        EXPECT_FALSE(DecryptBlob(modified, key).IsNone());
        EXPECT_FALSE(std::filesystem::exists(mDecryptedPath)) << "unauthenticated plaintext was left behind";
    }
}

TEST_F(BlobDecryptorRoundTripTest, BlobWithoutRoomForTagIsRejected)
{
    // IV followed by fewer bytes than an authentication tag
    EXPECT_FALSE(DecryptBlob(Concat(Pattern(cIVLen, 50), Pattern(cTagLen - 1, 51)), Pattern(32, 52)).IsNone());
    EXPECT_FALSE(std::filesystem::exists(mDecryptedPath));
}

TEST_F(BlobDecryptorRoundTripTest, KeyOfWrongSizeIsRejected)
{
    Bytes blob;

    ASSERT_NO_FATAL_FAILURE(Encrypt(Pattern(32, 60), Pattern(cIVLen, 61), Pattern(100, 62), blob));

    // AES256 needs exactly 32 bytes
    EXPECT_FALSE(DecryptBlob(blob, Pattern(16, 60)).IsNone());
}

} // namespace aos::sm::imagemanager
