/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core/common/tools/error.hpp>
#include <core/common/tools/fs.hpp>
#include <core/common/tools/logger.hpp>

#include "blobdecryptor.hpp"

namespace aos::sm::imagemanager {

namespace {

// Adapts an open fs::File into a crypto::ChunkProviderItf, so the whole ciphertext file never needs to be
// read into memory before decrypting it. buffer is allocator-owned by the caller (BlobDecryptor, which has
// an AllocatorItf) rather than by this class itself: a chunk-sized (tens of KiB) buffer would blow the
// stack budget on a stack-constrained target if it lived in a local variable instead.
class FileChunkProvider : public crypto::ChunkProviderItf {
public:
    FileChunkProvider(fs::File& file, Array<uint8_t>& buffer)
        : mFile(file)
        , mBuffer(buffer)
    {
    }

    RetWithError<Array<uint8_t>> NextChunk() override
    {
        if (mExhausted) {
            return {Array<uint8_t>(), ErrorEnum::eEOF};
        }

        (void)mBuffer.Resize(mBuffer.MaxSize());

        auto err = mFile.ReadBlock(mBuffer);
        if (!err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
            return {Array<uint8_t>(), AOS_ERROR_WRAP(err)};
        }

        if (err.Is(ErrorEnum::eEOF)) {
            mExhausted = true;

            // deliver this last chunk now if it still carries data; the following call reports eEOF
            // with nothing left.
            if (mBuffer.IsEmpty()) {
                return {Array<uint8_t>(), ErrorEnum::eEOF};
            }
        }

        return {mBuffer, ErrorEnum::eNone};
    }

private:
    fs::File&       mFile;
    Array<uint8_t>& mBuffer;
    bool            mExhausted = false;
};

} // namespace

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error BlobDecryptor::Init(AllocatorItf& allocator, iamclient::CertProviderItf& certProvider,
    crypto::CertLoaderItf& certLoader, const String& certType)
{
    mAllocator    = &allocator;
    mCertProvider = &certProvider;
    mCertLoader   = &certLoader;

    if (auto err = mCertType.Assign(certType); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error BlobDecryptor::Decrypt(const String& encryptedPath, const String& decryptedPath)
{
    LOG_DBG() << "Decrypting blob" << Log::Field("encryptedPath", encryptedPath)
              << Log::Field("decryptedPath", decryptedPath);

    auto [key, keyErr] = GetKey();
    if (!keyErr.IsNone()) {
        return AOS_ERROR_WRAP(keyErr);
    }

    auto [encryptedSize, sizeErr] = fs::CalculateSize(*mAllocator, encryptedPath);
    if (!sizeErr.IsNone()) {
        return AOS_ERROR_WRAP(sizeErr);
    }

    if (encryptedSize < crypto::AESCipherItf::cGCMIVSize + crypto::AESCipherItf::cGCMTagSize) {
        return AOS_ERROR_WRAP(
            Error(ErrorEnum::eInvalidArgument, "encrypted file too short to contain an IV and a tag"));
    }

    // rest of the file: ciphertext followed by the 16-byte authentication tag, exactly as
    // crypto::PrivateKeyItf::StreamDecrypt expects it.
    auto cipherSize = encryptedSize - crypto::AESCipherItf::cGCMIVSize;

    // plaintext can't be larger than the ciphertext it came from (GCM never expands data): this buffer is
    // always big enough, however much of it ends up filled in. Most PKCS11 modules (SoftHSM2 included,
    // verified empirically) only release the whole plaintext at the very end, once the authentication tag
    // has been checked, so this can't be chunked the way the ciphertext side is.
    auto plainBuf = mAllocator->Allocate(cipherSize);
    if (!plainBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freePlain = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(plainBuf); });

    Array<uint8_t> plaintext(static_cast<uint8_t*>(plainBuf), cipherSize);

    crypto::GCMDecryptionOptions gcmOptions;

    if (auto err = StreamDecrypt(*key, encryptedPath, gcmOptions, plaintext); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    // staged to a deterministic sibling path and unconditionally removed, unless renamed into place on success
    // below: decryptedPath itself is never touched unless the whole operation, including the tag check, succeeds.
    StaticString<cFilePathLen> stagedPath;

    if (auto err = stagedPath.Format("%s.gcmtmp", decryptedPath.CStr()); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    auto cleanUp = DeferRelease(&stagedPath, [](const auto* path) { (void)fs::Remove(*path); });

    fs::File output;

    // owner-only: it briefly holds plaintext that is already authenticated by this point, but stays private
    // regardless.
    if (auto err = output.Open(stagedPath, fs::File::Mode::WriteNew, 0600); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (!plaintext.IsEmpty()) {
        if (auto err = output.WriteBlock(plaintext); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    if (auto err = output.Close(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return fs::Rename(stagedPath, decryptedPath);
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

RetWithError<SharedPtr<crypto::PrivateKeyItf>> BlobDecryptor::GetKey()
{
    LockGuard lock(mKeyMutex);

    if (mKey) {
        return {mKey, ErrorEnum::eNone};
    }

    return FetchKey();
}

RetWithError<SharedPtr<crypto::PrivateKeyItf>> BlobDecryptor::FetchKey()
{
    auto certInfo = MakeUnique<CertInfo>(mAllocator);
    if (!certInfo) {
        return {nullptr, AOS_ERROR_WRAP(ErrorEnum::eNoMemory)};
    }

    if (auto err = mCertProvider->GetCert(mCertType, {}, {}, *certInfo); !err.IsNone()) {
        return {nullptr, AOS_ERROR_WRAP(err)};
    }

    auto [key, err] = mCertLoader->LoadPrivKeyByURL(certInfo->mKeyURL);
    if (!err.IsNone()) {
        return {nullptr, err};
    }

    mKey = key;

    return {mKey, ErrorEnum::eNone};
}

Error BlobDecryptor::StreamDecrypt(const crypto::PrivateKeyItf& key, const String& encryptedPath,
    crypto::GCMDecryptionOptions& gcmOptions, Array<uint8_t>& plaintext) const
{
    fs::File input;

    if (auto err = input.Open(encryptedPath, fs::File::Mode::Read); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = input.ReadBlock(gcmOptions.mIV); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
        return AOS_ERROR_WRAP(err);
    }

    if (gcmOptions.mIV.Size() != crypto::AESCipherItf::cGCMIVSize) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eInvalidArgument, "encrypted file too short to contain an IV"));
    }

    // fixed-size chunk buffer, reused for every chunk read off disk: this is what keeps ciphertext-side
    // memory bounded regardless of how large the encrypted file is.
    auto chunkBuf = mAllocator->Allocate(cFileChunkSize);
    if (!chunkBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freeChunk = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(chunkBuf); });

    Array<uint8_t> chunk(static_cast<uint8_t*>(chunkBuf), cFileChunkSize);

    FileChunkProvider chunkProvider(input, chunk);

    return key.StreamDecrypt(chunkProvider, crypto::DecryptionOptions {gcmOptions}, plaintext);
}

} // namespace aos::sm::imagemanager
