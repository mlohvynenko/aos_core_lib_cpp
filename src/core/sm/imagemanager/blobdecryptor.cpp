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
// read into memory before decrypting it. Delivers exactly size bytes from the file's current position, so
// trailing data (the GCM tag) is left out. buffer is allocator-owned by the caller (BlobDecryptor, which has
// an AllocatorItf) rather than by this class itself: a chunk-sized (tens of KiB) buffer would blow the
// stack budget on a stack-constrained target if it lived in a local variable instead.
class FileChunkProvider : public crypto::ChunkProviderItf {
public:
    FileChunkProvider(fs::File& file, Array<uint8_t>& buffer, size_t size)
        : mFile(file)
        , mBuffer(buffer)
        , mRemaining(size)
    {
    }

    RetWithError<Array<uint8_t>> NextChunk() override
    {
        if (mRemaining == 0) {
            return {Array<uint8_t>(), ErrorEnum::eEOF};
        }

        Array<uint8_t> chunk(mBuffer.Get(), Min(mBuffer.MaxSize(), mRemaining));

        if (auto err = mFile.ReadBlock(chunk); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
            return {Array<uint8_t>(), AOS_ERROR_WRAP(err)};
        }

        if (chunk.IsEmpty()) {
            return {Array<uint8_t>(), AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, "encrypted file ended prematurely"))};
        }

        mRemaining -= chunk.Size();

        return {chunk, ErrorEnum::eNone};
    }

private:
    fs::File&       mFile;
    Array<uint8_t>& mBuffer;
    size_t          mRemaining;
};

// Adapts an open fs::File into a crypto::ChunkReceiverItf, so decrypted data is written out as the key
// releases it instead of being collected in memory first. buffer is allocator-owned by the caller, for the
// same reason as FileChunkProvider's.
class FileChunkReceiver : public crypto::ChunkReceiverItf {
public:
    FileChunkReceiver(fs::File& file, Array<uint8_t>& buffer)
        : mFile(file)
        , mBuffer(buffer)
    {
    }

    Array<uint8_t>& GetBuffer() override { return mBuffer; }

    Error OnChunk(const Array<uint8_t>& chunk) override
    {
        if (auto err = mFile.WriteBlock(chunk); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        return ErrorEnum::eNone;
    }

private:
    fs::File&       mFile;
    Array<uint8_t>& mBuffer;
};

} // namespace

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

constexpr uint8_t BlobDecryptor::cGCMPayloadCounterSuffix[];

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

    // CTR releases exactly as much plaintext per C_DecryptUpdate as it is given ciphertext, so a buffer the
    // size of one ciphertext chunk is always big enough for whatever a single decrypt step releases.
    auto plainBuf = mAllocator->Allocate(cDecryptChunkSize);
    if (!plainBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freePlain = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(plainBuf); });

    Array<uint8_t> plaintext(static_cast<uint8_t*>(plainBuf), cDecryptChunkSize);

    // staged to a deterministic sibling path and unconditionally removed, unless renamed into place on success
    // below: decryptedPath itself is never touched unless the whole operation succeeds.
    StaticString<cFilePathLen> stagedPath;

    if (auto err = stagedPath.Format("%s.gcmtmp", decryptedPath.CStr()); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    auto cleanUp = DeferRelease(&stagedPath, [](const auto* path) { (void)fs::Remove(*path); });

    fs::File output;

    // owner-only: it holds plaintext while decryption is still in progress.
    if (auto err = output.Open(stagedPath, fs::File::Mode::WriteNew, 0600); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    FileChunkReceiver chunkReceiver(output, plaintext);

    if (auto err = StreamDecrypt(*key, encryptedPath, encryptedSize, chunkReceiver); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
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
    size_t encryptedSize, crypto::ChunkReceiverItf& chunkReceiver) const
{
    fs::File input;

    if (auto err = input.Open(encryptedPath, fs::File::Mode::Read); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    StaticArray<uint8_t, crypto::AESCipherItf::cGCMIVSize> iv;

    if (auto err = input.ReadBlock(iv); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
        return AOS_ERROR_WRAP(err);
    }

    if (iv.Size() != crypto::AESCipherItf::cGCMIVSize) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eInvalidArgument, "encrypted file too short to contain an IV"));
    }

    // GCM encrypts the payload with plain AES-CTR, starting from counter block IV || 0x00000002 (J0 + 1;
    // J0 = IV || 0x00000001 itself is only used to encrypt the tag), so CTR decrypts it as is.
    crypto::CTRDecryptionOptions ctrOptions;

    if (auto err = ctrOptions.mCounter.Assign(iv); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    for (const uint8_t byte : cGCMPayloadCounterSuffix) {
        if (auto err = ctrOptions.mCounter.PushBack(byte); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    // fixed-size chunk buffer, reused for every chunk read off disk: this is what keeps ciphertext-side
    // memory bounded regardless of how large the encrypted file is. Deliberately cDecryptChunkSize, not the
    // larger generic cFileChunkSize: some PKCS11 modules (TEE-backed ones especially) reject a single
    // C_DecryptUpdate call above a much smaller size with CKR_DEVICE_MEMORY.
    auto chunkBuf = mAllocator->Allocate(cDecryptChunkSize);
    if (!chunkBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freeChunk = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(chunkBuf); });

    Array<uint8_t> chunk(static_cast<uint8_t*>(chunkBuf), cDecryptChunkSize);

    // the trailing tag is not passed on: CTR doesn't verify it.
    FileChunkProvider chunkProvider(
        input, chunk, encryptedSize - crypto::AESCipherItf::cGCMIVSize - crypto::AESCipherItf::cGCMTagSize);

    return key.StreamDecrypt(chunkProvider, crypto::DecryptionOptions {ctrOptions}, chunkReceiver);
}

} // namespace aos::sm::imagemanager
