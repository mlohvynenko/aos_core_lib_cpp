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

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error BlobDecryptor::Init(AllocatorItf& allocator, SymmetricKeyProviderItf& keyProvider)
{
    mAllocator   = &allocator;
    mKeyProvider = &keyProvider;

    return ErrorEnum::eNone;
}

Error BlobDecryptor::Decrypt(const String& encryptedPath, const String& decryptedPath)
{
    LOG_DBG() << "Decrypting blob" << Log::Field("encryptedPath", encryptedPath)
              << Log::Field("decryptedPath", decryptedPath);

    auto [key, keyErr] = mKeyProvider->GetKey();
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

    fs::File input;

    if (auto err = input.Open(encryptedPath, fs::File::Mode::Read); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    crypto::GCMDecryptionOptions gcmOptions;

    if (auto err = input.ReadBlock(gcmOptions.mIV); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
        return AOS_ERROR_WRAP(err);
    }

    if (gcmOptions.mIV.Size() != crypto::AESCipherItf::cGCMIVSize) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eInvalidArgument, "encrypted file too short to contain an IV"));
    }

    // rest of the file: ciphertext followed by the 16-byte authentication tag, exactly as
    // crypto::PrivateKeyItf::Decrypt/GCMDecryptionOptions expects it. Buffered whole: the underlying PKCS11
    // C_Decrypt call is single-shot, there is no streaming variant here.
    auto cipherSize = encryptedSize - crypto::AESCipherItf::cGCMIVSize;

    auto cipherBuf = mAllocator->Allocate(cipherSize);
    if (!cipherBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freeCipher = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(cipherBuf); });

    Array<uint8_t> cipher(static_cast<uint8_t*>(cipherBuf), cipherSize);

    if (auto err = input.ReadBlock(cipher); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
        return AOS_ERROR_WRAP(err);
    }

    if (cipher.Size() != cipherSize) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eFailed, "encrypted file changed size during decryption"));
    }

    // plaintext can't be larger than the ciphertext it came from (GCM never expands data): this buffer is
    // always big enough, however much of it Decrypt actually fills in.
    auto plainBuf = mAllocator->Allocate(cipherSize);
    if (!plainBuf) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    auto freePlain = DeferRelease(mAllocator, [&](AllocatorItf* allocator) { allocator->Free(plainBuf); });

    Array<uint8_t> plaintext(static_cast<uint8_t*>(plainBuf), cipherSize);

    if (auto err = key->Decrypt(cipher, crypto::DecryptionOptions {gcmOptions}, plaintext); !err.IsNone()) {
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

} // namespace aos::sm::imagemanager
