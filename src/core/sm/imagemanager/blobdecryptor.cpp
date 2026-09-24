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

Error BlobDecryptor::Init(
    AllocatorItf& allocator, crypto::CryptoHelperItf& cryptoHelper, SymmetricKeyProviderItf& keyProvider)
{
    mAllocator    = &allocator;
    mCryptoHelper = &cryptoHelper;
    mKeyProvider  = &keyProvider;

    return ErrorEnum::eNone;
}

Error BlobDecryptor::Decrypt(const String& encryptedPath, const String& decryptedPath)
{
    LOG_DBG() << "Decrypting blob" << Log::Field("encryptedPath", encryptedPath)
              << Log::Field("decryptedPath", decryptedPath);

    crypto::DecryptInfo decryptInfo;

    if (auto err = decryptInfo.mBlockAlg.Assign(cLayerBlockAlg); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    StaticString<cFilePathLen> ciphertextPath;

    auto cleanUp = DeferRelease(&ciphertextPath, [](const auto* path) { (void)fs::Remove(*path); });

    if (auto err = ciphertextPath.Format("%s.ct", encryptedPath.CStr()); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    StaticArray<uint8_t, crypto::AESCipherItf::cGCMIVSize> iv;

    if (auto err = SplitIV(encryptedPath, ciphertextPath, iv); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = decryptInfo.mBlockIV.Assign(iv); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mKeyProvider->GetKey(decryptInfo.mBlockKey); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mCryptoHelper->Decrypt(ciphertextPath, decryptedPath, decryptInfo); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

Error BlobDecryptor::SplitIV(const String& encryptedPath, const String& ciphertextPath, Array<uint8_t>& iv) const
{
    fs::File input;
    fs::File output;

    if (auto err = input.Open(encryptedPath, fs::File::Mode::Read); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = input.ReadBlock(iv); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
        return AOS_ERROR_WRAP(err);
    }

    if (iv.Size() != crypto::AESCipherItf::cGCMIVSize) {
        return AOS_ERROR_WRAP(Error(ErrorEnum::eInvalidArgument, "encrypted file too short to contain an IV"));
    }

    if (auto err = output.Open(ciphertextPath, fs::File::Mode::Write); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    auto block = MakeUnique<StaticArray<uint8_t, cFileChunkSize>>(mAllocator);
    if (!block) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    while (true) {
        if (auto err = input.ReadBlock(*block); !err.IsNone() && !err.Is(ErrorEnum::eEOF)) {
            return AOS_ERROR_WRAP(err);
        }

        if (block->IsEmpty()) {
            break;
        }

        if (auto err = output.WriteBlock(*block); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    if (auto err = input.Close(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return output.Close();
}

} // namespace aos::sm::imagemanager
