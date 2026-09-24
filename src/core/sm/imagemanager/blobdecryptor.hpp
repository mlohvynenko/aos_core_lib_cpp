/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_

#include <core/common/crypto/itf/aes.hpp>
#include <core/common/crypto/itf/cryptohelper.hpp>

#include "itf/blobdecryptor.hpp"
#include "itf/keyprovider.hpp"

namespace aos::sm::imagemanager {

/**
 * Decrypts blobs using a device-local symmetric key (see SymmetricKeyProviderItf). Algorithm is
 * fixed to AES-256-GCM: authenticated (a wrong key or a modified blob is detected, not decrypted to garbage)
 * and without padding. The IV (nonce) travels with the data (first 12 bytes of the encrypted file) rather
 * than being derived or exchanged separately, since only the key itself needs to stay off the network.
 * Encrypted file layout: IV (12 bytes) | ciphertext | authentication tag (16 bytes).
 */
class BlobDecryptor : public BlobDecryptorItf {
public:
    /**
     * Initializes object instance.
     *
     * @param allocator allocator to use for temporary objects.
     * @param cryptoHelper crypto helper used to perform the actual file decryption.
     * @param keyProvider provider of the device-local symmetric key.
     * @return Error.
     */
    Error Init(AllocatorItf& allocator, crypto::CryptoHelperItf& cryptoHelper, SymmetricKeyProviderItf& keyProvider);

    /**
     * Decrypts a blob file using the device-local symmetric key.
     *
     * @param encryptedPath path to the encrypted file (IV, ciphertext, authentication tag).
     * @param decryptedPath path where the decrypted file will be written.
     * @return Error.
     */
    Error Decrypt(const String& encryptedPath, const String& decryptedPath) override;

private:
    static constexpr auto cLayerBlockAlg = "AES256/GCM";

    Error SplitIV(const String& encryptedPath, const String& ciphertextPath, Array<uint8_t>& iv) const;

    AllocatorItf*            mAllocator {};
    crypto::CryptoHelperItf* mCryptoHelper {};
    SymmetricKeyProviderItf* mKeyProvider {};
};

} // namespace aos::sm::imagemanager

#endif
