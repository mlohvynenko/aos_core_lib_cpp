/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_

#include "itf/blobdecryptor.hpp"
#include "itf/keyprovider.hpp"

namespace aos::sm::imagemanager {

/**
 * Decrypts blobs using a device-local symmetric key (see SymmetricKeyProviderItf): the key never leaves its
 * backing store (e.g. a PKCS11 token) and the actual AES-GCM decrypt call happens through it
 * (crypto::PrivateKeyItf::Decrypt with crypto::GCMDecryptionOptions); this class handles the file I/O
 * around that single in-memory call (splitting off the IV, staging output, renaming into place once the
 * authentication tag checks out). Algorithm is fixed to AES-256-GCM: authenticated (a wrong key or a
 * modified blob is detected, not decrypted to garbage) and without padding. The IV (nonce) travels with the
 * data (first 12 bytes of the encrypted file) rather than being derived or exchanged separately, since only
 * the key itself needs to stay off the network. Encrypted file layout: IV (12 bytes) | ciphertext |
 * authentication tag (16 bytes).
 */
class BlobDecryptor : public BlobDecryptorItf {
public:
    /**
     * Initializes object instance.
     *
     * @param allocator allocator used to buffer ciphertext/plaintext for the single in-memory Decrypt call.
     * @param keyProvider provider of the device-local symmetric key.
     * @return Error.
     */
    Error Init(AllocatorItf& allocator, SymmetricKeyProviderItf& keyProvider);

    /**
     * Decrypts a blob file using the device-local symmetric key.
     *
     * @param encryptedPath path to the encrypted file (IV, ciphertext, authentication tag).
     * @param decryptedPath path where the decrypted file will be written.
     * @return Error.
     */
    Error Decrypt(const String& encryptedPath, const String& decryptedPath) override;

private:
    AllocatorItf*            mAllocator {};
    SymmetricKeyProviderItf* mKeyProvider {};
};

} // namespace aos::sm::imagemanager

#endif
