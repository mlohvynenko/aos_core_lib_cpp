/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_BLOBDECRYPTOR_HPP_

#include <core/common/crypto/itf/certloader.hpp>
#include <core/common/iamclient/itf/certprovider.hpp>
#include <core/common/tools/thread.hpp>

#include "itf/blobdecryptor.hpp"

namespace aos::sm::imagemanager {

/**
 * Decrypts blobs using a device-local symmetric key that is never exchanged over the network or exposed to
 * this process, in any form: the key is stored as a CKO_SECRET_KEY object on the same PKCS11 token as a
 * certificate managed by IAM's cert module system (see certModules config), that cert module is dedicated
 * to locating the key (its registered key URL's token/library/PIN *and* id/label directly identify the
 * CKO_SECRET_KEY object), it is not used cryptographically itself. The key handle is resolved once, on
 * first use, and cached; the key's own value is never read - the actual AES-GCM decrypt call happens
 * through it (crypto::PrivateKeyItf::Decrypt with crypto::GCMDecryptionOptions), this class handles the
 * file I/O around that single in-memory call (splitting off the IV, staging output, renaming into place
 * once the authentication tag checks out). It is protected by the token's own access control (PIN/login)
 * the same way a certificate's private key is: both the key and the cert module are provisioned onto the
 * device's token out of band. Algorithm is fixed to AES-256-GCM: authenticated (a wrong key or a modified
 * blob is detected, not decrypted to garbage) and without padding. The IV (nonce) travels with the data
 * (first 12 bytes of the encrypted file) rather than being derived or exchanged separately, since only the
 * key itself needs to stay off the network. Encrypted file layout: IV (12 bytes) | ciphertext |
 * authentication tag (16 bytes).
 *
 * Decrypt reads the ciphertext off disk in chunks via key->StreamDecrypt, rather than buffering the whole
 * file, so the token/key this class is Init'd with must support that (pkcs11::AESPrivateKey does; there is
 * no whole-buffer fallback here). The *plaintext* buffer is still sized for the whole file regardless: most
 * PKCS11 modules only release AEAD-decrypted data once the authentication tag has been verified, all at
 * once, so chunking only ever reduces the ciphertext-side memory footprint, not the plaintext side.
 */
class BlobDecryptor : public BlobDecryptorItf {
public:
    /**
     * Initializes object instance.
     *
     * @param allocator allocator used for the plaintext buffer and the ciphertext chunk buffer.
     * @param certProvider provider of a certificate that identifies the token/id/label to read the key from.
     * @param certLoader loader used to resolve the token's session and read the secret key object.
     * @param certType certificate type/module id to fetch from certProvider.
     * @return Error.
     */
    Error Init(AllocatorItf& allocator, iamclient::CertProviderItf& certProvider, crypto::CertLoaderItf& certLoader,
        const String& certType);

    /**
     * Decrypts a blob file using the device-local symmetric key.
     *
     * @param encryptedPath path to the encrypted file (IV, ciphertext, authentication tag).
     * @param decryptedPath path where the decrypted file will be written.
     * @return Error.
     */
    Error Decrypt(const String& encryptedPath, const String& decryptedPath) override;

private:
    // Returns the symmetric key, resolving and caching it on first call.
    RetWithError<SharedPtr<crypto::PrivateKeyItf>> GetKey();
    RetWithError<SharedPtr<crypto::PrivateKeyItf>> FetchKey();

    // Reads the encrypted file's IV, then decrypts the rest via key.StreamDecrypt, so the ciphertext
    // never needs to be fully buffered in memory (see crypto::PrivateKeyItf::StreamDecrypt). Returns
    // whatever error key.StreamDecrypt returns, including ErrorEnum::eNotSupported if the key/token
    // doesn't support it - there is no whole-buffer fallback.
    Error StreamDecrypt(const crypto::PrivateKeyItf& key, const String& encryptedPath,
        crypto::GCMDecryptionOptions& gcmOptions, Array<uint8_t>& plaintext) const;

    AllocatorItf*                    mAllocator {};
    Mutex                            mKeyMutex;
    iamclient::CertProviderItf*      mCertProvider {};
    crypto::CertLoaderItf*           mCertLoader {};
    StaticString<cCertTypeLen>       mCertType;
    SharedPtr<crypto::PrivateKeyItf> mKey;
};

} // namespace aos::sm::imagemanager

#endif
