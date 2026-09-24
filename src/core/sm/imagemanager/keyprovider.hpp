/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_KEYPROVIDER_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_KEYPROVIDER_HPP_

#include <core/common/crypto/itf/certloader.hpp>
#include <core/common/crypto/itf/cryptohelper.hpp>
#include <core/common/iamclient/itf/certprovider.hpp>
#include <core/common/tools/thread.hpp>

#include "itf/keyprovider.hpp"

namespace aos::sm::imagemanager {

/**
 * Provides a symmetric key stored as an opaque data object on the same PKCS11 token as a certificate
 * managed by IAM's cert module system (see certModules config): the certificate itself is only used to
 * locate that token (library/token label/PIN, via its key URL), it is not used cryptographically here.
 * The key is read once, on first use, and cached. It is protected by the token's own access control
 * (PIN/login) the same way the certificate's private key is, and is never exchanged over the network:
 * both the key and the cert module are provisioned onto the device's token out of band.
 */
class KeyProvider : public SymmetricKeyProviderItf {
public:
    /**
     * Initializes object instance.
     *
     * @param allocator allocator to use for temporary objects.
     * @param certProvider provider of a certificate that identifies the token to read the key from.
     * @param certLoader loader used to resolve the token's session and read the key data object.
     * @param certType certificate type/module id to fetch from certProvider.
     * @return Error.
     */
    Error Init(AllocatorItf& allocator, iamclient::CertProviderItf& certProvider, crypto::CertLoaderItf& certLoader,
        const String& certType);

    /**
     * Returns the symmetric key, fetching and caching it on first call.
     *
     * @param[out] key result key bytes.
     * @return Error.
     */
    Error GetKey(Array<uint8_t>& key) override;

private:
    static constexpr auto cKeyDataLabel = "aos-layer-key";

    Error Fetch();

    AllocatorItf*                          mAllocator {};
    Mutex                                  mMutex;
    iamclient::CertProviderItf*            mCertProvider {};
    crypto::CertLoaderItf*                 mCertLoader {};
    StaticString<cCertTypeLen>             mCertType;
    StaticArray<uint8_t, crypto::cKeySize> mKey;
    bool                                   mFetched {};
};

} // namespace aos::sm::imagemanager

#endif
