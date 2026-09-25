/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_KEYPROVIDER_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_KEYPROVIDER_HPP_

#include <core/common/crypto/itf/certloader.hpp>
#include <core/common/iamclient/itf/certprovider.hpp>
#include <core/common/tools/thread.hpp>

#include "itf/keyprovider.hpp"

namespace aos::sm::imagemanager {

/**
 * Provides a symmetric key stored as a CKO_SECRET_KEY object on the same PKCS11 token as a certificate
 * managed by IAM's cert module system (see certModules config): that cert module is dedicated to locating
 * the key (its registered key URL's token/library/PIN *and* id/label directly identify the CKO_SECRET_KEY
 * object), it is not used cryptographically here. The key handle is resolved once, on first use, and
 * cached; the key's own value is never read. It is protected by the token's own access control (PIN/login)
 * the same way a certificate's private key is, and is never exchanged over the network: both the key and
 * the cert module are provisioned onto the device's token out of band.
 */
class KeyProvider : public SymmetricKeyProviderItf {
public:
    /**
     * Initializes object instance.
     *
     * @param allocator allocator to use for temporary objects.
     * @param certProvider provider of a certificate that identifies the token/id/label to read the key from.
     * @param certLoader loader used to resolve the token's session and read the secret key object.
     * @param certType certificate type/module id to fetch from certProvider.
     * @return Error.
     */
    Error Init(AllocatorItf& allocator, iamclient::CertProviderItf& certProvider, crypto::CertLoaderItf& certLoader,
        const String& certType);

    /**
     * Returns the symmetric key, resolving and caching it on first call.
     *
     * @return RetWithError<SharedPtr<crypto::PrivateKeyItf>>.
     */
    RetWithError<SharedPtr<crypto::PrivateKeyItf>> GetKey() override;

private:
    RetWithError<SharedPtr<crypto::PrivateKeyItf>> Fetch();

    AllocatorItf*                    mAllocator {};
    Mutex                            mMutex;
    iamclient::CertProviderItf*      mCertProvider {};
    crypto::CertLoaderItf*           mCertLoader {};
    StaticString<cCertTypeLen>       mCertType;
    SharedPtr<crypto::PrivateKeyItf> mKey;
};

} // namespace aos::sm::imagemanager

#endif
