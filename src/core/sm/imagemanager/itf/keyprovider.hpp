/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_ITF_KEYPROVIDER_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_ITF_KEYPROVIDER_HPP_

#include <core/common/crypto/itf/privkey.hpp>
#include <core/common/tools/memory.hpp>
#include <core/common/tools/string.hpp>

namespace aos::sm::imagemanager {

/**
 * Provides a symmetric key that is held only by the local device and is never exchanged over the network or
 * exposed to this process, in any form: the key stays in its backing store (e.g. a PKCS11 token) and only
 * ever performs operations on request, never returning its own value. Used to decrypt content that was
 * encrypted for this specific device out of band, e.g. at provisioning time.
 *
 * The returned handle is a crypto::PrivateKeyItf (see pkcs11::AESPrivateKey): GetPublic/Sign are not
 * supported for it, only Decrypt with crypto::GCMDecryptionOptions.
 */
class SymmetricKeyProviderItf {
public:
    /**
     * Returns the device-local symmetric key.
     *
     * @return RetWithError<SharedPtr<crypto::PrivateKeyItf>>.
     */
    virtual RetWithError<SharedPtr<crypto::PrivateKeyItf>> GetKey() = 0;

    /**
     * Destructor.
     */
    virtual ~SymmetricKeyProviderItf() = default;
};

} // namespace aos::sm::imagemanager

#endif
