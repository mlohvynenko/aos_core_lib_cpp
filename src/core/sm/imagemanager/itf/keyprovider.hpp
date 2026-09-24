/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_CORE_SM_IMAGEMANAGER_ITF_KEYPROVIDER_HPP_
#define AOS_CORE_SM_IMAGEMANAGER_ITF_KEYPROVIDER_HPP_

#include <core/common/tools/memory.hpp>
#include <core/common/tools/string.hpp>

namespace aos::sm::imagemanager {

/**
 * Provides a symmetric key that is held only by the local device and is never exchanged over the network,
 * in any form (raw or wrapped). Used to decrypt content that was encrypted for this specific device
 * out of band, e.g. at provisioning time.
 */
class SymmetricKeyProviderItf {
public:
    /**
     * Returns the device-local symmetric key.
     *
     * @param[out] key result key bytes.
     * @return Error.
     */
    virtual Error GetKey(Array<uint8_t>& key) = 0;

    /**
     * Destructor.
     */
    virtual ~SymmetricKeyProviderItf() = default;
};

} // namespace aos::sm::imagemanager

#endif
