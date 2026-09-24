/*
 * Copyright (C) 2026 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core/common/tools/error.hpp>

#include "keyprovider.hpp"

namespace aos::sm::imagemanager {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error KeyProvider::Init(AllocatorItf& allocator, iamclient::CertProviderItf& certProvider,
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

Error KeyProvider::GetKey(Array<uint8_t>& key)
{
    LockGuard lock(mMutex);

    if (!mFetched) {
        if (auto err = Fetch(); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        mFetched = true;
    }

    return key.Assign(mKey);
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

Error KeyProvider::Fetch()
{
    auto certInfo = MakeUnique<CertInfo>(mAllocator);
    if (!certInfo) {
        return AOS_ERROR_WRAP(ErrorEnum::eNoMemory);
    }

    if (auto err = mCertProvider->GetCert(mCertType, {}, {}, *certInfo); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return mCertLoader->LoadDataByURL(certInfo->mKeyURL, cKeyDataLabel, mKey);
}

} // namespace aos::sm::imagemanager
