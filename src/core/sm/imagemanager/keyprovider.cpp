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

RetWithError<SharedPtr<crypto::PrivateKeyItf>> KeyProvider::GetKey()
{
    LockGuard lock(mMutex);

    if (mKey) {
        return {mKey, ErrorEnum::eNone};
    }

    return Fetch();
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

RetWithError<SharedPtr<crypto::PrivateKeyItf>> KeyProvider::Fetch()
{
    auto certInfo = MakeUnique<CertInfo>(mAllocator);
    if (!certInfo) {
        return {nullptr, AOS_ERROR_WRAP(ErrorEnum::eNoMemory)};
    }

    if (auto err = mCertProvider->GetCert(mCertType, {}, {}, *certInfo); !err.IsNone()) {
        return {nullptr, AOS_ERROR_WRAP(err)};
    }

    auto [key, err] = mCertLoader->LoadPrivKeyByURL(certInfo->mKeyURL);
    if (!err.IsNone()) {
        return {nullptr, err};
    }

    mKey = key;

    return {mKey, ErrorEnum::eNone};
}

} // namespace aos::sm::imagemanager
