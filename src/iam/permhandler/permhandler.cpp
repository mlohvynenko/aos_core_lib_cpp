/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/iam/permhandler.hpp"
#include "log.hpp"

namespace aos {
namespace iam {
namespace permhandler {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

RetWithError<StaticString<uuid::cUUIDStrLen>> PermHandler::RegisterInstance(
    const InstanceIdent& instanceIdent, const Array<FunctionalServicePermissions>& instancePermissions)
{
    LockGuard lk(mMutex);

    const auto err = GetSecretForInstance(instanceIdent);
    if (err.mError.IsNone()) {
        LOG_DBG() << "Instance " << instanceIdent << " has been already registered";

        return err;
    }

    const auto secretUUID = GenerateSecret();

    return {secretUUID, AddSecret(secretUUID, instanceIdent, instancePermissions)};
}

Error PermHandler::UnregisterInstance(const InstanceIdent& instanceIdent)
{
    LockGuard lk(mMutex);

    auto err
        = mInstancesPerms.Find([&instanceIdent](const auto& item) { return item.mInstanceIdent == instanceIdent; });
    if (!err.mError.IsNone()) {
        LOG_WRN() << "Instance " << instanceIdent << " not registered";

        return err.mError;
    }

    return mInstancesPerms.Remove(err.mValue).mError;
}

Error PermHandler::GetPermissions(InstanceIdent& instanceIdent, Array<PermKeyValue>& servicePermissions,
    const String& secretUUID, const String& funcServerID)
{
    LockGuard lk(mMutex);

    auto err = mInstancesPerms.Find([&secretUUID](const auto& item) { return secretUUID == item.mSecretUUID; });
    if (!err.mError.IsNone()) {
        LOG_ERR() << "secret not found";

        return err.mError;
    }

    instanceIdent = err.mValue->mInstanceIdent;

    for (const auto& it : err.mValue->mFuncServicePerms) {
        if (it.mName == funcServerID) {
            if (it.mPermissions.Size() > servicePermissions.MaxSize()) {
                return ErrorEnum::eNoMemory;
            }

            servicePermissions = it.mPermissions;

            return ErrorEnum::eNone;
        }
    }

    LOG_ERR() << "permissions for functional server " << funcServerID << " not found";

    return ErrorEnum::eNotFound;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

Error PermHandler::AddSecret(const String& secretUUID, const InstanceIdent& instanceIdent,
    const Array<FunctionalServicePermissions>& instancePermissions)
{
    if (mInstancesPerms.Size() == mInstancesPerms.MaxSize()) {
        LOG_ERR() << "Max number of secrets stored has been reached";

        return ErrorEnum::eNoMemory;
    }

    InstancePermissions newEntrie {secretUUID, instanceIdent, instancePermissions};

    return mInstancesPerms.PushBack(Move(newEntrie));
}

StaticString<uuid::cUUIDStrLen> PermHandler::GenerateSecret()
{
    const auto uuid = uuid::CreateUUID();

    return uuid::UUIDToString(uuid);
}

RetWithError<StaticString<uuid::cUUIDStrLen>> PermHandler::GetSecretForInstance(const InstanceIdent& instanceIdent)
{
    const auto err
        = mInstancesPerms.Find([&instanceIdent](const auto& elem) { return instanceIdent == elem.mInstanceIdent; });

    if (!err.mError.IsNone()) {
        return {"", ErrorEnum::eNotFound};
    }

    return err.mValue->mSecretUUID;
}

} // namespace permhandler
} // namespace iam
} // namespace aos
