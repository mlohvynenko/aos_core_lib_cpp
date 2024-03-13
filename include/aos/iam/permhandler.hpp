/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_PERMHANDLER_HPP_
#define AOS_PERMHANDLER_HPP_

#include "aos/common/tools/thread.hpp"
#include "aos/common/tools/utils.hpp"
#include "aos/common/tools/uuid.hpp"
#include "aos/common/types.hpp"
#include "aos/iam/certmodules/certmodule.hpp"
#include "aos/iam/config.hpp"

namespace aos {
namespace iam {
namespace permhandler {

/** @addtogroup iam Identification and Access Manager
 *  @{
 */

/**
 * Maximum length of permhandler permission key string.
 */
constexpr auto cPermKeyStringLen = AOS_CONFIG_PERMHANDLER_PERM_KEY_STRING_LEN;

/**
 * Maximum length of permhandler permission value string.
 */
constexpr auto cPermValueStringLien = AOS_CONFIG_PERMHANDLER_PERM_VALUE_STRING_LEN;

/**
 * Maximum number of permhandler service permissions.
 */
constexpr auto cServicePermissionMaxCount = AOS_CONFIG_PERMHANDLER_SERVICE_PERMS_MAX_COUNT;

/**
 * Permission key value.
 */
struct PermKeyValue {
    StaticString<cPermKeyStringLen>    mKey;
    StaticString<cPermValueStringLien> mValue;

    /**
     * Compares permission key value.
     *
     * @param rhs object to compare.
     * @return bool.
     */
    bool operator==(const PermKeyValue& rhs) { return (mKey == rhs.mKey) && (mValue == rhs.mValue); }
};

/**
 * Functional service permissions.
 */
struct FunctionalServicePermissions {
    StaticString<cSystemIDLen>                            mName;
    StaticArray<PermKeyValue, cServicePermissionMaxCount> mPermissions;
};

/**
 * Instance permissions.
 */
struct InstancePermissions {
    StaticString<uuid::cUUIDStrLen>                            mSecretUUID;
    InstanceIdent                                              mInstanceIdent;
    StaticArray<FunctionalServicePermissions, cMaxNumServices> mFuncServicePerms;
};

/**
 * Permission handler.
 */
class PermHandler {
public:
    /**
     * And new service instance and its permissions into cache
     *
     * @param instanceIdent instance identification.
     * @param instancePermissions instance permissions.
     * @returns RetWithError<StaticString<uuid::cUUIDStrLen>>.
     */
    RetWithError<StaticString<uuid::cUUIDStrLen>> RegisterInstance(
        const InstanceIdent& instanceIdent, const Array<FunctionalServicePermissions>& instancePermissions);

    /**
     * Unregister instance deletes service instance with permissions from cache.
     *
     * @param instanceIdent instance identification.
     * @returns Error.
     */
    Error UnregisterInstance(const InstanceIdent& instanceIdent);

    /**
     * Get permissions returns instance and permissions by secret UUID and functional server ID.
     *
     * @param[out] instanceIdent result instance ident.
     * @param[out] servicePermissions result service permission.
     * @param secretUUID secret UUID.
     * @param funcServerID functional server ID.
     * @returns Error.
     */
    Error GetPermissions(InstanceIdent& instanceIdent, Array<PermKeyValue>& servicePermissions,
        const String& secretUUID, const String& funcServerID);

private:
    Error                           AddSecret(const String& secretUUID, const InstanceIdent& instanceIdent,
                                  const Array<FunctionalServicePermissions>& instancePermissions);
    StaticString<uuid::cUUIDStrLen> GenerateSecret();
    RetWithError<StaticString<uuid::cUUIDStrLen>> GetSecretForInstance(const InstanceIdent& instanceIdent);

    Mutex                                              mMutex;
    StaticArray<InstancePermissions, cMaxNumInstances> mInstancesPerms;
};

/** @}*/

} // namespace permhandler
} // namespace iam
} // namespace aos

#endif
