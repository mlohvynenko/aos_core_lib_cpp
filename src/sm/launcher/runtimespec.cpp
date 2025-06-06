/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "runtimespec.hpp"

namespace aos::sm::launcher {

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

namespace {

RetWithError<StaticString<cEnvVarNameLen>> GetEnvVarName(const String& envVar)
{
    StaticString<cEnvVarLen> tmpStr = envVar;

    if (auto result = tmpStr.FindSubstr(0, "="); result.mError.IsNone()) {
        if (auto err = tmpStr.Resize(result.mValue); !err.IsNone()) {
            return {0, AOS_ERROR_WRAP(err)};
        }
    }

    tmpStr.Trim(" ");

    return StaticString<cEnvVarNameLen>(tmpStr);
}

} // namespace

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error AddMount(const Mount& mount, oci::RuntimeSpec& runtimeSpec)
{
    auto existMount = runtimeSpec.mMounts.FindIf(
        [&destination = mount.mDestination](const Mount& mount) { return mount.mDestination == destination; });
    if (existMount == runtimeSpec.mMounts.end()) {
        if (auto err = runtimeSpec.mMounts.PushBack(mount); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        existMount = &runtimeSpec.mMounts[runtimeSpec.mMounts.Size() - 1];
    } else {
        *existMount = mount;
    }

    if (existMount->mType.IsEmpty()) {
        existMount->mType = "bind";
    }

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error AddNamespace(const oci::LinuxNamespace& ns, oci::RuntimeSpec& runtimeSpec)
{
    auto existNS = runtimeSpec.mLinux->mNamespaces.FindIf(
        [&nsType = ns.mType](const oci::LinuxNamespace& ns) { return ns.mType == nsType; });
    if (existNS == runtimeSpec.mLinux->mNamespaces.end()) {
        if (auto err = runtimeSpec.mLinux->mNamespaces.PushBack(ns); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    } else {
        *existNS = ns;
    }

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error AddEnvVars(const Array<StaticString<cEnvVarLen>>& envVars, oci::RuntimeSpec& runtimeSpec)
{
    for (const auto& newEnvVar : envVars) {
        StaticString<cEnvVarNameLen> newEnvVarName;
        Error                        err;

        Tie(newEnvVarName, err) = GetEnvVarName(newEnvVar);
        if (!err.IsNone()) {
            return err;
        }

        auto updated = false;

        for (auto& existingEnvVar : runtimeSpec.mProcess->mEnv) {
            StaticString<cEnvVarNameLen> existingEnvVarName;

            Tie(existingEnvVarName, err) = GetEnvVarName(existingEnvVar);
            if (!err.IsNone()) {
                return err;
            }

            if (newEnvVarName == existingEnvVarName) {
                existingEnvVar = newEnvVar;
                updated        = true;

                break;
            }
        }

        if (!updated) {
            if (err = runtimeSpec.mProcess->mEnv.PushBack(newEnvVar); !err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }
        }
    }

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error SetCPULimit(int64_t quota, uint64_t period, oci::RuntimeSpec& runtimeSpec)
{
    if (!runtimeSpec.mLinux->mResources->mCPU.HasValue()) {
        runtimeSpec.mLinux->mResources->mCPU.EmplaceValue();
    }

    runtimeSpec.mLinux->mResources->mCPU->mPeriod = period;
    runtimeSpec.mLinux->mResources->mCPU->mQuota  = quota;

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error SetRAMLimit(int64_t limit, oci::RuntimeSpec& runtimeSpec)
{
    if (!runtimeSpec.mLinux->mResources->mMemory.HasValue()) {
        runtimeSpec.mLinux->mResources->mMemory.EmplaceValue();
    }

    runtimeSpec.mLinux->mResources->mMemory->mLimit = limit;

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error SetPIDLimit(int64_t limit, oci::RuntimeSpec& runtimeSpec)
{
    if (!runtimeSpec.mLinux->mResources->mPids.HasValue()) {
        runtimeSpec.mLinux->mResources->mPids.EmplaceValue();
    }

    runtimeSpec.mLinux->mResources->mPids->mLimit = limit;

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error AddRLimit(const oci::POSIXRlimit& rlimit, oci::RuntimeSpec& runtimeSpec)
{
    auto existRlimit = runtimeSpec.mProcess->mRlimits.FindIf(
        [&type = rlimit.mType](const oci::POSIXRlimit& rlimit) { return rlimit.mType == type; });
    if (existRlimit == runtimeSpec.mProcess->mRlimits.end()) {
        if (auto err = runtimeSpec.mProcess->mRlimits.PushBack(rlimit); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    } else {
        *existRlimit = rlimit;
    }

    return ErrorEnum::eNone;
}

// cppcheck-suppress constParameter
Error AddAdditionalGID(uint32_t gid, oci::RuntimeSpec& runtimeSpec)
{
    if (runtimeSpec.mProcess->mUser.mAdditionalGIDs.Find(gid) != runtimeSpec.mProcess->mUser.mAdditionalGIDs.end()) {
        return ErrorEnum::eNone;
    }

    if (auto err = runtimeSpec.mProcess->mUser.mAdditionalGIDs.PushBack(gid); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error AddDevice(const oci::LinuxDevice& device, const StaticString<cPermissionsLen>& permissions,
    oci::RuntimeSpec& runtimeSpec) // cppcheck-suppress constParameter
{
    auto existDevice = runtimeSpec.mLinux->mDevices.FindIf(
        [&path = device.mPath](const oci::LinuxDevice& device) { return device.mPath == path; });
    if (existDevice == runtimeSpec.mLinux->mDevices.end()) {
        if (auto err = runtimeSpec.mLinux->mDevices.PushBack(device); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    } else {
        *existDevice = device;
    }

    auto existCgroup
        = runtimeSpec.mLinux->mResources->mDevices.FindIf([&device](const oci::LinuxDeviceCgroup& cgroupDevice) {
              return cgroupDevice.mType == device.mType && cgroupDevice.mMajor == device.mMajor
                  && cgroupDevice.mMinor == device.mMinor;
          });
    if (existCgroup == runtimeSpec.mLinux->mResources->mDevices.end()) {
        if (auto err = runtimeSpec.mLinux->mResources->mDevices.EmplaceBack(
                device.mType, permissions, true, device.mMajor, device.mMinor);
            !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    } else {
        existCgroup->mAllow  = true;
        existCgroup->mAccess = permissions;
    }

    return ErrorEnum::eNone;
}

} // namespace aos::sm::launcher
