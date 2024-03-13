/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/common/tools/buffer.hpp"
#include "mocks/subjectsobservermock.hpp"
#include <gtest/gtest.h>

#include "aos/iam/permhandler.hpp"
#include <iostream>

using namespace aos;
using namespace aos::iam::permhandler;
using namespace testing;

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class PermHandlerTest : public Test {
protected:
    void SetUp() override
    {
        Log::SetCallback([](LogModule module, LogLevel level, const String& message) {
            static std::mutex sLogMutex;

            std::lock_guard<std::mutex> lock(sLogMutex);

            std::cout << level.ToString().CStr() << " | " << module.ToString().CStr() << " | " << message.CStr()
                      << std::endl;
        });
    }

    void TearDown() override { }

    PermHandler mPermHandler;
};

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(PermHandlerTest, RegisterInstanceSucceeds)
{
    InstanceIdent                                instanceIdent;
    StaticArray<FunctionalServicePermissions, 1> perms;
    const auto                                   err = mPermHandler.RegisterInstance(instanceIdent, perms);

    EXPECT_TRUE(err.mError.IsNone()) << err.mError.Message();

    ASSERT_FALSE(err.mValue.IsEmpty());
}

TEST_F(PermHandlerTest, RegisterInstanceReturnsSecretFromCache)
{
    InstanceIdent                                instanceIdent;
    StaticArray<FunctionalServicePermissions, 1> perms;

    const auto lhsErr = mPermHandler.RegisterInstance(instanceIdent, perms);

    EXPECT_TRUE(lhsErr.mError.IsNone()) << lhsErr.mError.Message();
    ASSERT_FALSE(lhsErr.mValue.IsEmpty());

    const auto rhsErr = mPermHandler.RegisterInstance(instanceIdent, perms);
    EXPECT_EQ(lhsErr.mError, rhsErr.mError);
    EXPECT_EQ(lhsErr.mValue, rhsErr.mValue);
}

TEST_F(PermHandlerTest, UnregisterInstance)
{
    InstanceIdent instanceIdent;
    instanceIdent.mServiceID = "test-service-id";

    StaticArray<FunctionalServicePermissions, 1> perms;

    auto err = mPermHandler.UnregisterInstance(instanceIdent);
    EXPECT_FALSE(err.IsNone()) << err.Message();

    const auto errWithValue = mPermHandler.RegisterInstance(instanceIdent, perms);
    EXPECT_TRUE(errWithValue.mError.IsNone()) << errWithValue.mError.Message();

    err = mPermHandler.UnregisterInstance(instanceIdent);
    EXPECT_TRUE(err.IsNone()) << err.Message();

    err = mPermHandler.UnregisterInstance(instanceIdent);
    EXPECT_TRUE(err.Is(ErrorEnum::eNotFound)) << err.Message();
}

TEST_F(PermHandlerTest, TestInstancePermissions)
{
    const InstanceIdent instanceIdent1 {"serviceID1", "subjectID1", 1};
    const InstanceIdent instanceIdent2 {"serviceID2", "subjectID2", 2};
    InstanceIdent       instance;

    FunctionalServicePermissions visServicePermissions;
    visServicePermissions.mName = "vis";
    visServicePermissions.mPermissions.PushBack({"*", "rw"});
    visServicePermissions.mPermissions.PushBack({"test", "r"});

    FunctionalServicePermissions systemCoreServicePermissions;
    systemCoreServicePermissions.mName = "systemCore";
    systemCoreServicePermissions.mPermissions.PushBack({"test1.*", "rw"});
    systemCoreServicePermissions.mPermissions.PushBack({"test2", "r"});

    StaticArray<FunctionalServicePermissions, 2> funcServerPermissions;
    funcServerPermissions.PushBack(visServicePermissions);
    funcServerPermissions.PushBack(systemCoreServicePermissions);

    auto       errRegister = mPermHandler.RegisterInstance(instanceIdent1, funcServerPermissions);
    const auto secret1     = errRegister.mValue;

    ASSERT_TRUE(errRegister.mError.IsNone()) << errRegister.mError.Message();
    ASSERT_FALSE(secret1.IsEmpty());

    StaticArray<PermKeyValue, 2> permsResult;
    const auto                   errGetVisPerms = mPermHandler.GetPermissions(instance, permsResult, secret1, "vis");
    ASSERT_TRUE(errGetVisPerms.IsNone()) << errGetVisPerms.Message();
    ASSERT_EQ(instance, instanceIdent1) << "Wrong instance";
    ASSERT_EQ(permsResult, visServicePermissions.mPermissions);

    errRegister        = mPermHandler.RegisterInstance(instanceIdent2, funcServerPermissions);
    const auto secret2 = errRegister.mValue;

    ASSERT_TRUE(errRegister.mError.IsNone()) << errRegister.mError.Message();
    ASSERT_FALSE(secret2.IsEmpty());

    ASSERT_NE(secret1, secret2) << "Duplicated secret for second registration";

    permsResult.Clear();
    const auto errGetSystemCorePerms = mPermHandler.GetPermissions(instance, permsResult, secret2, "systemCore");
    ASSERT_TRUE(errGetSystemCorePerms.IsNone()) << errGetSystemCorePerms.Message();
    ASSERT_EQ(instance, instanceIdent2) << "Wrong instance";
    ASSERT_EQ(permsResult, systemCoreServicePermissions.mPermissions);

    permsResult.Clear();
    const auto errGetUnknownPerms = mPermHandler.GetPermissions(instance, permsResult, secret1, "nill");
    ASSERT_TRUE(errGetUnknownPerms.Is(ErrorEnum::eNotFound)) << errGetSystemCorePerms.Message();

    auto errUnregister = mPermHandler.UnregisterInstance(instanceIdent2);
    ASSERT_TRUE(errUnregister.IsNone()) << errUnregister.Message();

    errUnregister = mPermHandler.UnregisterInstance(instanceIdent2);
    ASSERT_TRUE(errUnregister.Is(ErrorEnum::eNotFound)) << errUnregister.Message();

    errUnregister = mPermHandler.UnregisterInstance(instanceIdent1);
    ASSERT_TRUE(errUnregister.IsNone()) << errUnregister.Message();

    errUnregister = mPermHandler.UnregisterInstance(instanceIdent1);
    ASSERT_TRUE(errUnregister.Is(ErrorEnum::eNotFound)) << errUnregister.Message();
}
