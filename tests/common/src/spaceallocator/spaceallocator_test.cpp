/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "aos/common/spaceallocator/spaceallocator.hpp"
#include "aos/test/log.hpp"

using namespace testing;

namespace aos::spaceallocator {

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class SpaceAllocatorTest : public Test {
public:
    void SetUp() override { aos::test::InitLog(); }
};

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

TEST_F(SpaceAllocatorTest, SpaceIsProperlyReleased)
{
    constexpr auto cMaxNumAllocations = 8;

    SpaceAllocator<cMaxNumAllocations> spaceAllocator;

    for (size_t i = 0; i < cMaxNumAllocations + 1; ++i) {
        auto [space, err] = spaceAllocator.AllocateSpace(1);

        ASSERT_TRUE(err.IsNone());
    }
}

} // namespace aos::spaceallocator
