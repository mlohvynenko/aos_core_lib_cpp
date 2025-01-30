/*
 * Copyright (C) 2025 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/common/tools/time.hpp"

namespace aos {

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

StaticString<cTimeStrLen> Duration::ToISO8601String() const
{
    if (mDuration == 0) {
        return "PT0S";
    }

    StaticString<cTimeStrLen> result = (mDuration < 0) ? "-P" : "P";

    auto total = abs(mDuration);
    char buffer[16];

    if (auto years = total / Time::cYear.Nanoseconds(); years > 0) {
        snprintf(buffer, sizeof(buffer), "%ldY", years);

        result.Append(buffer);

        total %= Time::cYear.Nanoseconds();
    }

    if (auto months = total / Time::cMonth.Nanoseconds(); months > 0) {
        snprintf(buffer, sizeof(buffer), "%ldM", months);

        result.Append(buffer);
        total %= Time::cMonth.Nanoseconds();
    }

    if (auto weeks = total / Time::cWeek.Nanoseconds(); weeks > 0) {
        snprintf(buffer, sizeof(buffer), "%ldW", weeks);

        result.Append(buffer);

        total %= Time::cWeek.Nanoseconds();
    }

    if (auto days = total / Time::cDay.Nanoseconds(); days > 0) {
        snprintf(buffer, sizeof(buffer), "%ldD", days);

        result.Append(buffer);

        total %= Time::cDay.Nanoseconds();
    }

    const auto hours = total / Time::cHours.Nanoseconds();
    total %= Time::cHours.Nanoseconds();

    const auto minutes = total / Time::cMinutes.Nanoseconds();
    total %= Time::cMinutes.Nanoseconds();

    auto seconds = total / Time::cSeconds.Nanoseconds();
    total %= Time::cSeconds.Nanoseconds();

    if (hours || minutes || seconds || total) {
        result.Append("T");

        if (hours) {
            snprintf(buffer, sizeof(buffer), "%ldH", hours);
            result.Append(buffer);
        }

        if (minutes) {
            snprintf(buffer, sizeof(buffer), "%ldM", minutes);
            result.Append(buffer);
        }

        if (total == 0 && seconds > 0) {
            snprintf(buffer, sizeof(buffer), "%ldS", seconds);
            result.Append(buffer);
        }

        if (total > 0) {
            const auto rest = static_cast<double>(total) / Time::cSeconds.Nanoseconds() + static_cast<double>(seconds);

            snprintf(buffer, sizeof(buffer), "%0.9lfS", rest);
            result.Append(buffer);
        }
    }

    return result;
}

} // namespace aos
