/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AOS_STRING_HPP_
#define AOS_STRING_HPP_

#define __STDC_FORMAT_MACROS

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "aos/common/tools/array.hpp"

namespace aos {

/**
 * String instance.
 */
class String : public Array<char> {
public:
    /**
     * Creates string.
     */
    using Array::Array;

    // TODO: automatically make const String from const char*.
    // cppcheck-suppress noExplicitConstructor
    /**
     * Constructs string from C string.
     *
     * @param str C string.
     */
    String(const char* str)
        : Array(const_cast<char*>(str), strlen(str))
    {
        if (*end()) {
            *end() = 0;
        }
    }

    /**
     * Constructs string from other string.
     *
     * @param str string.
     */
    String(const String& str)
        : Array(str)
    {
        if (*end()) {
            *end() = 0;
        }
    }

    /**
     * Assigns string to string.
     *
     * @param str string.
     * @return String&.
     */
    String& operator=(const String& str)
    {
        Array::operator=(str);
        *end() = 0;

        return *this;
    }

    /**
     * Returns C string representation.
     *
     * @return const char* C string.
     */
    const char* CStr() const { return Get(); }

    /**
     * Sets new string size.
     *
     * @param size new size.
     * @return Error.
     */
    Error Resize(size_t size)
    {
        if (size > MaxSize()) {
            return ErrorEnum::eNoMemory;
        }

        Array::SetSize(size);
        *end() = 0;

        return ErrorEnum::eNone;
    }

    /**
     * Clears string.
     */
    void Clear() { Resize(0); }

    /**
     * Appends string.
     *
     * @param str string to append with.
     * @return String&.
     */
    String& Append(const String& str)
    {
        auto err = Array::Insert(end(), str.begin(), str.end());
        *end() = 0;
        assert(err.IsNone());

        return *this;
    }

    /**
     * Inserts items from range.
     *
     * @param pos insert position.
     * @param from insert from this position.
     * @param till insert till this position.
     * @return Error.
     */
    Error Insert(char* pos, const char* from, const char* till)
    {
        auto err = Array::Insert(pos, from, till);
        *end() = 0;

        return err;
    }

    /**
     * Appends string operator.
     *
     * @param str string to append with.
     * @return String&.
     */
    String& operator+=(const String& str) { return Append(str); }

    /**
     * Checks if str equals to C string.
     *
     * @param cStr C string to compare with.
     * @return bool.
     */
    bool operator==(const char* cStr) const
    {
        if (strlen(cStr) != Size()) {
            return false;
        }

        return memcmp(Get(), cStr, Size()) == 0;
    };

    /**
     * Checks if str doesn't equal to C string.
     *
     * @param cStr C string to compare with.
     * @return bool.
     */
    bool operator!=(const char* cStr) const { return !operator==(cStr); };

    /**
     * Checks if str equals to another string.
     *
     * @param str string to compare with.
     * @return bool.
     */
    bool operator==(const String& str) const { return Array::operator==(str); };

    /**
     * Checks if str doesn't equal to another string.
     *
     * @param str string to compare with.
     * @return bool.
     */
    bool operator!=(const String& str) const { return Array::operator!=(str); };

    /**
     * Checks if C string equals to string.
     *
     * @param cStr C string to compare with.
     * @param srt string to compare with.
     * @return bool.
     */
    friend bool operator==(const char* cStr, const String& str) { return str.operator==(cStr); };

    /**
     * Checks if C string doesn't equal to string.
     *
     * @param cStr C string to compare with.
     * @param srt string to compare with.
     * @return bool.
     */
    friend bool operator!=(const char* cStr, const String& str) { return str.operator!=(cStr); };

    /**
     * Converts sting to int.
     *
     * @return RetWithError<int>.
     */
    RetWithError<int> ToInt()
    {
        int value;

        auto err = ConvertString("%d", value);
        if (!err.IsNone()) {
            return {value, err};
        }

        return value;
    }

    /**
     * Converts sting to uint64.
     *
     * @return RetWithError<uint64_t>.
     */
    RetWithError<uint64_t> ToUint64()
    {
        uint64_t value;

        auto err = ConvertString("%" PRIu64, value);
        if (!err.IsNone()) {
            return {value, err};
        }

        return value;
    }

    /**
     * Converts sting to int64.
     *
     * @return RetWithError<int64_t>.
     */
    RetWithError<int64_t> ToInt64()
    {
        int64_t value;

        auto err = ConvertString("%" PRIi64, value);
        if (!err.IsNone()) {
            return {value, err};
        }

        return value;
    }

    /**
     * Converts int to string.
     *
     * @param value int value.
     * @return Error.
     */
    Error Convert(int value) { return ConvertValue(value, "%d"); }

    /**
     * Converts uint64_t to string.
     *
     * @param value uint64_t value.
     * @return Error.
     */
    Error Convert(uint64_t value) { return ConvertValue(value, "%" PRIu64); }

    /**
     * Converts int64_t to string.
     *
     * @param value int64_t value.
     * @return Error.
     */
    Error Convert(int64_t value) { return ConvertValue(value, "%" PRIi64); }

    /**
     * Converts error to string.
     *
     * @param inErr error.
     * @return Error.
     */
    Error Convert(const Error& inErr)
    {
        Clear();

        Append(inErr.Message());

        if (inErr.FileName()) {
            char tmpBuf[16];

            auto err = String(tmpBuf, sizeof(tmpBuf) - 1).Convert(inErr.LineNumber());
            if (!err.IsNone()) {
                return err;
            }

            Append(" (").Append(inErr.FileName()).Append(":").Append(tmpBuf).Append(")");
        }

        return ErrorEnum::eNone;
    }

    /**
     * Splits string to string list.
     *
     * @param list string list to split to.
     * @param delim delimeter.
     * @return Error.
     */
    template <typename T>
    Error Split(T& list, char delim = 0) const
    {
        list.Clear();

        auto it = begin();
        auto prevIt = it;

        while (it != end()) {
            if (delim ? *it == delim : isspace(*it)) {
                auto err = list.PushBack(String(prevIt, it - prevIt));
                if (!err.IsNone()) {
                    return err;
                }

                it++;
                prevIt = it;

                continue;
            }

            it++;
        }

        if (it != prevIt) {
            auto err = list.PushBack(String(prevIt, it - prevIt));
            if (!err.IsNone()) {
                return err;
            }
        }

        return ErrorEnum::eNone;
    }

private:
    template <typename T>
    Error ConvertValue(T value, const char* format)
    {
        Clear();

        // cppcheck-suppress wrongPrintfScanfArgNum
        auto ret = snprintf(Get(), MaxSize() + 1, format, value);
        if (ret < 0) {
            return ret;
        }

        Resize(ret);

        return ErrorEnum::eNone;
    }

    template <typename T>
    Error ConvertString(const char* format, T& value)
    {
        // cppcheck-suppress wrongPrintfScanfArgNum
        auto ret = sscanf(CStr(), format, &value);
        if (ret < 0) {
            return ret;
        }

        return ErrorEnum::eNone;
    }
};

/**
 * Static string instance.
 *
 * @tparam cMaxSize max static string size.
 */
template <size_t cMaxSize>
class StaticString : public String {
public:
    /**
     * Creates static string.
     */
    StaticString()
    {
        *(static_cast<char*>(mBuffer.Get())) = 0;
        *(static_cast<char*>(mBuffer.Get()) + cMaxSize) = 0;
        String::SetBuffer(mBuffer, cMaxSize);
    }

    /**
     * Creates static string from another static string.
     *
     * @param str string to create from.
     */
    StaticString(const StaticString& str)
        : String()
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    /**
     * Assigns static string from another static string.
     *
     * @param str string to create from.
     */
    StaticString& operator=(const StaticString& str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);

        return *this;
    }

    // cppcheck-suppress noExplicitConstructor
    /**
     * Creates static string from another string.
     *
     * @param str string to create from.
     */
    StaticString(const String& str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    // cppcheck-suppress noExplicitConstructor
    /**
     * Creates static string from C string.
     *
     * @param str initial value.
     */
    StaticString(const char* str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    /**
     * Assigns C string to static string.
     *
     * @param str C string.
     * @return StaticString&.
     */
    StaticString& operator=(const char* str)
    {
        String::operator=(str);

        return *this;
    }

private:
    StaticBuffer<cMaxSize + 1> mBuffer;
};

/**
 * Dynamic string instance.
 *
 * @tparam cMaxSize max dynamic string size.
 */
template <size_t cMaxSize>
class DynamicString : public String {
public:
    /**
     * Create dynamic string.
     */
    DynamicString()
        : mBuffer(cMaxSize * +1)
    {
        *(static_cast<char*>(mBuffer.Get())) = 0;
        *(static_cast<char*>(mBuffer.Get()) + cMaxSize) = 0;
        String::SetBuffer(mBuffer, cMaxSize);
    }

    /**
     * Creates dynamic string from another dynamic string.
     *
     * @param str string to create from.
     */
    DynamicString(const DynamicString& str)
        : String()
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    /**
     * Assigns dynamic string from another dynamic string.
     *
     * @param str string to create from.
     */
    DynamicString& operator=(const DynamicString& str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);

        return *this;
    }

    // cppcheck-suppress noExplicitConstructor
    /**
     * Creates dynamic string from another string.
     *
     * @param str initial value.
     */
    DynamicString(const String& str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    // cppcheck-suppress noExplicitConstructor
    /**
     * Creates dynamic string from C string.
     *
     * @param str initial value.
     */
    DynamicString(const char* str)
    {
        String::SetBuffer(mBuffer, cMaxSize);
        String::operator=(str);
    }

    /**
     * Assigns C string to dynamic string.
     *
     * @param str C string.
     * @return DynamicString&.
     */
    DynamicString& operator=(const char* str)
    {
        String::operator=(str);

        return *this;
    }

private:
    DynamicBuffer mBuffer;
};

/**
 * Interface used to convert derived type to string.
 */
class Stringer {
public:
    /**
     * Returns string representation of derived class.
     *
     * @return string.
     */
    virtual const String ToString() const = 0;
};

} // namespace aos

#endif
