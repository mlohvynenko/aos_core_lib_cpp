/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <filesystem>
#include <fstream>

#include <gtest/gtest.h>

#include "aos/common/tools/fs.hpp"

using namespace aos;

static const auto kBaseTestDir = std::filesystem::current_path();

static void CreateFile(const char* path, const char* text = "test file", size_t permissions = 0666U)
{
    std::ofstream stream {path, std::ios_base::trunc};

    stream << text;
    stream.close();

    std::filesystem::permissions(path, std::filesystem::perms(permissions));
}

static void CheckFile(const char* path, const char* text, const size_t permissions)
{
    StaticArray<uint8_t, 100> data;
    Array<uint8_t>            expData {reinterpret_cast<const uint8_t*>(text), strlen(text)};

    EXPECT_TRUE(FS::ReadFile(path, data).IsNone());
    EXPECT_EQ(data, expData) << "Wrong data in file: " << path;
    EXPECT_EQ(std::filesystem::status(path).permissions(), std::filesystem::perms(permissions))
        << "Wrong permissions for file: " << path;
}

TEST(FSTest, AppendPath)
{
    const auto home  = "/home/root";
    const auto build = "work/aos_core_lib_cpp/build";

    StaticString<cFilePathLen> src1 = home;

    FS::AppendPath(src1, build);
    EXPECT_EQ(src1, "/home/root/work/aos_core_lib_cpp/build");

    StaticString<cFilePathLen> src2 = home;

    FS::AppendPath(src2, "misc/", build);
    EXPECT_EQ(src2, "/home/root/misc/work/aos_core_lib_cpp/build");

    StaticString<cFilePathLen> src3;

    FS::AppendPath(src3, home, build);
    EXPECT_EQ(src3, "/home/root/work/aos_core_lib_cpp/build");
}

TEST(FSTest, JoinPath)
{
    const auto home  = "/home/root";
    const auto build = "work/aos_core_lib_cpp/build";

    auto path1 = FS::JoinPath(home, "misc", build);
    EXPECT_EQ(path1, "/home/root/misc/work/aos_core_lib_cpp/build");
}

TEST(FSTest, Dir)
{
    const auto test1 = "/home/root/test.txt";

    auto path1 = FS::Dir(test1);
    EXPECT_EQ(path1, "/home/root");

    const auto test2 = "/home/root/";

    auto path2 = FS::Dir(test2);
    EXPECT_EQ(path2, "/home/root");
}

TEST(FSTest, DirExist)
{
    EXPECT_EQ(FS::DirExist(kBaseTestDir.c_str()), RetWithError<bool>(true));

    const auto notExistingDir = FS::JoinPath(kBaseTestDir.c_str(), "dir-doesnt-exist");

    EXPECT_EQ(FS::DirExist(notExistingDir), RetWithError<bool>(false));
}

TEST(FSTest, MakeDir)
{
    const auto testDir = kBaseTestDir / "make-dir-test";

    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(false));
    EXPECT_TRUE(FS::MakeDir(testDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(true));

    FS::RemoveAll(testDir.c_str());
}

TEST(FSTest, MakeDirPathExists)
{
    EXPECT_EQ(FS::DirExist(kBaseTestDir.c_str()), RetWithError<bool>(true));
    EXPECT_TRUE(FS::MakeDir(kBaseTestDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(kBaseTestDir.c_str()), RetWithError<bool>(true));
}

TEST(FSTest, MakeDirAll)
{
    const auto testDir  = kBaseTestDir / "make-dir-all-test";
    const auto childDir = testDir / "child";

    EXPECT_EQ(FS::DirExist(childDir.c_str()), RetWithError<bool>(false));
    EXPECT_TRUE(FS::MakeDirAll(childDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(childDir.c_str()), RetWithError<bool>(true));

    FS::RemoveAll(testDir.c_str());
}

TEST(FSTest, ClearDir)
{
    const auto testDir   = kBaseTestDir / "clear-dir-test";
    const auto childDir  = testDir / "child1/child2";
    const auto childFile = testDir / "test.txt";

    ASSERT_TRUE(std::filesystem::create_directories(childDir));
    CreateFile(childFile.c_str());

    EXPECT_EQ(FS::DirExist(childDir.c_str()), RetWithError<bool>(true));
    EXPECT_TRUE(FS::ClearDir(testDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(childDir.c_str()), RetWithError<bool>(false));

    EXPECT_TRUE(FS::Remove(testDir.c_str()).IsNone());
}

TEST(FSTest, RemoveFile)
{
    const auto testDir   = kBaseTestDir / "remove-file-test";
    const auto childFile = testDir / "test.txt";

    EXPECT_TRUE(std::filesystem::create_directories(testDir));
    CreateFile(childFile.c_str());

    EXPECT_TRUE(FS::Remove(childFile.c_str()).IsNone());
    EXPECT_FALSE(std::filesystem::exists(childFile));

    FS::Remove(testDir.c_str());
}

TEST(FSTest, RemoveDirEmpty)
{
    const auto testDir = kBaseTestDir / "remove-dir-empty-test";

    EXPECT_TRUE(std::filesystem::create_directories(testDir));

    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(true));
    EXPECT_TRUE(FS::Remove(testDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(false));
}

TEST(FSTest, RemoveDirNotEmpty)
{
    const auto testDir  = kBaseTestDir / "remove-dir-notempty-test";
    const auto childDir = testDir / "child1";

    EXPECT_TRUE(std::filesystem::create_directories(childDir));

    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(true));
    EXPECT_FALSE(FS::Remove(testDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(true));

    FS::RemoveAll(testDir.c_str());
}

TEST(FSTest, RemoveAllFile)
{
    const auto testDir   = kBaseTestDir / "remove-all-file-test";
    const auto childFile = testDir / "test.txt";

    EXPECT_TRUE(std::filesystem::create_directories(testDir));
    CreateFile(childFile.c_str());

    EXPECT_TRUE(FS::RemoveAll(childFile.c_str()).IsNone());
    EXPECT_FALSE(std::filesystem::exists(childFile));

    FS::Remove(testDir.c_str());
}

TEST(FSTest, RemoveAllDirNotEmpty)
{
    const auto testDir   = kBaseTestDir / "remove-all-dir-notempty-test";
    const auto childDir  = testDir / "child1";
    const auto childFile = testDir / "test.txt";

    EXPECT_TRUE(std::filesystem::create_directories(childDir));
    CreateFile(childFile.c_str());

    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(true));
    EXPECT_TRUE(FS::RemoveAll(testDir.c_str()).IsNone());
    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(false));
}

TEST(FSTest, RemoveAllNotExistingDir)
{
    const auto testDir = kBaseTestDir / "remove-all-not-existing-dir-test";

    EXPECT_EQ(FS::DirExist(testDir.c_str()), RetWithError<bool>(false));
    EXPECT_TRUE(FS::RemoveAll(testDir.c_str()).IsNone());
}

TEST(FSTest, ReadFile)
{
    const auto testFile      = kBaseTestDir / "read-file-test.txt";
    const auto wrongFileName = kBaseTestDir / "wrong-file-name.txt";

    const char text[] = "Hello World";

    const Array<uint8_t> expData {reinterpret_cast<const uint8_t*>(text), strlen(text)};

    CreateFile(testFile.c_str(), text);

    StaticArray<uint8_t, 100> bigBuff;
    StaticArray<uint8_t, 1>   smallBuff;

    EXPECT_TRUE(FS::ReadFile(testFile.c_str(), bigBuff).IsNone());
    EXPECT_EQ(expData, bigBuff);

    EXPECT_FALSE(FS::ReadFile(testFile.c_str(), smallBuff).IsNone());
    EXPECT_FALSE(FS::ReadFile(wrongFileName.c_str(), bigBuff).IsNone());

    FS::RemoveAll(testFile.c_str());
}

TEST(FSTest, ReadFileToString)
{
    const auto testFile      = kBaseTestDir / "read-file-to-string-test.txt";
    const auto wrongFileName = kBaseTestDir / "wrong-file-name.txt";

    const char text[] = "Hello World";

    CreateFile(testFile.c_str(), text);

    StaticString<100> bigBuff;
    StaticString<1>   smallBuff;

    EXPECT_TRUE(FS::ReadFileToString(testFile.c_str(), bigBuff).IsNone());
    EXPECT_EQ(bigBuff, text);

    EXPECT_FALSE(FS::ReadFileToString(testFile.c_str(), smallBuff).IsNone());
    EXPECT_FALSE(FS::ReadFileToString(wrongFileName.c_str(), bigBuff).IsNone());

    FS::RemoveAll(testFile.c_str());
}

TEST(FSTest, WriteFile)
{
    const auto newFile      = kBaseTestDir / "write-file-new.txt";
    const auto existingFile = kBaseTestDir / "write-file-overwrite.txt";

    CreateFile(existingFile.c_str(), "dlroW olleH", 0664);

    const char           text[] = "Hello World";
    const Array<uint8_t> data {reinterpret_cast<const uint8_t*>(text), strlen(text)};

    EXPECT_TRUE(FS::WriteFile(newFile.c_str(), data, 0664).IsNone());
    CheckFile(newFile.c_str(), text, 0664);

    EXPECT_TRUE(FS::WriteFile(existingFile.c_str(), data, 0664).IsNone());
    CheckFile(existingFile.c_str(), text, 0664);

    FS::RemoveAll(newFile.c_str());
    FS::RemoveAll(existingFile.c_str());
}

TEST(FSTest, WriteStringToFile)
{
    const auto newFile      = kBaseTestDir / "write-file-to-string-new.txt";
    const auto existingFile = kBaseTestDir / "write-file-to-string-overwrite.txt";

    CreateFile(existingFile.c_str(), "dlroW olleH", 0444);

    const char text[] = "Hello World";

    EXPECT_TRUE(FS::WriteStringToFile(newFile.c_str(), text, 0664).IsNone());
    CheckFile(newFile.c_str(), text, 0664);

    EXPECT_TRUE(FS::WriteStringToFile(existingFile.c_str(), text, 0666).IsNone());
    CheckFile(existingFile.c_str(), text, 0666);

    FS::RemoveAll(newFile.c_str());
    FS::RemoveAll(existingFile.c_str());
}
