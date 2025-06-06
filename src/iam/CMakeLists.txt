#
# Copyright (C) 2023 Renesas Electronics Corporation.
# Copyright (C) 2023 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET aosiam)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES
    certhandler/certhandler.cpp
    certmodules/certmodule.cpp
    certmodules/pkcs11/pkcs11.cpp
    certprovider/certprovider.cpp
    identmodules/fileidentifier.cpp
    nodeinfoprovider/nodeinfoprovider.cpp
    nodemanager/nodemanager.cpp
    permhandler/permhandler.cpp
    provisionmanager/provisionmanager.cpp
)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(${TARGET} STATIC ${SOURCES})

target_compile_options(${TARGET} PRIVATE -Wstack-usage=${AOS_STACK_USAGE})
target_include_directories(${TARGET} PUBLIC ${AOS_CORE_LIB_DIR}/include)

# ######################################################################################################################
# Install
# ######################################################################################################################

install(TARGETS ${TARGET} ARCHIVE DESTINATION lib)

install(
    DIRECTORY ${AOS_CORE_LIB_DIR}/include/aos/iam
    DESTINATION include/aos
    FILES_MATCHING
    PATTERN "*.hpp"
)
