#
# Copyright (C) 2023 Renesas Electronics Corporation.
# Copyright (C) 2023 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET aossm)

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES
    image/imageparts.cpp
    launcher/launcher.cpp
    launcher/instance.cpp
    launcher/runtimespec.cpp
    layermanager/layermanager.cpp
    resourcemanager/resourcemanager.cpp
    servicemanager/servicemanager.cpp
    networkmanager/networkmanager.cpp
)

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(${TARGET} STATIC ${SOURCES})

target_compile_options(${TARGET} PRIVATE -Wstack-usage=${AOS_STACK_USAGE})
target_include_directories(${TARGET} PUBLIC ${AOS_CORE_LIB_DIR}/include)
target_link_libraries(${TARGET} PRIVATE aoscommon)

# ######################################################################################################################
# Install
# ######################################################################################################################

install(TARGETS ${TARGET} ARCHIVE DESTINATION lib)

install(
    DIRECTORY ${AOS_CORE_LIB_DIR}/include/aos/sm
    DESTINATION include/aos
    FILES_MATCHING
    PATTERN "*.hpp"
)
