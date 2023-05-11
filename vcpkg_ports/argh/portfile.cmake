# header-only library

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO adishavit/argh
    REF master
    SHA512 c80b4812b087282565ade021e2e33bb2daa3670422e9c78ad49cb7e92dcc2ca5b3c68028d9eae4acee994490d638e948880414e1672b966c0e7b8f80a402c239
    HEAD_REF master
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTS=OFF
        -DBUILD_EXAMPLES=OFF
)

vcpkg_cmake_install()

if(EXISTS "${CURRENT_PACKAGES_DIR}/CMake")
    vcpkg_cmake_config_fixup(CONFIG_PATH CMake)
elseif(EXISTS "${CURRENT_PACKAGES_DIR}/lib/cmake/${PORT}")
    vcpkg_cmake_config_fixup(CONFIG_PATH "lib/cmake/${PORT}")
endif()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug" "${CURRENT_PACKAGES_DIR}/lib")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/share/doc")

# Handle copyright
file(INSTALL "${SOURCE_PATH}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
