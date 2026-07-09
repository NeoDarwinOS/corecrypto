cmake_minimum_required(VERSION 3.25)

project(corecrypto C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(corecrypto SHARED)

# This is stupid. And also a quick library for ld64 on Linux. Reduces code size.
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(microcrypto STATIC)
endif()

include(cmake/components.cmake)

foreach(component IN LISTS CORECRYPTO_SHARED_COMPONENTS)
  message("CoreCrypto: Enabling Component - ${component}")
  target_include_directories(corecrypto PRIVATE
                             ${CMAKE_SOURCE_DIR}/${component}/include)
  foreach(file IN LISTS CORECRYPTO_${component}_SOURCES)
    target_sources(corecrypto PRIVATE
                   ${CMAKE_SOURCE_DIR}/${component}/src/${file})
  endforeach()
endforeach()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  foreach(component IN LISTS CORECRYPTO_MICRO_COMPONENTS)
    message("MicroCrypto: Enabling Component - ${component}")
    target_include_directories(microcrypto PRIVATE
                               ${CMAKE_SOURCE_DIR}/${component}/include)
    foreach(file IN LISTS CORECRYPTO_${component}_SOURCES)
      target_sources(microcrypto PRIVATE
                     ${CMAKE_SOURCE_DIR}/${component}/src/${file})
    endforeach()
  endforeach()
endif()

add_library(corecrypto_test)

target_link_libraries(corecrypto_test PRIVATE corecrypto)

target_include_directories(corecrypto_test PRIVATE
    ${CMAKE_SOURCE_DIR}/cc/include
    ${CMAKE_SOURCE_DIR}/ccdigest/include
    ${CMAKE_SOURCE_DIR}/ccmode/include
    ${CMAKE_SOURCE_DIR}/cctest/include
)

target_sources(corecrypto_test PRIVATE
    ${CMAKE_SOURCE_DIR}/cctest/src/cctest_base.c
    ${CMAKE_SOURCE_DIR}/cctest/src/cctest_symmetric.c
)

add_executable(cc_boot_post)

target_link_libraries(cc_boot_post PRIVATE corecrypto)

target_include_directories(cc_boot_post PRIVATE
    ${CMAKE_SOURCE_DIR}/cc/include
    ${CMAKE_SOURCE_DIR}/ccpost/include
)

target_sources(cc_boot_post PRIVATE
    ${CMAKE_SOURCE_DIR}/cc_boot_post/src/cc_boot_post.c
)
