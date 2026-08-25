cmake_minimum_required(VERSION 3.25)

project(corecrypto C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

add_library(corecrypto_shared SHARED)
add_library(corecrypto_static STATIC)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
  include(cmake/config/win32.cmake)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  include(cmake/config/linux.cmake)
endif()

set_target_properties(corecrypto_shared PROPERTIES OUTPUT_NAME "corecrypto")

foreach(component IN LISTS CORECRYPTO_STATIC_COMPONENTS)
  message("corecrypto (static): Enabling Component - ${component}")
  include(cmake/components/${component}.cmake)
  target_include_directories(corecrypto_static PRIVATE
                             ${CMAKE_SOURCE_DIR}/${component}/include)
  foreach(file IN LISTS CORECRYPTO_${component}_SOURCES)
    target_sources(corecrypto_static PRIVATE
                   ${CMAKE_SOURCE_DIR}/${component}/src/${file})
  endforeach()
endforeach()

foreach(component IN LISTS CORECRYPTO_SHARED_COMPONENTS)
  message("corecrypto (shared): Enabling Component - ${component}")
  include(cmake/components/${component}.cmake)
  target_include_directories(corecrypto_shared PRIVATE
                             ${CMAKE_SOURCE_DIR}/${component}/include)
  foreach(file IN LISTS CORECRYPTO_${component}_SOURCES)
    target_sources(corecrypto_shared PRIVATE
                   ${CMAKE_SOURCE_DIR}/${component}/src/${file})
  endforeach()
endforeach()

add_library(corecrypto_test)

target_link_libraries(corecrypto_test PRIVATE corecrypto_shared)

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
