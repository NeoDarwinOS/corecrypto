cmake_minimum_required(VERSION 3.25)

project(corecrypto C)

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
