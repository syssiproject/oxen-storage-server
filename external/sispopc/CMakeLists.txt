cmake_minimum_required(VERSION 3.10)  # bionic's cmake version

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.12 CACHE STRING "macOS deployment target (Apple clang only)")

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang ${LANGS})
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

project(sispopc
    VERSION 1.0.4
    DESCRIPTION "sispopc - Base 16/32/64 and Bittorrent Encoding/Decoding Header Only Library"
    LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)

message(STATUS "sispopc v${PROJECT_VERSION}")

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(sispopc_IS_TOPLEVEL_PROJECT TRUE)
else()
    set(sispopc_IS_TOPLEVEL_PROJECT FALSE)
endif()

option(SISPOPC_BUILD_TESTS "Building and perform sispopc tests" ${sispopc_IS_TOPLEVEL_PROJECT})
option(SISPOPC_BUILD_DOCS "Build sispopc documentation" ${sispopc_IS_TOPLEVEL_PROJECT})
option(SISPOPC_INSTALL "Add sispopc headers to install target" ${sispopc_IS_TOPLEVEL_PROJECT})


configure_file(sispopc/version.h.in sispopc/version.h @ONLY)
configure_file(libsispopc.pc.in libsispopc.pc @ONLY)


add_library(sispopc INTERFACE)

target_include_directories(sispopc
    INTERFACE
        $<INSTALL_INTERFACE:>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

add_library(sispopc::sispopc ALIAS sispopc)

export(
    TARGETS sispopc
    NAMESPACE sispopc::
    FILE sispopcTargets.cmake
)

if(SISPOPC_INSTALL)
  install(
    TARGETS sispopc
    EXPORT sispopcConfig
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

  install(
    FILES
    sispopc/base32z.h
    sispopc/base64.h
    sispopc/bt.h
    sispopc/bt_producer.h
    sispopc/bt_serialize.h
    sispopc/bt_value.h
    sispopc/byte_type.h
    sispopc/endian.h
    sispopc/hex.h
    sispopc/variant.h
    ${CMAKE_CURRENT_BINARY_DIR}/sispopc/version.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sispopc
    )


  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/libsispopc.pc
    DESTINATION ${CMAKE_INSTALL_DATADIR}/pkgconfig
    )
endif()


if(SISPOPC_BUILD_DOCS)
  add_subdirectory(docs)
endif()

if(SISPOPC_BUILD_TESTS)
  add_subdirectory(tests)
endif()
