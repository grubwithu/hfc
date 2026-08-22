cmake_minimum_required(VERSION 3.20)
project(OrchestraEdgeIDPass LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Override CMAKE_CXX_FLAGS with LLVM's exact flags to match ABI.
set(CMAKE_CXX_FLAGS "${LLVM_CXXFLAGS}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Use llvm-config directly instead of find_package(LLVM), since the OSS-Fuzz
# builder image installs LLVM without CMake config files.
find_program(LLVM_CONFIG llvm-config REQUIRED)

execute_process(COMMAND ${LLVM_CONFIG} --includedir
  OUTPUT_VARIABLE LLVM_INCLUDE_DIR OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND ${LLVM_CONFIG} --version
  OUTPUT_VARIABLE LLVM_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
# Get the exact CXX flags used to build LLVM to match the ABI.
execute_process(COMMAND ${LLVM_CONFIG} --cxxflags
  OUTPUT_VARIABLE LLVM_CXXFLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "LLVM version: ${LLVM_VERSION}")
message(STATUS "LLVM include: ${LLVM_INCLUDE_DIR}")
message(STATUS "LLVM cxxflags: ${LLVM_CXXFLAGS}")

# For an out-of-tree pass plugin loaded by Clang, we only need headers.
# The plugin is loaded at runtime by Clang, which provides the LLVM symbols.
include_directories(SYSTEM ${LLVM_INCLUDE_DIR})

# Apply LLVM's exact CXX flags only to C++ targets (not C files).
separate_arguments(LLVM_CXXFLAGS_LIST UNIX_COMMAND "${LLVM_CXXFLAGS}")

# RTTI is typically disabled in LLVM builds. llvm-config --cxxflags includes
# -fno-rtti, but enforce it to be safe.
if(NOT LLVM_ENABLE_RTTI)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# Determine RTTI setting from llvm-config.
execute_process(COMMAND ${LLVM_CONFIG} --has-rtti
  OUTPUT_VARIABLE LLVM_HAS_RTTI OUTPUT_STRIP_TRAILING_WHITESPACE)
if(LLVM_HAS_RTTI STREQUAL "NO")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

# Suppress warnings from LLVM headers.
add_compile_options(-Wno-unused-parameter -Wno-covered-switch-default
  -Wno-deprecated-declarations -Wno-non-virtual-dtor -Wno-unused-variable)

add_library(OrchestraEdgeIDPass MODULE
  src/EdgeIDPass.cpp
)

# Apply LLVM's CXX flags to the C++ pass target only.
target_compile_options(OrchestraEdgeIDPass PRIVATE ${LLVM_CXXFLAGS_LIST})

# LLVM pass plugins should not have a lib prefix.
# The plugin entry point (llvmGetPassPluginInfo) must be exported, so
# we use default visibility rather than hidden.
set_target_properties(OrchestraEdgeIDPass PROPERTIES
  PREFIX ""
)

# No linking against LLVM libraries: the pass is loaded by Clang which
# already has all LLVM symbols resolved.

# Runtime coverage library: provides __orchestra_record_edge callback.
# The function is weak so non-fuzzer test binaries can link without it.
# When linked into fuzzer binaries, it captures and dumps edge coverage.
add_library(orchestra_edge_runtime STATIC
  src/edge_runtime.c
)
set_target_properties(orchestra_edge_runtime PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
