# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.16)
project(capture_app VERSION 1.0)
include(CTest)
include(CheckCXXCompilerFlag)
function(enable_cxx_compiler_flag_if_supported flag)
    string(FIND "${CMAKE_CXX_FLAGS}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()
set(CMAKE_CXX_STANDARD 17)
enable_cxx_compiler_flag_if_supported("-Wall")
if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")
    set(PRJ_ROOT, "C:/Projects/unsorted/C_C++")
    include_directories(${PRJ_ROOT}/shared_src/c)
    add_executable(capture_app capture.cpp appConfig.h appConfig.cpp getopt_win32.h getopt_win32.c)
    add_executable(capture_app_test capture.cpp appConfig.h appConfig.cpp getopt_win32.h getopt_win32.c)
else(WIN32)
    add_executable(capture_app capture.cpp appConfig.h appConfig.cpp)
    target_link_libraries(capture_app rt)
    add_executable(capture_app_test capture.cpp appConfig.h appConfig.cpp)
    target_link_libraries(capture_app_test rt)
endif(WIN32)
add_executable(pcap_reader pcap_reader.c)
add_test(minimal capture_app_test capture_app_test)

find_package(PCAP)
if (PCAP_FOUND)
    message(STATUS "Using detected libpcap-dev package")
    target_link_libraries(capture_app  ${PCAP_LIBRARY})
    target_link_libraries(capture_app_test  ${PCAP_LIBRARY})
else(PCAP_FOUND)
    message(STATUS "Unable to detect libpcap-dev package - falling back to pkg-config...")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    target_link_libraries(capture_app  ${PCAP_LIBRARIES})
    target_include_directories(capture_app PUBLIC ${PCAP_INCLUDE_DIRS})
    target_link_libraries(capture_app_test  ${PCAP_LIBRARIES})
    target_include_directories(capture_app_test PUBLIC ${PCAP_INCLUDE_DIRS})
endif(PCAP_FOUND)
