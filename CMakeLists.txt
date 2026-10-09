cmake_minimum_required(VERSION 3.25)

project(AeroRE VERSION 0.3.0 LANGUAGES CXX)

option(AERORE_BUILD_TESTS "Build the native regression suite" ON)
option(AERORE_BUILD_GUI "Build the Dear ImGui DirectX 11 frontend" OFF)
option(AERORE_BUILD_PYTHON "Build the pybind11 extension" OFF)
option(AERORE_USE_ZYDIS "Use Zydis with the built-in decoder as fallback" ON)
option(AERORE_USE_LZMA "Enable VMProtect static LZMA reconstruction" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(SQLite3 REQUIRED)

set(AERORE_SOURCES
    AeroRE/src/anti_debug.cpp
    AeroRE/src/database.cpp
    AeroRE/src/debugger.cpp
    AeroRE/src/decoder.cpp
    AeroRE/src/emu.cpp
    AeroRE/src/engine.cpp
    AeroRE/src/exports.cpp
    AeroRE/src/iat.cpp
    AeroRE/src/json.cpp
    AeroRE/src/mcp.cpp
    AeroRE/src/model.cpp
    AeroRE/src/pe.cpp
    AeroRE/src/pseudocode.cpp
    AeroRE/src/session.cpp
    AeroRE/src/ui.cpp
    AeroRE/src/unpack.cpp)

add_library(aerore_core STATIC ${AERORE_SOURCES})
add_library(AeroRE::Core ALIAS aerore_core)
target_include_directories(aerore_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/AeroRE/include>
        $<INSTALL_INTERFACE:include>)
target_link_libraries(aerore_core PUBLIC SQLite::SQLite3)
target_compile_definitions(aerore_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
set_target_properties(aerore_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WIN32)
    target_link_libraries(aerore_core PUBLIC ws2_32)
endif()

if(AERORE_USE_ZYDIS)
    find_package(Zydis CONFIG REQUIRED)
    target_link_libraries(aerore_core PUBLIC Zydis::Zydis)
    target_compile_definitions(aerore_core PRIVATE AERORE_HAS_ZYDIS=1)
endif()

if(AERORE_USE_LZMA)
    find_package(LibLZMA REQUIRED)
    target_link_libraries(aerore_core PUBLIC LibLZMA::LibLZMA)
    target_compile_definitions(aerore_core PUBLIC AERORE_HAS_LZMA=1)
endif()

if(AERORE_BUILD_GUI)
    if(NOT WIN32)
        message(FATAL_ERROR "AERORE_BUILD_GUI currently requires Windows")
    endif()
    find_package(imgui CONFIG REQUIRED)
    target_link_libraries(aerore_core PUBLIC imgui::imgui d3d11 dxgi comdlg32)
    target_compile_definitions(aerore_core PRIVATE AERORE_HAS_IMGUI=1)
endif()

if(MSVC)
    target_compile_options(aerore_core PRIVATE /W4 /permissive- /EHsc /utf-8)
else()
    target_compile_options(aerore_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(aerore AeroRE/src/cli.cpp)
target_link_libraries(aerore PRIVATE AeroRE::Core)

if(AERORE_BUILD_PYTHON)
    find_package(pybind11 CONFIG REQUIRED)
    pybind11_add_module(aerore_python MODULE AeroRE/src/python.cpp)
    target_link_libraries(aerore_python PRIVATE AeroRE::Core)
    target_compile_definitions(aerore_python PRIVATE AERORE_HAS_PYBIND=1)
    set_target_properties(aerore_python PROPERTIES OUTPUT_NAME aerore)
endif()

if(AERORE_BUILD_TESTS)
    include(CTest)
    add_executable(aerore_tests AeroRE/tests/test_main.cpp)
    target_link_libraries(aerore_tests PRIVATE AeroRE::Core)
    add_test(NAME aerore.native COMMAND aerore_tests)
endif()

include(GNUInstallDirs)
install(TARGETS aerore_core aerore
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY AeroRE/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

