cmake_minimum_required(VERSION 3.30)

project(DmaDetector LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ring3 library + CLI
add_library(DmaDetectorLib STATIC
        lib/bus.cpp
)

target_include_directories(DmaDetectorLib PUBLIC include)
target_link_libraries(DmaDetectorLib PUBLIC user32)

add_executable(DmaDetector
        lib/main_cli.cpp
)

target_link_libraries(DmaDetector PUBLIC DmaDetectorLib)

# ring0 driver (only when the WDK is around)
if (NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vendor/FindWDK/CMakeLists.txt")
    include(FetchContent)
    FetchContent_Declare(
            FindWDK
            GIT_REPOSITORY https://github.com/SergiusTheBest/FindWDK.git
            GIT_TAG master
            SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/FindWDK)
    FetchContent_MakeAvailable(FindWDK)
else ()
    add_subdirectory(vendor/FindWDK)
endif ()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/vendor/FindWDK/cmake")
find_package(WDK QUIET)

if (WDK_FOUND)
    message(STATUS "DmaDetector: building kernel driver with WDK ${WDK_VERSION}")
    file(GLOB DMA_KERNEL_SOURCES kernel/*.cpp)
    wdk_add_driver(DmaDetectorDriver
            NTDDI_VERSION 0x0A000010
            ${DMA_KERNEL_SOURCES})
    target_compile_definitions(DmaDetectorDriver PRIVATE _KMODE)
else ()
    message(STATUS "DmaDetector: WDK not found - kernel driver skipped, ring3 targets still built")
endif ()
