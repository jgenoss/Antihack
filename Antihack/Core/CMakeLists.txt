# AntiCheatCore - Native Security Module
# CMake build configuration

cmake_minimum_required(VERSION 3.15)
project(AntiCheatCore VERSION 1.0.0 LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows-specific settings
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
    add_definitions(-DUNICODE -D_UNICODE)
    add_definitions(-DANTICHEATCORE_EXPORTS)
endif()

# Source files
set(SOURCES
    src/core.cpp
    src/detection.cpp
    src/antidebug.cpp
    src/integrity.cpp
)

# Header files
set(HEADERS
    include/anticheat_core.h
)

# Create DLL
add_library(AntiCheatCore SHARED ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(AntiCheatCore PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(AntiCheatCore PRIVATE
    kernel32
    user32
    advapi32
    psapi
    iphlpapi
)

# Output name
set_target_properties(AntiCheatCore PROPERTIES
    OUTPUT_NAME "AntiCheatCore"
    PREFIX ""
)

# Compiler flags for security
if(MSVC)
    target_compile_options(AntiCheatCore PRIVATE
        /W4         # Warning level 4
        /WX-        # Warnings not as errors (for now)
        /GS         # Buffer security check
        /sdl        # SDL checks
        /guard:cf   # Control Flow Guard
    )
    target_link_options(AntiCheatCore PRIVATE
        /DYNAMICBASE    # ASLR
        /NXCOMPAT       # DEP
        /GUARD:CF       # Control Flow Guard
    )
endif()

# Install
install(TARGETS AntiCheatCore
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
install(FILES ${HEADERS} DESTINATION include)
