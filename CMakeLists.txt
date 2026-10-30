# ===================== CMakeLists.txt =====================
cmake_minimum_required(VERSION 3.16)
project(decoder VERSION 2.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/utf-8)
endif()

add_executable(decoder
    src/main.cpp
    src/crypto.cpp
    src/json.cpp
    src/decfile.cpp
    src/util.cpp
)
