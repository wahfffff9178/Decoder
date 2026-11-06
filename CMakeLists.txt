# ===================== CMakeLists.txt =====================
cmake_minimum_required(VERSION 3.16)
project(deccoder VERSION 2.2.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/utf-8)
endif()

add_executable(deccoder
    src/main.cpp
    src/crypto.cpp
    src/json.cpp
    src/decfile.cpp
    src/util.cpp
)
install(TARGETS deccoder DESTINATION bin)
