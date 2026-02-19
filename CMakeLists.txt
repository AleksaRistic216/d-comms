cmake_minimum_required(VERSION 3.20)
project(dcomms C)
set(CMAKE_C_STANDARD 99)

find_package(Threads REQUIRED)

add_library(dcomms_core STATIC
    src/proto.c src/sync.c src/aes.c src/sha256.c)
target_include_directories(dcomms_core PUBLIC src)
target_link_libraries(dcomms_core PUBLIC Threads::Threads)
