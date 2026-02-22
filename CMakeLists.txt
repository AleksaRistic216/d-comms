cmake_minimum_required(VERSION 3.20)
project(dcomms C)
set(CMAKE_C_STANDARD 99)

find_package(Threads REQUIRED)

include(FetchContent)
FetchContent_Declare(jech_dht
    GIT_REPOSITORY https://github.com/jech/dht.git
    GIT_TAG        master)
FetchContent_MakeAvailable(jech_dht)

add_library(dcomms_core STATIC
    src/proto.c src/sync.c src/aes.c src/sha256.c
    src/dht_client.c src/upnp.c src/compat.c
    ${jech_dht_SOURCE_DIR}/dht.c)
target_include_directories(dcomms_core PUBLIC
    src
    ${jech_dht_SOURCE_DIR})
target_link_libraries(dcomms_core PUBLIC Threads::Threads)

enable_testing()

# Separate library variant with minimal KDF rounds so the test suite runs fast.
add_library(dcomms_core_test STATIC
    src/proto.c src/sync.c src/aes.c src/sha256.c
    src/dht_client.c src/upnp.c src/compat.c
    ${jech_dht_SOURCE_DIR}/dht.c)
target_include_directories(dcomms_core_test PUBLIC
    src
    ${jech_dht_SOURCE_DIR})
target_link_libraries(dcomms_core_test PUBLIC Threads::Threads)
target_compile_definitions(dcomms_core_test PRIVATE KDF_ROUNDS=10)

if(WIN32)
    target_link_libraries(dcomms_core      PUBLIC ws2_32 bcrypt)
    target_link_libraries(dcomms_core_test PUBLIC ws2_32 bcrypt)
    target_compile_definitions(dcomms_core      PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_definitions(dcomms_core_test PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

if(MSVC)
    FetchContent_Declare(pthreads4w
        GIT_REPOSITORY https://github.com/jwinarske/pthreads4w.git
        GIT_TAG        main)
    FetchContent_MakeAvailable(pthreads4w)
    target_link_libraries(dcomms_core      PUBLIC pthreads4w)
    target_link_libraries(dcomms_core_test PUBLIC pthreads4w)
endif()

foreach(t crypto proto sync)
    add_executable(test_${t} tests/test_${t}.c)
    target_link_libraries(test_${t} PRIVATE dcomms_core_test)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
