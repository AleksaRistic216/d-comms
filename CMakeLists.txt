cmake_minimum_required(VERSION 3.20)
project(dcomms C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

set(DCOMMS_PLATFORM "desktop" CACHE STRING
    "Target platform: desktop | macos | ios | android")

find_package(Threads REQUIRED)

# --- Core static library (pure C, unchanged) ---
add_library(dcomms_core STATIC
    src/proto.c src/sync.c src/aes.c src/sha256.c)
target_include_directories(dcomms_core PUBLIC src)
target_link_libraries(dcomms_core PRIVATE Threads::Threads)

# --- Dear ImGui (common sources, no backend yet) ---
include(FetchContent)
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.91.6)
FetchContent_MakeAvailable(imgui)

add_library(imgui_core STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp)
target_include_directories(imgui_core PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends)

# --- Platform-specific target ---
if(DCOMMS_PLATFORM STREQUAL "desktop")
    FetchContent_Declare(glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG 3.4)
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(glfw)
    find_package(OpenGL REQUIRED)

    target_sources(imgui_core PRIVATE
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
    target_link_libraries(imgui_core PUBLIC glfw OpenGL::GL)

    add_executable(dcomms
        src/ui/app.cpp
        src/ui/main_desktop.cpp)

elseif(DCOMMS_PLATFORM STREQUAL "macos")
    # TODO: Metal backend
    # target_sources(imgui_core PRIVATE imgui_impl_glfw.cpp imgui_impl_metal.mm)
    add_executable(dcomms MACOSX_BUNDLE
        src/ui/app.cpp src/ui/main_macos.mm)

elseif(DCOMMS_PLATFORM STREQUAL "ios")
    # TODO: UIKit + Metal
    add_executable(dcomms MACOSX_BUNDLE
        src/ui/app.cpp src/ui/main_ios.mm)
    set_target_properties(dcomms PROPERTIES
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.dcomms.app"
        XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "14.0")

elseif(DCOMMS_PLATFORM STREQUAL "android")
    # TODO: ANativeActivity + OpenGL ES 3.0
    add_library(dcomms SHARED
        src/ui/app.cpp src/ui/main_android.cpp)
endif()

target_link_libraries(dcomms PRIVATE dcomms_core imgui_core Threads::Threads)
target_include_directories(dcomms PRIVATE src src/ui)
