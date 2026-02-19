#include "app.h"

#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>

#include <cstdio>
#include <cstring>

#ifndef _WIN32
#  include <unistd.h>
#  include <signal.h>
#else
#  include <windows.h>
#endif

static void resolve_basedir(char *out, size_t sz)
{
#ifdef _WIN32
    GetModuleFileNameA(nullptr, out, (DWORD)sz);
    char *slash = strrchr(out, '\\');
    if (slash) *slash = '\0';
    else out[0] = '\0';
#else
    ssize_t n = readlink("/proc/self/exe", out, sz - 1);
    if (n > 0) {
        out[n] = '\0';
        char *slash = strrchr(out, '/');
        if (slash) *slash = '\0';
        else out[0] = '\0';
    } else {
        out[0] = '.';
        out[1] = '\0';
    }
#endif
}

int main(void)
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    if (!glfwInit()) {
        fprintf(stderr, "glfwInit failed\n");
        return 1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);
#endif

    GLFWwindow *win = glfwCreateWindow(900, 600, "d-comms", nullptr, nullptr);
    if (!win) {
        fprintf(stderr, "glfwCreateWindow failed\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(win);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr; /* disable imgui.ini */

    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(win, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    char basedir[256];
    resolve_basedir(basedir, sizeof(basedir));
    app_init(basedir);

    while (!glfwWindowShouldClose(win) && !app_quit_requested()) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app_frame();

        ImGui::Render();

        int w, h;
        glfwGetFramebufferSize(win, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(win);
    }

    app_shutdown();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(win);
    glfwTerminate();

    return 0;
}
