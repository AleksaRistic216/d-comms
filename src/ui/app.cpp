#include "app.h"

#include <imgui.h>

#include <atomic>
#include <thread>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <dirent.h>
#endif

extern "C" {
#include "proto.h"
#include "sync.h"
}

#define MAX_CHATS 64

/* ---- application state ---- */

enum class Screen { ChatList, ChatView };
static Screen     g_screen      = Screen::ChatList;
static char       g_basedir[256] = {};
static char       g_active_chat[64] = {};
static proto_chat g_chat         = {};
static bool       g_chat_open    = false;

static char g_msg_input[4096]  = {};
static char g_new_name[64]     = {};
static char g_join_name[64]    = {};
static char g_join_cmd[256]    = {};
static char g_credentials[128] = {};

static bool g_show_new_modal   = false;
static bool g_show_join_modal  = false;
static bool g_show_cred_modal  = false;
static bool g_scroll_to_bottom = false;
static bool g_quit_requested   = false;

static std::atomic<bool> g_sync_stop{false};
static std::thread       g_sync_thread;

static void color_table_reset(void);  /* forward declaration */

/* ---- helpers ---- */

static int scan_chats(char names[][64])
{
    int count = 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/chats", g_basedir);

#ifdef _WIN32
    char pattern[600];
    snprintf(pattern, sizeof(pattern), "%s\\*.chat", path);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        int len = (int)strlen(fd.cFileName);
        if (len > 5 && len - 5 < 64) {
            memcpy(names[count], fd.cFileName, (size_t)(len - 5));
            names[count][len - 5] = '\0';
            count++;
        }
    } while (count < MAX_CHATS && FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < MAX_CHATS) {
        int len = (int)strlen(ent->d_name);
        if (len > 5 && len - 5 < 64 && strcmp(ent->d_name + len - 5, ".chat") == 0) {
            memcpy(names[count], ent->d_name, (size_t)(len - 5));
            names[count][len - 5] = '\0';
            count++;
        }
    }
    closedir(d);
#endif
    return count;
}

static void open_chat(const char *name)
{
    if (g_chat_open) {
        proto_save_chat(&g_chat, g_active_chat, g_basedir);
        proto_chat_cleanup(&g_chat);
        g_chat_open = false;
    }
    if (proto_load_chat(&g_chat, name, g_basedir) == 0) {
        strncpy(g_active_chat, name, sizeof(g_active_chat) - 1);
        g_active_chat[sizeof(g_active_chat) - 1] = '\0';
        g_chat_open = true;
        g_screen = Screen::ChatView;
        g_scroll_to_bottom = true;
        g_msg_input[0] = '\0';
        color_table_reset();
    }
}

static void close_chat(void)
{
    if (g_chat_open) {
        proto_save_chat(&g_chat, g_active_chat, g_basedir);
        proto_chat_cleanup(&g_chat);
        g_chat_open = false;
    }
    g_screen = Screen::ChatList;
}

/* ---- lifecycle ---- */

void app_init(const char *basedir)
{
    strncpy(g_basedir, basedir, sizeof(g_basedir) - 1);
    g_basedir[sizeof(g_basedir) - 1] = '\0';

    int port = sync_start_server();
    if (port > 0)
        sync_register(port);

    sync_with_peers();

    g_sync_stop = false;
    g_sync_thread = std::thread([]() {
        while (!g_sync_stop) {
            for (int i = 0; i < 50 && !g_sync_stop; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!g_sync_stop)
                sync_with_peers();
        }
    });
}

void app_shutdown(void)
{
    g_sync_stop = true;
    if (g_sync_thread.joinable())
        g_sync_thread.join();
    sync_unregister();
    if (g_chat_open) {
        proto_save_chat(&g_chat, g_active_chat, g_basedir);
        proto_chat_cleanup(&g_chat);
        g_chat_open = false;
    }
}

int app_quit_requested(void)
{
    return g_quit_requested ? 1 : 0;
}

/* ---- full-size window helper ---- */

static void begin_fullscreen(const char *id)
{
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin(id, nullptr,
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize   |
        ImGuiWindowFlags_NoMove     |
        ImGuiWindowFlags_NoScrollbar|
        ImGuiWindowFlags_NoScrollWithMouse);
}

/* ---- per-entity colour assignment ---- */

static const ImVec4 k_colors[] = {
    {0.30f, 0.80f, 1.00f, 1.f},  // cyan
    {1.00f, 0.80f, 0.20f, 1.f},  // yellow
    {0.40f, 1.00f, 0.40f, 1.f},  // green
    {1.00f, 0.50f, 0.30f, 1.f},  // orange
    {0.90f, 0.40f, 0.90f, 1.f},  // magenta
    {0.40f, 0.90f, 0.90f, 1.f},  // teal
    {1.00f, 0.70f, 0.70f, 1.f},  // pink
    {0.75f, 0.75f, 1.00f, 1.f},  // lavender
};
static constexpr int k_ncolors = (int)(sizeof(k_colors) / sizeof(k_colors[0]));

static char g_eid_map[k_ncolors][17] = {};
static int  g_eid_count = 0;

static void color_table_reset(void)
{
    memset(g_eid_map, 0, sizeof(g_eid_map));
    g_eid_count = 0;
}

/* Assign colours sequentially as new entity_ids are first seen.
   Guarantees no collision for up to k_ncolors unique participants. */
static ImVec4 color_for(const char *eid)
{
    if (!eid || eid[0] == '\0')
        return ImVec4(0.6f, 0.6f, 0.6f, 1.f);
    for (int i = 0; i < g_eid_count; i++)
        if (strcmp(g_eid_map[i], eid) == 0)
            return k_colors[i];
    if (g_eid_count < k_ncolors) {
        strncpy(g_eid_map[g_eid_count], eid, 16);
        g_eid_map[g_eid_count][16] = '\0';
        return k_colors[g_eid_count++];
    }
    /* More than k_ncolors unique IDs: fall back to hash (collisions possible) */
    unsigned h = 0;
    for (const char *p = eid; *p; p++) h = h * 31u + (unsigned char)*p;
    return k_colors[h % k_ncolors];
}

/* ---- chat list screen ---- */

static void draw_chat_list(void)
{
    begin_fullscreen("##chatlist");

    ImGui::TextUnformatted("d-comms");
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 220);
    if (ImGui::Button("New Chat"))  { g_show_new_modal  = true; g_new_name[0] = '\0'; }
    ImGui::SameLine();
    if (ImGui::Button("Join Chat")) { g_show_join_modal = true; g_join_name[0] = '\0'; g_join_cmd[0] = '\0'; }
    ImGui::SameLine();
    if (ImGui::Button("Quit"))      { g_quit_requested = true; }

    ImGui::Separator();

    char names[MAX_CHATS][64];
    int count = scan_chats(names);

    ImGui::BeginChild("##chatscroll");
    for (int i = 0; i < count; i++) {
        if (ImGui::Selectable(names[i])) {
            open_chat(names[i]);
        }
    }
    if (count == 0)
        ImGui::TextDisabled("No chats yet. Press New Chat or Join Chat.");
    ImGui::EndChild();

    /* New Chat modal */
    if (g_show_new_modal) {
        ImGui::OpenPopup("New Chat");
        g_show_new_modal = false;
    }
    if (ImGui::BeginPopupModal("New Chat", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Chat name:");
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##newname", g_new_name, sizeof(g_new_name));

        bool create = ImGui::Button("Create");
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();

        if (create && g_new_name[0] != '\0') {
            proto_chat tmp = {};
            char out_key[ID_BYTES * 2 + 1];
            char out_id[ID_BYTES * 2 + 1];
            if (proto_initialize(&tmp, out_key, out_id) == 0) {
                proto_save_chat(&tmp, g_new_name, g_basedir);
                proto_chat_cleanup(&tmp);
                snprintf(g_credentials, sizeof(g_credentials), "set %s %s", out_key, out_id);
                g_show_cred_modal = true;
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    /* Credentials modal */
    if (g_show_cred_modal) {
        ImGui::OpenPopup("Credentials");
        g_show_cred_modal = false;
    }
    if (ImGui::BeginPopupModal("Credentials", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Share this with the other device:");
        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.15f, 0.15f, 0.15f, 1.0f));
        ImGui::InputText("##cred", g_credentials, sizeof(g_credentials),
                         ImGuiInputTextFlags_ReadOnly);
        ImGui::PopStyleColor();
        if (ImGui::Button("Copy to clipboard"))
            ImGui::SetClipboardText(g_credentials);
        ImGui::SameLine();
        if (ImGui::Button("OK")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    /* Join Chat modal */
    if (g_show_join_modal) {
        ImGui::OpenPopup("Join Chat");
        g_show_join_modal = false;
    }
    if (ImGui::BeginPopupModal("Join Chat", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Chat name:");
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##joinname", g_join_name, sizeof(g_join_name));
        ImGui::Text("Credentials (\"set <key> <id>\"):");
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##joincmd", g_join_cmd, sizeof(g_join_cmd));

        bool join = ImGui::Button("Join");
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();

        if (join && g_join_name[0] != '\0' && g_join_cmd[0] != '\0') {
            char key[64], id[64];
            const char *p = g_join_cmd;
            if (strncmp(p, "set ", 4) == 0) p += 4;
            while (*p == ' ') p++;
            if (sscanf(p, "%63s %63s", key, id) == 2) {
                proto_chat tmp = {};
                proto_join(&tmp, key, id);
                proto_save_chat(&tmp, g_join_name, g_basedir);
                proto_chat_cleanup(&tmp);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::End();
}

/* ---- chat view screen ---- */

static void draw_chat_view(void)
{
    begin_fullscreen("##chatview");

    if (ImGui::Button("Back")) {
        close_chat();
        ImGui::End();
        return;
    }
    ImGui::SameLine();
    ImGui::Text("%s", g_active_chat);

    ImGui::Separator();

    /* Messages area */
    float input_height = ImGui::GetFrameHeightWithSpacing() + 8;
    ImGui::BeginChild("##msgs", ImVec2(0, -input_height), false);

    const proto_messages *msgs = nullptr;
    if (g_chat_open)
        msgs = proto_list(&g_chat);  /* proto_list locks internally via db_read */

    if (msgs) {
        /* Reset colour table every frame so colours always reflect the current
           sorted order, even after a re-walk triggered by sync. */
        color_table_reset();
        for (int i = 0; i < msgs->count; i++) {
            ImGui::TextColored(color_for(msgs->entity_ids[i]), "%s", msgs->texts[i]);
        }
    }

    if (g_scroll_to_bottom) {
        ImGui::SetScrollHereY(1.0f);
        g_scroll_to_bottom = false;
    }

    ImGui::EndChild();

    ImGui::Separator();

    /* Input row */
    float send_btn_width = 60;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - send_btn_width - ImGui::GetStyle().ItemSpacing.x);
    bool enter_pressed = ImGui::InputText("##msginput", g_msg_input, sizeof(g_msg_input),
                                         ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    bool send_clicked = ImGui::Button("Send", ImVec2(send_btn_width, 0));

    if ((enter_pressed || send_clicked) && g_msg_input[0] != '\0' && g_chat_open) {
        proto_send(&g_chat, g_msg_input);
        g_msg_input[0] = '\0';
        g_scroll_to_bottom = true;
        /* Refocus the input field */
        ImGui::SetKeyboardFocusHere(-1);
    }

    ImGui::End();
}

/* ---- per-frame entry point ---- */

void app_frame(void)
{
    if (g_screen == Screen::ChatList)
        draw_chat_list();
    else
        draw_chat_view();
}
