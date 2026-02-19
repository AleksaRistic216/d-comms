#pragma once
#ifdef __cplusplus
extern "C" {
#endif

/* Called once before the render loop. basedir = directory of executable. */
void app_init(const char *basedir);

/* Called every frame inside the ImGui NewFrame / Render pair. */
void app_frame(void);

/* Called once after the render loop exits. */
void app_shutdown(void);

/* Returns non-zero if the user pressed Quit inside the UI. */
int app_quit_requested(void);

#ifdef __cplusplus
}
#endif
