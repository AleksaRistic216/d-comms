#include "compat.h"

#ifdef DCOMMS_WINDOWS
#  include <bcrypt.h>
#endif

/* ---- dcomms_flock ---- */

int dcomms_flock(int fd, int op)
{
#ifdef DCOMMS_WINDOWS
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov;
    memset(&ov, 0, sizeof(ov));
    if (op == LOCK_UN) {
        return UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov) ? 0 : -1;
    } else {
        DWORD flags = LOCKFILE_FAIL_IMMEDIATELY;
        if (op & LOCK_EX) flags |= LOCKFILE_EXCLUSIVE_LOCK;
        return LockFileEx(h, flags, 0, MAXDWORD, MAXDWORD, &ov) ? 0 : -1;
    }
#else
    return flock(fd, op);
#endif
}

/* ---- dcomms_random_bytes ---- */

int dcomms_random_bytes(void *buf, size_t size)
{
#ifdef DCOMMS_WINDOWS
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)size,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size);
    close(fd);
    return (n == (ssize_t)size) ? 0 : -1;
#endif
}

/* ---- dcomms_open_private ---- */

int dcomms_open_private(const char *path)
{
#ifdef DCOMMS_WINDOWS
    return _open(path, _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY,
                 _S_IREAD | _S_IWRITE);
#else
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
}

/* ---- dcomms_wsa_init / dcomms_wsa_cleanup ---- */

#ifdef DCOMMS_WINDOWS
static int g_wsa_init = 0;
#endif

void dcomms_wsa_init(void)
{
#ifdef DCOMMS_WINDOWS
    if (!g_wsa_init) {
        WSADATA wd;
        WSAStartup(MAKEWORD(2, 2), &wd);
        g_wsa_init = 1;
    }
#endif
}

void dcomms_wsa_cleanup(void)
{
#ifdef DCOMMS_WINDOWS
    if (g_wsa_init) {
        WSACleanup();
        g_wsa_init = 0;
    }
#endif
}
