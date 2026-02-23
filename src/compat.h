#ifndef DCOMMS_COMPAT_H
#define DCOMMS_COMPAT_H

/* ---- Platform detection ---- */
#ifdef _WIN32
#  define DCOMMS_WINDOWS
#elif defined(__APPLE__)
#  define DCOMMS_MACOS
#else
#  define DCOMMS_LINUX
#endif

/* ---- Platform-specific socket and file headers ---- */
#ifdef DCOMMS_WINDOWS
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#  include <io.h>
#  include <direct.h>
#  include <fcntl.h>
#  include <basetsd.h>
   typedef SSIZE_T ssize_t;
#  define LOCK_SH 1
#  define LOCK_EX 2
#  define LOCK_UN 8
   /* Winsock2 uses SD_BOTH; map POSIX name */
#  ifndef SHUT_RDWR
#    define SHUT_RDWR SD_BOTH
#  endif
#else
#  include <sys/socket.h>
#  include <sys/select.h>
#  include <sys/file.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#endif

/* ---- All-platform headers ---- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>

/* ---- strndup fallback (Windows) ---- */
#ifdef DCOMMS_WINDOWS
static inline char *dcomms_strndup(const char *s, size_t n)
{
    size_t len = 0;
    while (len < n && s[len]) len++;
    char *p = (char *)malloc(len + 1);
    if (!p) return NULL;
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}
#  define strndup dcomms_strndup
#endif

/* ---- strcasestr fallback (Windows) ---- */
#ifdef DCOMMS_WINDOWS
static inline char *dcomms_strcasestr(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0) return (char *)haystack;
    for (; *haystack; haystack++) {
        if (_strnicmp(haystack, needle, nlen) == 0)
            return (char *)haystack;
    }
    return NULL;
}
#  define strcasestr dcomms_strcasestr
#endif

/* ---- setenv fallback (Windows) ---- */
#ifdef DCOMMS_WINDOWS
static inline int dcomms_setenv(const char *name, const char *value, int overwrite)
{
    if (!overwrite && getenv(name) != NULL) return 0;
    return _putenv_s(name, value) == 0 ? 0 : -1;
}
#  define setenv(n, v, o) dcomms_setenv(n, v, o)
#endif

/* ---- ftruncate fallback (Windows) ---- */
#ifdef DCOMMS_WINDOWS
#  define ftruncate(fd, len) _chsize_s(fd, (long long)(len))
#endif

/* ---- mkdir wrapper ---- */
#ifdef DCOMMS_WINDOWS
#  define dcomms_mkdir(path, mode) _mkdir(path)
#else
#  define dcomms_mkdir(path, mode) mkdir(path, mode)
#endif

/* ---- socket type ---- */
#ifdef DCOMMS_WINDOWS
   typedef SOCKET dcomms_socket_t;
#  define DCOMMS_INVALID_SOCKET INVALID_SOCKET
#else
   typedef int dcomms_socket_t;
#  define DCOMMS_INVALID_SOCKET (-1)
#endif

/* ---- sock_close ---- */
#ifdef DCOMMS_WINDOWS
#  define sock_close(s) closesocket(s)
#else
#  define sock_close(s) close(s)
#endif

/* ---- sock_send / sock_recv ---- */
#ifdef DCOMMS_WINDOWS
#  define sock_send(fd, b, n) send((SOCKET)(fd), (const char *)(b), (int)(n), 0)
#  define sock_recv(fd, b, n) recv((SOCKET)(fd), (char *)(b), (int)(n), 0)
#else
#  define sock_send(fd, b, n) write(fd, b, n)
#  define sock_recv(fd, b, n) read(fd, b, n)
#endif

/* ---- setsockopt / getsockopt value casts ---- */
#ifdef DCOMMS_WINDOWS
#  define SOCKOPT_VAL(p)    ((const char *)(p))  /* setsockopt: const char* */
#  define SOCKOPT_OUTVAL(p) ((char *)(p))         /* getsockopt: char*       */
#else
#  define SOCKOPT_VAL(p)    (p)
#  define SOCKOPT_OUTVAL(p) (p)
#endif

/* ---- socket error codes ---- */
#ifdef DCOMMS_WINDOWS
#  define SOCK_ERRNO        WSAGetLastError()
#  define SOCK_EINPROGRESS  WSAEWOULDBLOCK
#  define SOCK_EALREADY     WSAEALREADY
#else
#  define SOCK_ERRNO        errno
#  define SOCK_EINPROGRESS  EINPROGRESS
#  define SOCK_EALREADY     EALREADY
#endif

/* ---- non-blocking helpers ---- */
static inline int dcomms_set_nonblocking(dcomms_socket_t s, int on)
{
#ifdef DCOMMS_WINDOWS
    u_long mode = (u_long)on;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl((int)s, F_GETFL, 0);
    if (flags < 0) return -1;
    if (on)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl((int)s, F_SETFL, flags) == 0 ? 0 : -1;
#endif
}

static inline int dcomms_set_blocking(dcomms_socket_t s)
{
    return dcomms_set_nonblocking(s, 0);
}

/* ---- socket timeout helper ---- */
static inline void dcomms_set_socktimeo(dcomms_socket_t s, int which, int secs)
{
#ifdef DCOMMS_WINDOWS
    DWORD ms = (DWORD)(secs * 1000);
    setsockopt(s, SOL_SOCKET, which, SOCKOPT_VAL(&ms), sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec  = secs;
    tv.tv_usec = 0;
    setsockopt((int)s, SOL_SOCKET, which, SOCKOPT_VAL(&tv), sizeof(tv));
#endif
}

/* ---- function declarations ---- */
int  dcomms_flock(int fd, int op);
int  dcomms_random_bytes(void *buf, size_t size);
int  dcomms_open_private(const char *path);
void dcomms_wsa_init(void);
void dcomms_wsa_cleanup(void);

#endif /* DCOMMS_COMPAT_H */
