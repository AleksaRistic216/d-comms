#ifndef DCOMMS_TEST_COMPAT_H
#define DCOMMS_TEST_COMPAT_H

#ifdef _WIN32
#  include <direct.h>
#  include <io.h>
#  define chdir       _chdir
#  define getcwd(b,s) _getcwd(b, (int)(s))
#  define unlink      _unlink
#  define rmdir       _rmdir

static inline char *mkdtemp(char *tmpl)
{
    if (_mktemp_s(tmpl, strlen(tmpl) + 1) != 0) return NULL;
    if (_mkdir(tmpl) != 0) return NULL;
    return tmpl;
}

#  define DCOMMS_TEST_TMPDIR "%TEMP%\\dcomms_ptest_XXXXXX"
#else
#  define DCOMMS_TEST_TMPDIR "/tmp/dcomms_ptest_XXXXXX"
#endif

#endif /* DCOMMS_TEST_COMPAT_H */
