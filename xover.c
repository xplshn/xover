#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>

typedef union {
    void *void_ptr;
    int (*openat_func)(int, const char *, int, mode_t);
    int (*stat_func)(const char *, struct stat *);
    int (*lstat_func)(const char *, struct stat *);
    int (*fstatat_func)(int, const char *, struct stat *, int);
    int (*access_func)(const char *, int);
    int (*faccessat_func)(int, const char *, int, int);
    int (*mkdir_func)(const char *, mode_t);
    int (*mkdirat_func)(int, const char *, mode_t);
    int (*rmdir_func)(const char *);
    int (*unlinkat_func)(int, const char *, int);
    DIR *(*opendir_func)(const char *);
    ssize_t (*readlink_func)(const char *, char *, size_t);
    ssize_t (*readlinkat_func)(int, const char *, char *, size_t);
} func_ptr_union;

/* File access flags */
#define O_RDONLY        00
#define O_WRONLY        01
#define O_RDWR          02
#define O_CREAT         0100
#define O_EXCL          0200
#define O_TRUNC         01000
#define O_APPEND        02000
#define O_LARGEFILE     0100000
#define O_CLOEXEC       02000000

/* AT_* constants for *at functions */
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

/* cfg limits */
#define MAXPATH 4096
#define MAXOVERRIDES 128

/* Global cfg state */
struct xover_cfg {
    char paths_from[MAXOVERRIDES][MAXPATH];
    char paths_to[MAXOVERRIDES][MAXPATH];
    int n_overrides;
    int do_absolutize;
    int do_debug;
    int is_initialized;
};

#ifndef DEBUG_BUILD
#define DEBUG_BUILD 0
#endif
#define DEBUG_FLAG DEBUG_BUILD

static struct xover_cfg config = {
    .n_overrides = 0,
    .do_absolutize = 1,
    .do_debug = DEBUG_FLAG,
    .is_initialized = 0
};

/* Original function pointers */
struct orig_funcs {
    int (*openat)(int dirfd, const char *pathname, int flags, mode_t mode);
    int (*stat)(const char *pathname, struct stat *statbuf);
    int (*lstat)(const char *pathname, struct stat *statbuf);
    int (*fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
    int (*access)(const char *pathname, int mode);
    int (*faccessat)(int dirfd, const char *pathname, int mode, int flags);
    int (*mkdir)(const char *pathname, mode_t mode);
    int (*mkdirat)(int dirfd, const char *pathname, mode_t mode);
    int (*rmdir)(const char *pathname);
    int (*unlinkat)(int dirfd, const char *pathname, int flags);
    DIR *(*opendir)(const char *name);
    ssize_t (*readlink)(const char *pathname, char *buf, size_t bufsiz);
    ssize_t (*readlinkat)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
};

static struct orig_funcs orig = {0};

/* Convert fopen mode string to open flags */
static int mode_to_flags(const char *mode)
{
    int flags;

    if (strchr(mode, '+'))
        flags = O_RDWR;
    else if (*mode == 'r')
        flags = O_RDONLY;
    else
        flags = O_WRONLY;

    if (strchr(mode, 'x')) flags |= O_EXCL;
    if (strchr(mode, 'e')) flags |= O_CLOEXEC;
    if (*mode != 'r') flags |= O_CREAT;
    if (*mode == 'w') flags |= O_TRUNC;
    if (*mode == 'a') flags |= O_APPEND;

    return flags;
}

/* Convert relative path to absolute path */
static int absolutize_path(char *outpath, int outpath_size, const char *pathname, int dirfd)
{
    if (pathname[0] != '/') {
        /* Handle relative path */
        int len;

        if (dirfd == AT_FDCWD) {
            if (!getcwd(outpath, outpath_size)) {
                return -1;
            }
            len = strlen(outpath);
        } else {
            char proc_path[128];
            snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);

            ssize_t ret = readlink(proc_path, outpath, outpath_size - 1);
            if (ret == -1) {
                if (config.do_debug) {
                    fprintf(stderr, "xover: warning: cannot readlink %s, assuming root\n", proc_path);
                }
                len = 0;
            } else {
                len = ret;
                outpath[len] = '\0';
            }
        }

        /* Add trailing slash if needed */
        if (len > 0 && outpath[len-1] != '/') {
            outpath[len] = '/';
            len++;
        }

        /* Append pathname */
        size_t pathname_len = strlen(pathname);
        if (len + pathname_len >= outpath_size) {
            errno = ERANGE;
            return -1;
        }

        strcpy(outpath + len, pathname);
    } else {
        /* Handle absolute path */
        if (strlen(pathname) >= outpath_size) {
            errno = ERANGE;
            return -1;
        }
        strcpy(outpath, pathname);
    }

    return 0;
}

/* Resolve path through override table */
static const char *resolve_path(const char *pathname, int dirfd, char *pathbuf, size_t pathbuf_size)
{
    const char *resolved = pathname;

    if (config.do_absolutize) {
        if (absolutize_path(pathbuf, pathbuf_size, pathname, dirfd) == -1) {
            return NULL;
        }
        resolved = pathbuf;

        if (config.do_debug) {
            fprintf(stderr, "xover: absolutized: %s\n", resolved);
        }
    }

    /* Look up override */
    for (int i = 0; i < config.n_overrides; i++) {
        if (strcmp(resolved, config.paths_from[i]) == 0) {
            resolved = config.paths_to[i];
            if (config.do_debug) {
                fprintf(stderr, "xover: overridden: %s\n", resolved);
            }
            break;
        }
    }

    return resolved;
}

/* Parse configuration from environment */
static void parse_config(void)
{
    const char *env = getenv("XOVER");
    if (!env) {
        if (config.do_debug) {
            fprintf(stderr, "Usage: LD_PRELOAD=libxover.so XOVER=/path/from=/path/to,/path2/from=/path2/to program [args...]\n");
            fprintf(stderr, "    Special flags: debug, noabs\n");
            fprintf(stderr, "    Use backslash to escape commas and equals\n");
        }
        config.is_initialized = 1;
        return;
    }

    char buffer[MAXPATH];
    int buffer_pos = 0;
    int parsing_key = 1;

    for (;;) {
        if (config.n_overrides >= MAXOVERRIDES) {
            fprintf(stderr, "xover: error: maximum overrides exceeded\n");
            return;
        }

        char c = *env;
        switch (c) {
        case '=':
            if (parsing_key) {
                buffer[buffer_pos] = '\0';
                strncpy(config.paths_from[config.n_overrides], buffer, MAXPATH-1);
                config.paths_from[config.n_overrides][MAXPATH-1] = '\0';
                buffer_pos = 0;
                parsing_key = 0;
            } else {
                fprintf(stderr, "xover: error: unexpected '=' in value\n");
                return;
            }
            break;

        case ',':
        case '\0':
            buffer[buffer_pos] = '\0';

            if (parsing_key) {
                if (strcmp(buffer, "debug") == 0) {
                    config.do_debug = 1;
                } else if (strcmp(buffer, "noabs") == 0) {
                    config.do_absolutize = 0;
                } else if (strlen(buffer) > 0) {
                    fprintf(stderr, "xover: error: invalid flag '%s'\n", buffer);
                    return;
                }
            } else {
                strncpy(config.paths_to[config.n_overrides], buffer, MAXPATH-1);
                config.paths_to[config.n_overrides][MAXPATH-1] = '\0';

                if (config.do_debug) {
                    fprintf(stderr, "xover: mapping: %s -> %s\n",
                           config.paths_from[config.n_overrides],
                           config.paths_to[config.n_overrides]);
                }
                config.n_overrides++;
                parsing_key = 1;
            }
            buffer_pos = 0;
            break;

        case '\\':
            env++;
            if (*env == '\0') break;
            /* fallthrough */
        default:
            if (buffer_pos >= MAXPATH - 1) {
                fprintf(stderr, "xover: error: path too long\n");
                return;
            }
            buffer[buffer_pos++] = c;
            break;
        }

        if (c == '\0') break;
        env++;
    }

    config.is_initialized = 1;
}

/* Get original function pointer */
static void *get_orig_func(const char *name)
{
    void *func = dlsym(RTLD_NEXT, name);
    if (!func) {
        errno = ENOSYS;
    }
    return func;
}

/* Core openat implementation */
static int xover_openat(int dirfd, const char *pathname, int flags, mode_t mode)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: openat: %s (dirfd=%d, flags=%d, mode=%o)\n",
               pathname, dirfd, flags, mode);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.openat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("openat");
        orig.openat = u.openat_func;
        if (!orig.openat) return -1;
    }

    return orig.openat(dirfd, resolved, flags, mode);
}

/* File operation implementations */
static int xover_open(const char *pathname, int flags, mode_t mode)
{
    return xover_openat(AT_FDCWD, pathname, flags, mode);
}

static FILE *xover_fopen(const char *pathname, const char *mode)
{
    int flags = mode_to_flags(mode) | O_LARGEFILE;
    int fd = xover_open(pathname, flags, 0666);
    if (fd == -1) {
        return NULL;
    }
    return fdopen(fd, mode);
}

/* Stat family implementations */
static int xover_stat(const char *pathname, struct stat *statbuf)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: stat: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.stat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("stat");
        orig.stat = u.stat_func;
        if (!orig.stat) return -1;
    }

    return orig.stat(resolved, statbuf);
}

static int xover_lstat(const char *pathname, struct stat *statbuf)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: lstat: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.lstat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("lstat");
        orig.lstat = u.lstat_func;
        if (!orig.lstat) return -1;
    }

    return orig.lstat(resolved, statbuf);
}

static int xover_fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: fstatat: %s (dirfd=%d, flags=%d)\n", pathname, dirfd, flags);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.fstatat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("fstatat");
        if (!u.void_ptr) {
            u.void_ptr = get_orig_func("newfstatat");
        }
        orig.fstatat = u.fstatat_func;
        if (!orig.fstatat) return -1;
    }

    return orig.fstatat(dirfd, resolved, statbuf, flags);
}

/* Access function implementations */
static int xover_access(const char *pathname, int mode)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: access: %s (mode=%d)\n", pathname, mode);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.access) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("access");
        orig.access = u.access_func;
        if (!orig.access) return -1;
    }

    return orig.access(resolved, mode);
}

static int xover_faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: faccessat: %s (dirfd=%d, mode=%d, flags=%d)\n",
               pathname, dirfd, mode, flags);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.faccessat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("faccessat");
        orig.faccessat = u.faccessat_func;
        if (!orig.faccessat) return -1;
    }

    return orig.faccessat(dirfd, resolved, mode, flags);
}

/* Directory operation implementations */
static int xover_mkdir(const char *pathname, mode_t mode)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: mkdir: %s (mode=%o)\n", pathname, mode);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.mkdir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("mkdir");
        orig.mkdir = u.mkdir_func;
        if (!orig.mkdir) return -1;
    }

    return orig.mkdir(resolved, mode);
}

static int xover_mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: mkdirat: %s (dirfd=%d, mode=%o)\n", pathname, dirfd, mode);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.mkdirat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("mkdirat");
        orig.mkdirat = u.mkdirat_func;
        if (!orig.mkdirat) return -1;
    }

    return orig.mkdirat(dirfd, resolved, mode);
}

static int xover_rmdir(const char *pathname)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: rmdir: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.rmdir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("rmdir");
        orig.rmdir = u.rmdir_func;
        if (!orig.rmdir) return -1;
    }

    return orig.rmdir(resolved);
}

static int xover_unlinkat(int dirfd, const char *pathname, int flags)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: unlinkat: %s (dirfd=%d, flags=%d)\n", pathname, dirfd, flags);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.unlinkat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("unlinkat");
        orig.unlinkat = u.unlinkat_func;
        if (!orig.unlinkat) return -1;
    }

    return orig.unlinkat(dirfd, resolved, flags);
}

static DIR *xover_opendir(const char *pathname)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return NULL;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: opendir: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return NULL;
    }

    if (!orig.opendir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("opendir");
        orig.opendir = u.opendir_func;
        if (!orig.opendir) return NULL;
    }

    return orig.opendir(resolved);
}

/* Symlink operation implementations */
static ssize_t xover_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: readlink: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.readlink) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("readlink");
        orig.readlink = u.readlink_func;
        if (!orig.readlink) return -1;
    }

    return orig.readlink(resolved, buf, bufsiz);
}

static ssize_t xover_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.do_debug) {
        fprintf(stderr, "xover: readlinkat: %s (dirfd=%d)\n", pathname, dirfd);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, dirfd, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.readlinkat) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("readlinkat");
        orig.readlinkat = u.readlinkat_func;
        if (!orig.readlinkat) return -1;
    }

    return orig.readlinkat(dirfd, resolved, buf, bufsiz);
}

/* Public API implementations with proper variadic handling */
int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return xover_open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return xover_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return xover_openat(dirfd, pathname, flags, mode);
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return xover_openat(dirfd, pathname, flags, mode);
}

int creat(const char *pathname, mode_t mode)
{
    return xover_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

int creat64(const char *pathname, mode_t mode)
{
    return xover_open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode);
}

FILE *fopen(const char *pathname, const char *mode)
{
    return xover_fopen(pathname, mode);
}

FILE *fopen64(const char *pathname, const char *mode)
{
    return xover_fopen(pathname, mode);
}

int stat(const char *pathname, struct stat *statbuf)
{
    return xover_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf)
{
    return xover_lstat(pathname, statbuf);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    return xover_fstatat(dirfd, pathname, statbuf, flags);
}

int newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{
    return xover_fstatat(dirfd, pathname, statbuf, flags);
}

int access(const char *pathname, int mode)
{
    return xover_access(pathname, mode);
}

int faccessat(int dirfd, const char *pathname, int mode, int flags)
{
    return xover_faccessat(dirfd, pathname, mode, flags);
}

int mkdir(const char *pathname, mode_t mode)
{
    return xover_mkdir(pathname, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    return xover_mkdirat(dirfd, pathname, mode);
}

int rmdir(const char *pathname)
{
    return xover_rmdir(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    return xover_unlinkat(dirfd, pathname, flags);
}

DIR *opendir(const char *pathname)
{
    return xover_opendir(pathname);
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return xover_readlink(pathname, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    return xover_readlinkat(dirfd, pathname, buf, bufsiz);
}
