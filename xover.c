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
#include <sys/syscall.h>
#include <ftw.h>

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
    struct dirent *(*readdir_func)(DIR *);
    struct dirent64 *(*readdir64_func)(DIR *);
    int (*scandir_func)(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **));
    int (*scandir64_func)(const char *, struct dirent64 ***, int (*)(const struct dirent64 *), int (*)(const struct dirent64 **, const struct dirent64 **));
    int (*getdents_func)(int, struct dirent *, unsigned int);
    long (*getdents64_func)(int, void *, unsigned long);
    #ifdef FTW
    int (*ftw_func)(const char *, int (*)(const char *, const struct stat *, int), int);
    int (*nftw_func)(const char *, int (*)(const char *, const struct stat *, int, struct FTW *), int, int);
    #endif
    ssize_t (*readlink_func)(const char *, char *, size_t);
    ssize_t (*readlinkat_func)(int, const char *, char *, size_t);
    int (*closedir_func)(DIR *);
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

/* MISC */
#define BLUE "\x1b[0;34m"
#define YELLOW "\x1b[0;33m"
#define RED "\x1b[31m"
#define RESET "\x1b[m"

/* cfg limits */
#define MAXPATH 4096
#define MAXOVERRIDES 128

/* Global cfg state */
struct xover_cfg {
    char paths_from[MAXOVERRIDES][MAXPATH];
    char paths_to[MAXOVERRIDES][MAXPATH];
    int n_overrides;
    int do_absolutize;
    int DEBUG_MODE_VAR;
    int is_initialized;
};

#ifndef DEBUG_BUILD
#define DEBUG_BUILD 0
#endif
#define DEBUG_FLAG DEBUG_BUILD

static struct xover_cfg config = {
    .n_overrides = 0,
    .do_absolutize = 1,
    .DEBUG_MODE_VAR = DEBUG_FLAG,
    .is_initialized = 0
};

/* Original function pointers */
static struct {
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
    struct dirent *(*readdir)(DIR *dirp);
    struct dirent64 *(*readdir64)(DIR *dirp);
    int (*scandir)(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **));
    int (*scandir64)(const char *, struct dirent64 ***, int (*)(const struct dirent64 *), int (*)(const struct dirent64 **, const struct dirent64 **));
    int (*getdents)(int, struct dirent *, unsigned int);
    long (*getdents64)(int, void *, unsigned long);
    int (*ftw)(const char *, int (*)(const char *, const struct stat *, int), int);
    int (*nftw)(const char *, int (*)(const char *, const struct stat *, int, struct FTW *), int, int);
    ssize_t (*readlink)(const char *pathname, char *buf, size_t bufsiz);
    ssize_t (*readlinkat)(int dirfd, const char *pathname, char *buf, size_t bufsiz);
    int (*closedir)(DIR *dirp);
} orig = {0};

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
                if (config.DEBUG_MODE_VAR >= 1) {
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

/* Check if path starts with prefix, handling trailing slashes */
static int path_starts_with(const char *path, const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    size_t path_len = strlen(path);

    /* Path must be at least as long as prefix */
    if (path_len < prefix_len) {
        return 0;
    }

    /* Check if prefix matches */
    if (strncmp(path, prefix, prefix_len) != 0) {
        return 0;
    }

    /* If path is exactly the prefix, it matches */
    if (path_len == prefix_len) {
        return 1;
    }

    /* If prefix ends with '/', path can continue with anything */
    if (prefix[prefix_len - 1] == '/') {
        return 1;
    }

    /* If path continues with '/', it's a subdirectory */
    if (path[prefix_len] == '/') {
        return 1;
    }

    return 0;
}

static const char *resolve_path(const char *pathname, int dirfd, char *pathbuf, size_t pathbuf_size)
{
    const char *resolved = pathname;
    static char result_buf[MAXPATH];

    if (config.do_absolutize) {
        if (absolutize_path(pathbuf, pathbuf_size, pathname, dirfd) == -1) {
            fprintf(stderr, "xover: error: failed to absolutize path %s\n", pathname);
            return NULL;
        }
        resolved = pathbuf;

        if (config.DEBUG_MODE_VAR >= 2) {
            fprintf(stderr, "xover: absolutized: %s\n", resolved);
        }
    }

    /* Look up override - check both exact matches and directory prefixes */
    for (int i = 0; i < config.n_overrides; i++) {
        if (strcmp(resolved, config.paths_from[i]) == 0) {
            /* Exact match */
            resolved = config.paths_to[i];
            if (config.DEBUG_MODE_VAR >= 1) {
                fprintf(stderr, "xover: %sexact match%s: %s%s%s -> %s%s%s\n",
                       RED, RESET, BLUE, config.paths_from[i], RESET, BLUE, resolved, RESET);
            }
            break;
        } else if (path_starts_with(resolved, config.paths_from[i])) {
            /* Directory prefix match */
            size_t from_len = strlen(config.paths_from[i]);
            size_t to_len = strlen(config.paths_to[i]);

            /* Calculate remaining part after the prefix */
            const char *remaining = resolved + from_len;

            /* Remove leading slash from remaining if prefix doesn't end with slash */
            if (remaining[0] == '/' && config.paths_from[i][from_len-1] != '/') {
                remaining++;
            }

            /* Build new path: to_path + remaining */
            if (to_len + strlen(remaining) + 2 >= sizeof(result_buf)) {
                fprintf(stderr, "xover: error: path too long for %s and %s\n", config.paths_to[i], remaining);
                errno = ERANGE;
                return NULL;
            }

            strcpy(result_buf, config.paths_to[i]);

            /* Add separator if needed */
            if (strlen(remaining) > 0) {
                if (result_buf[to_len-1] != '/' && remaining[0] != '/') {
                    strcat(result_buf, "/");
                }
                strcat(result_buf, remaining);
            }

            resolved = result_buf;

            if (config.DEBUG_MODE_VAR >= 1) {
                fprintf(stderr, "xover: %sdir match%s: %s%s%s -> %s%s%s\n",
                       RED, RESET, BLUE, pathname, RESET, BLUE, resolved, RESET);
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
        if (config.DEBUG_MODE_VAR >= 1) {
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
                    config.DEBUG_MODE_VAR = 1;
                } else if (strcmp(buffer, "noabs") == 0) {
                    config.do_absolutize = 0;
                } else if (strlen(buffer) > 0) {
                    fprintf(stderr, "xover: error: invalid flag '%s'\n", buffer);
                    return;
                }
            } else {
                strncpy(config.paths_to[config.n_overrides], buffer, MAXPATH-1);
                config.paths_to[config.n_overrides][MAXPATH-1] = '\0';

                if (config.DEBUG_MODE_VAR >= 1) {
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

    if (config.DEBUG_MODE_VAR >= 3) {
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

/* Stat family implementations */
static int xover_stat(const char *pathname, struct stat *statbuf)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 3) {
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

    if (config.DEBUG_MODE_VAR >= 3) {
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

    if (config.DEBUG_MODE_VAR >= 3) {
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

    if (config.DEBUG_MODE_VAR >= 3) {
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

    if (config.DEBUG_MODE_VAR >= 3) {
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

    if (config.DEBUG_MODE_VAR >= 2) {
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

    if (config.DEBUG_MODE_VAR >= 2) {
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

    if (config.DEBUG_MODE_VAR >= 2) {
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

    if (config.DEBUG_MODE_VAR >= 2) {
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

    if (config.DEBUG_MODE_VAR >= 2) {
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

    DIR *dir = orig.opendir(resolved);
    if (dir && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: opendir: opened %s (resolved to %s)\n", pathname, resolved);
    }
    return dir;
}

/* Wrapper structure to store original path for directory operations */
struct dir_wrapper {
    DIR *dirp;
    char orig_path[MAXPATH];
};

/* Global storage for directory wrappers */
#define MAX_DIRS 128
static struct dir_wrapper dir_wrappers[MAX_DIRS];
static int n_dir_wrappers = 0;

/* Find or create a directory wrapper */
static struct dir_wrapper *get_dir_wrapper(DIR *dirp, const char *orig_path)
{
    for (int i = 0; i < n_dir_wrappers; i++) {
        if (dir_wrappers[i].dirp == dirp) {
            return &dir_wrappers[i];
        }
    }

    if (n_dir_wrappers >= MAX_DIRS) {
        errno = ENOMEM;
        return NULL;
    }

    struct dir_wrapper *wrapper = &dir_wrappers[n_dir_wrappers++];
    wrapper->dirp = dirp;
    if (orig_path) {
        strncpy(wrapper->orig_path, orig_path, MAXPATH-1);
        wrapper->orig_path[MAXPATH-1] = '\0';
    } else {
        wrapper->orig_path[0] = '\0';
    }
    return wrapper;
}

/* Remove a directory wrapper */
static void remove_dir_wrapper(DIR *dirp)
{
    for (int i = 0; i < n_dir_wrappers; i++) {
        if (dir_wrappers[i].dirp == dirp) {
            dir_wrappers[i] = dir_wrappers[n_dir_wrappers-1];
            n_dir_wrappers--;
            break;
        }
    }
}

static struct dirent *xover_readdir(DIR *dirp)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return NULL;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: readdir: called\n");
    }

    if (!orig.readdir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("readdir");
        orig.readdir = u.readdir_func;
        if (!orig.readdir) return NULL;
    }

    struct dirent *entry = orig.readdir(dirp);
    if (entry && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: readdir: returned entry %s\n", entry->d_name);
    }

    if (entry) {
        struct dir_wrapper *wrapper = get_dir_wrapper(dirp, NULL);
        if (wrapper && wrapper->orig_path[0] != '\0') {
            /* Check if this directory was opened with a redirected path */
            for (int i = 0; i < config.n_overrides; i++) {
                if (strcmp(wrapper->orig_path, config.paths_from[i]) == 0) {
                    /* This is a redirected directory, we need to modify the entry */
                    char new_path[MAXPATH];
                    snprintf(new_path, MAXPATH, "%s/%s", config.paths_to[i], entry->d_name);
                    /* For readdir, we just return the original entry as is */
                    break;
                }
            }
        }
    }

    return entry;
}

static struct dirent64 *xover_readdir64(DIR *dirp)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return NULL;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: readdir64: called\n");
    }

    if (!orig.readdir64) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("readdir64");
        orig.readdir64 = u.readdir64_func;
        if (!orig.readdir64) return NULL;
    }

    struct dirent64 *entry = orig.readdir64(dirp);
    if (entry && config.DEBUG_MODE_VAR >= 2) {
        // Cast to struct dirent* to safely access d_name
        struct dirent *dirent_entry = (struct dirent *)entry;
        fprintf(stderr, "xover: readdir64: returned entry %s\n", dirent_entry->d_name);
    }

    return entry;
}

static int xover_scandir(const char *pathname, struct dirent ***namelist,
                         int (*select)(const struct dirent *),
                         int (*compar)(const struct dirent **, const struct dirent **))
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: scandir: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.scandir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("scandir");
        orig.scandir = u.scandir_func;
        if (!orig.scandir) return -1;
    }

    int ret = orig.scandir(resolved, namelist, select, compar);
    if (ret >= 0 && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: scandir: found %d entries\n", ret);
    }

    return ret;
}

static int xover_scandir64(const char *pathname, struct dirent64 ***namelist,
                           int (*select)(const struct dirent64 *),
                           int (*compar)(const struct dirent64 **, const struct dirent64 **))
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: scandir64: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.scandir64) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("scandir64");
        orig.scandir64 = u.scandir64_func;
        if (!orig.scandir64) return -1;
    }

    int ret = orig.scandir64(resolved, namelist, select, compar);
    if (ret >= 0 && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: scandir64: found %d entries\n", ret);
    }

    return ret;
}

static int xover_getdents(int fd, struct dirent *dirp, unsigned int count)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: getdents: fd=%d, count=%u\n", fd, count);
    }

    if (!orig.getdents) {
        func_ptr_union u;
        u.void_ptr = dlsym(RTLD_NEXT, "getdents");
        if (!u.void_ptr) {
            u.getdents_func = NULL;
        }
        orig.getdents = u.getdents_func;
        if (!orig.getdents) return -1;
    }

    int ret = orig.getdents(fd, dirp, count);

    if (ret > 0 && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: getdents: returned %d bytes\n", ret);
    }

    return ret;
}

static long xover_getdents64(int fd, void *dirp, unsigned long count)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: getdents64: fd=%d, count=%lu\n", fd, count);
    }

    if (!orig.getdents64) {
        func_ptr_union u;
        u.void_ptr = dlsym(RTLD_NEXT, "getdents64");
        if (!u.void_ptr) {
            u.getdents64_func = NULL;
        }
        orig.getdents64 = u.getdents64_func;
        if (!orig.getdents64) return -1;
    }

    long ret = orig.getdents64(fd, dirp, count);

    if (ret > 0 && config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: getdents64: returned %ld bytes\n", ret);
    }

    return ret;
}

#ifdef FTW
static int xover_ftw(const char *pathname, int (*fn)(const char *, const struct stat *, int), int nopenfd)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: ftw: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.ftw) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("ftw");
        orig.ftw = u.ftw_func;
        if (!orig.ftw) return -1;
    }

    return orig.ftw(resolved, fn, nopenfd);
}

static int xover_nftw(const char *pathname, int (*fn)(const char *, const struct stat *, int, struct FTW *), int nopenfd, int flags)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: nftw: %s\n", pathname);
    }

    char pathbuf[MAXPATH];
    const char *resolved = resolve_path(pathname, AT_FDCWD, pathbuf, sizeof(pathbuf));
    if (!resolved) {
        return -1;
    }

    if (!orig.nftw) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("nftw");
        orig.nftw = u.nftw_func;
        if (!orig.nftw) return -1;
    }

    return orig.nftw(resolved, fn, nopenfd, flags);
}
#endif

/* Symlink operation implementations */
static ssize_t xover_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 3) {
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

    ssize_t ret = orig.readlink(resolved, buf, bufsiz);
    if (ret >= 0) {
        /* Check if the readlink result needs to be redirected back */
        for (int i = 0; i < config.n_overrides; i++) {
            if (path_starts_with(buf, config.paths_to[i])) {
                size_t to_len = strlen(config.paths_to[i]);
                size_t from_len = strlen(config.paths_from[i]);
                char new_buf[MAXPATH];
                if (to_len + strlen(buf + to_len) + from_len + 2 >= bufsiz) {
                    errno = ERANGE;
                    return -1;
                }
                strcpy(new_buf, config.paths_from[i]);
                if (buf[to_len] == '/') {
                    strcat(new_buf, buf + to_len);
                } else if (new_buf[from_len-1] != '/') {
                    strcat(new_buf, "/");
                    strcat(new_buf, buf + to_len);
                } else {
                    strcat(new_buf, buf + to_len);
                }
                strncpy(buf, new_buf, bufsiz);
                ret = strlen(buf);
                break;
            }
        }
    }
    return ret;
}

static ssize_t xover_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 3) {
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

    ssize_t ret = orig.readlinkat(dirfd, resolved, buf, bufsiz);
    if (ret >= 0) {
        /* Check if the readlinkat result needs to be redirected back */
        for (int i = 0; i < config.n_overrides; i++) {
            if (path_starts_with(buf, config.paths_to[i])) {
                size_t to_len = strlen(config.paths_to[i]);
                size_t from_len = strlen(config.paths_from[i]);
                char new_buf[MAXPATH];
                if (to_len + strlen(buf + to_len) + from_len + 2 >= bufsiz) {
                    errno = ERANGE;
                    return -1;
                }
                strcpy(new_buf, config.paths_from[i]);
                if (buf[to_len] == '/') {
                    strcat(new_buf, buf + to_len);
                } else if (new_buf[from_len-1] != '/') {
                    strcat(new_buf, "/");
                    strcat(new_buf, buf + to_len);
                } else {
                    strcat(new_buf, buf + to_len);
                }
                strncpy(buf, new_buf, bufsiz);
                ret = strlen(buf);
                break;
            }
        }
    }
    return ret;
}

/* Closedir implementation */
static int xover_closedir(DIR *dirp)
{
    if (!config.is_initialized) {
        parse_config();
    }
    if (!config.is_initialized) {
        return -1;
    }

    if (config.DEBUG_MODE_VAR >= 2) {
        fprintf(stderr, "xover: closedir: called\n");
    }

    if (!orig.closedir) {
        func_ptr_union u;
        u.void_ptr = get_orig_func("closedir");
        orig.closedir = u.closedir_func;
        if (!orig.closedir) return -1;
    }

    remove_dir_wrapper(dirp);
    return orig.closedir(dirp);
}

/* Public API implementations */
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
    DIR *dir = xover_opendir(pathname);
    if (dir) {
        get_dir_wrapper(dir, pathname);
    }
    return dir;
}

struct dirent *readdir(DIR *dirp)
{
    return xover_readdir(dirp);
}

struct dirent64 *readdir64(DIR *dirp)
{
    return xover_readdir64(dirp);
}

int scandir(const char *pathname, struct dirent ***namelist,
            int (*select)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
{
    return xover_scandir(pathname, namelist, select, compar);
}

int scandir64(const char *pathname, struct dirent64 ***namelist,
              int (*select)(const struct dirent64 *),
              int (*compar)(const struct dirent64 **, const struct dirent64 **))
{
    return xover_scandir64(pathname, namelist, select, compar);
}

int getdents(int fd, struct dirent *dirp, size_t count)
{
    return xover_getdents(fd, dirp, count);
}

long getdents64(int fd, void *dirp, unsigned long count)
{
    return xover_getdents64(fd, dirp, count);
}

#ifdef FTW
int ftw(const char *pathname, int (*fn)(const char *, const struct stat *, int), int nopenfd)
{
    return xover_ftw(pathname, fn, nopenfd);
}

int nftw(const char *pathname, int (*fn)(const char *, const struct stat *, int, struct FTW *), int nopenfd, int flags)
{
    return xover_nftw(pathname, fn, nopenfd, flags);
}
#endif

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    return xover_readlink(pathname, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    return xover_readlinkat(dirfd, pathname, buf, bufsiz);
}

int closedir(DIR *dirp)
{
    return xover_closedir(dirp);
}
