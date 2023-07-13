#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#include "confd_util.h"

/**
 * Function definition used for password and group information family
 * of functions that take user sized buffer and can return ERANGE in
 * case the buffer is too small.
 */
#define PWBUF_FUN(NAME, ID_TYPE, STRUCT_TYPE, FUN)                         \
    extern int NAME(ID_TYPE id, struct STRUCT_TYPE *in,                    \
                    char **buf, ssize_t *buflen, struct STRUCT_TYPE **out) \
    {                                                                      \
        *out = NULL;                                                       \
        int ret = FUN(id, in, *buf, *buflen, out);                         \
        while (ret == EINTR || ret == ERANGE) {                            \
            if (errno == ERANGE) {                                         \
                /* buffer was not big enough, grow */                      \
                *buflen = *buflen + 4096;                                  \
                *buf = confd_xrealloc(*buf, *buflen);                      \
            }                                                              \
            ret = FUN(id, in, *buf, *buflen, out);                         \
        }                                                                  \
        return *out == NULL ? 1 : 0;                                       \
    }

PWBUF_FUN(confd_get_pwnam, const char*, passwd, getpwnam_r);
PWBUF_FUN(confd_get_pwuid, uid_t, passwd, getpwuid_r);
PWBUF_FUN(confd_get_group, gid_t, group, getgrgid_r);
PWBUF_FUN(confd_get_group_name, const char*, group, getgrnam_r);

/* a version of snprintf that accepts negative n for size */
/* and treats it as zero                                  */
int confd_snprintf(char *str, int size, char *format, ...)
{
    va_list args;
    int ret;

    if (size < 0) {
        size = 0;
    }
    va_start(args, format);
    ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

/*  Like a mix of strncpy() and memcpy(). If src_len is less than zero
    it is treated as zero. If src_len is less than dest_len everything
    (src_len) will be copied. If src_len is greater than or equal to
    dest_len the result will be truncated. null is always added to the
    end of dest unless dest_len < 1. The return value of the function
    is the number of bytes copied (excluding null). Note that unlike
    strncpy() this function does not check for null inside src, nor
    does it fill the remaining part of dest with null. */
int confd_strncpy(char *dest, int dest_len, const void *src, int src_len)
{
    if (src_len < 0) {
        src_len = 0;
    }
    if (src_len < dest_len) {
        memcpy(dest, src, src_len);
        dest[src_len] = '\0';
        return src_len;
    }
    if (dest_len > 0) {
        memcpy(dest, src, dest_len - 1);
        dest[dest_len-1] = '\0';
        return dest_len - 1;
    }
    return 0;
}

/*  This function is similar to strncpy(), but it copies at most
    size-1 bytes to dest, always adds a terminating null byte (unless
    size is zero) and does not pad the destination with (further) null
    bytes.  This function fixes some of the problems of strcpy() and
    strncpy(), but the caller must still handle the possibility of
    data loss if size is too small.  The return value of the function
    is the length of src, which allows truncation to be easily
    detected: if the return value is greater than or equal to size,
    truncation occurred.  If loss of data matters, the caller must
    either check the arguments before the call, or test the function
    return value.  strlcpy() is not present in glibc and is not
    standardized by POSIX, so we provide an implementation here. A
    difference between the BSD version and this is that size is
    defined as int (size_t on BSD). This allow size to negative which
    is treated as zero. */
int confd_strlcpy(char *dest, const char *src, int size)
{
    const char *ps = src;

    if (size < 0) {
        size = 0;
    }
    if (size) {
        while (--size && *ps) {
            *dest++ = *ps++;
        }
        *dest = 0;
    }
    if (size == 0) {
        while (*ps) {
            ps++;
        }
    }
    return ps - src;
}

extern void *confd_xmalloc(size_t size)
{
    void *data = malloc(size);
    if (data == NULL) {
        fprintf(stderr, "Error: failed to allocate memory\n");
        exit(1);
    }
    return data;
}

extern void *confd_xrealloc(void *data, size_t size)
{
    data = realloc(data, size);
    if (data == NULL) {
        fprintf(stderr, "Error: failed to re-allocate memory\n");
        exit(1);
    }
    return data;
}

extern int confd_get_group_name_len(const gid_t *list, const int n,
                                    char **buf, ssize_t *bufsize)
{
    int size = 0;
    struct group group;
    struct group *g = NULL;
    for(int i=0 ; i < n ; i++) {
        if (!confd_get_group(list[i], &group, buf, bufsize, &g)) {
            size += strlen(g->gr_name) + 1;
        }
    }
    return size;
}

extern char *confd_build_group_names(const gid_t *list, const int n,
                                     const size_t size, char **buf,
                                     ssize_t *bufsize)
{
    if (size == 0) {
        return strdup("");
    }

    char *groups = confd_xmalloc(size);
    int num_written = 0;

    struct group group;
    struct group *g = NULL;

    for(int i=0; i < n; i++) {
        if (!confd_get_group(list[i], &group, buf, bufsize, &g)) {
            num_written += confd_strlcpy(groups + num_written,
                                         g->gr_name, size - num_written);
            if (i != n - 1) {
                num_written += confd_strlcpy(groups + num_written,
                                             ",", size - num_written);
            }
        }
    }

    return groups;
}

extern ssize_t confd_sysconf_size(ssize_t start_size) {
    ssize_t bufsize = sysconf(start_size);
    if (bufsize == -1) {
        bufsize = 4096; /* really huge (from Mac) */
    }
    return bufsize;
}
