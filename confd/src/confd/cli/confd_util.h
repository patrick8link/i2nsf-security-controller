#ifndef _CONFD_UTIL_H_
#define _CONFD_UTIL_H_

#include <grp.h>
#include <pwd.h>

#ifdef __GNUC__
#define PRINTF(F,A) __attribute__ ((format (printf, F, A)))
#else
#define PRINTF(F,A)
#endif

extern int confd_snprintf(char *src, int size, char *format, ...) PRINTF(3,4);
extern int confd_strncpy(char *dst, int dst_len, const void *src, int src_len);
extern int confd_strlcpy(char *dest, const char *src, int size);

extern void *confd_xmalloc(size_t size);
extern void *confd_xrealloc(void *data, size_t size);

extern int confd_get_group_name_len(const gid_t *list, const int n,
                                    char **buf, ssize_t *bufsize);
extern char *confd_build_group_names(const gid_t *list, const int n,
                                     const size_t size, char **buf,
                                     ssize_t *bufsize);

extern int confd_get_pwnam(const char* id, struct passwd *in,
                           char **buf, ssize_t *buflen, struct passwd **out);

extern int confd_get_pwuid(uid_t id, struct passwd *in,
                           char **buf, ssize_t *buflen, struct passwd **out);

extern int confd_get_group(gid_t id, struct group *in,
                           char **buf, ssize_t *buflen, struct group **out);

extern int confd_get_group_name(const char* id, struct group *in,
                                char **buf, ssize_t *buflen,
                                struct group **out);

extern ssize_t confd_sysconf_size(ssize_t start_size);

#endif
