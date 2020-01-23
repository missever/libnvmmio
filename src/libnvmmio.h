#ifndef _LIBNVMMIO_H
#define _LIBNVMMIO_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <sys/types.h>
#include "libnvmmio-rw.h"

extern void init_libnvmmio(void);

/* Memory mapped file I/O interfaces */
extern void *nvmmap(void *addr, size_t length, int prot, int flags, int fd,
                    off_t offset);
extern int nvmunmap(void *addr, size_t length);
extern void *nvmemcpy(void *dest, const void *src, size_t n);
extern int nvmsync(void *addr, size_t length, int flags);
extern int nvmemcmp(const void *s1, const void *s2, size_t n);
extern void *nvmemset(void *s, int c, size_t n);
extern int nvstrcmp(const char *s1, const char *s2);
extern char *nvstrchr(const char *s, int c);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // _LIBNVMMIO_H