#ifndef _LIBNVMMIO_NVMMIO_H
#define _LIBNVMMIO_NVMMIO_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <sys/types.h>
#include "uma.h"

void init_libnvmmio(void);

/* Memory mapped file I/O interfaces */
void *nvmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int nvmunmap(void *addr, size_t length);
void *nvmemcpy(void *dest, const void *src, size_t n);
int nvmsync(void *addr, size_t length, int flags);
int nvmemcmp(const void *s1, const void *s2, size_t n);
void *nvmemset(void *s, int c, size_t n);
int nvstrcmp(const char *s1, const char *s2);
char *nvstrchr(const char *s, int c);

void nvmmio_memcpy(void *, const void *, size_t);
void nvmemcpy_write(void *, const void *, size_t, struct mmap_area_struct *);
void nvmemcpy_read_redo(void *, const void *, size_t);
int nvmsync_uma(void *, size_t, int, uma_t *);
int nvmunmap_uma(void *, size_t, struct mmap_area_struct *);
void close_sync_thread(struct mmap_area_struct *);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* _LIBNVMMIO_NVMMIO_H */
