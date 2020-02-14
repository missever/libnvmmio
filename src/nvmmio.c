#define _GNU_SOURCE

#include <fcntl.h>
#include <libpmem.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "nvmmio.h"
#include "allocator.h"
#include "internal.h"
#include "list.h"
#include "debug.h"

//#define O_ATOMIC 01000000000
//#define _USE_HYBRID_LOGGING
#define HYBRID_WRITE_RATIO (40)
#define MIN_FILESIZE (1UL << 26)

static inline void nvmmio_fence(void);
static inline void nvmmio_write(void *, const void *, size_t, bool);
static inline void nvmmio_flush(const void *, size_t, bool);
static inline void atomic_decrease(int *);
static inline void init_base_address(void);
static void sync_uma(uma_t *);
static void cleanup_handler(void);
static inline void *get_base_mmap_addr(void *, size_t);
static inline bool filter_addr(const void *);
static void *sync_thread_func(void *);
static void create_sync_thread(uma_t *);
static inline int check_overwrite(void *, void *, void *, void *);
static inline log_size_t set_log_size(size_t);
static void nvmsync_sync(void *, size_t, unsigned long);
static inline void nvmemcpy_f2f_write(void *, const void *, size_t, uma_t *, uma_t *);

static size_t nvstrlen_redo(char *, char *, bool *);
static void get_string_from_redo(char **, const char *);

static bool initialized = false;
static void *base_mmap_addr = NULL;
static void *min_addr = (void *)ULONG_MAX;
static void *max_addr = (void *)0UL;

static inline void nvmmio_fence(void) {
  LIBNVMMIO_INIT_TIME(nvmmio_fence_time);
  LIBNVMMIO_START_TIME(nvmmio_fence_t, nvmmio_fence_time);

  pmem_drain();

  LIBNVMMIO_END_TIME(nvmmio_fence_t, nvmmio_fence_time);
}

static inline void nvmmio_write(void *dest, const void *src, size_t n,
                                bool fence) {
  LIBNVMMIO_INIT_TIME(nvmmio_write_time);
  LIBNVMMIO_START_TIME(nvmmio_write_t, nvmmio_write_time);

  pmem_memcpy_nodrain(dest, src, n);

  if (fence) {
    nvmmio_fence();
  }

  LIBNVMMIO_END_TIME(nvmmio_write_t, nvmmio_write_time);
}

static inline void nvmmio_flush(const void *addr, size_t n, bool flush) {
  LIBNVMMIO_INIT_TIME(nvmmio_flush_time);
  LIBNVMMIO_START_TIME(nvmmio_flush_t, nvmmio_flush_time);

  pmem_flush(addr, n);

  if (flush) {
    nvmmio_fence();
  }

  LIBNVMMIO_END_TIME(nvmmio_flush_t, nvmmio_flush_time);
}

inline void nvmmio_memcpy(void *dst, const void *src, size_t n) {
  LIBNVMMIO_INIT_TIME(nvmmio_memcpy_time);
  LIBNVMMIO_START_TIME(nvmmio_memcpy_t, nvmmio_memcpy_time);

  memcpy(dst, src, n);

  LIBNVMMIO_END_TIME(nvmmio_memcpy_t, nvmmio_memcpy_time);
}

static inline void atomic_decrease(int *count) {
  int old, new;

  do {
    old = *count;
    new = *count - 1;
  } while (!__sync_bool_compare_and_swap(count, old, new));
}

static inline void init_base_address(void) {
  void *addr;

  if (base_mmap_addr == NULL) {
    addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (__glibc_unlikely(addr == MAP_FAILED)) {
      handle_error("mmap for base_mmap_addr");
    }

    base_mmap_addr = (void *)(addr - (1UL << 38)); /* 256 GB */
    base_mmap_addr = ALIGN_TABLE((base_mmap_addr + TABLE_SIZE));
    munmap(addr, PAGE_SIZE);
  }
}

static void sync_uma(uma_t *uma) {
  unsigned long address, current_epoch, end, i;
  unsigned long table_size = 1UL << 21;
  unsigned long nrlogs;
  log_table_t *table;
  log_entry_t *entry;
  log_size_t log_size;
  void *dst, *src;
  int s;

  /* Acquire the reader lock of the per-file metadata */
  s = pthread_rwlock_rdlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_rdlock");
  }

  /* get the necessary information from the per-file metadata */
  address = (unsigned long)(uma->start);
  end = (unsigned long)(uma->end);
  current_epoch = uma->epoch;

  /* Release the reader lock of the per-file metadata */
  s = pthread_rwlock_unlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }

  while (address < end) {
    table = find_log_table(address);

    if (table && table->count > 0) {
      log_size = table->log_size;
      nrlogs = NUM_ENTRIES(log_size);

      for (i = nrlogs - 1; i > 0; i--) {
        entry = table->entries[i];

        if (entry && entry->epoch < current_epoch) {
          /* Acquire the writer lock of the log entry */
          if (pthread_rwlock_trywrlock(entry->rwlockp) != 0) continue;

          /* Committed log entry */
          if (entry->epoch < current_epoch) {
            if (entry->policy == REDO) {
              dst = entry->dst + entry->offset;
              src = entry->data + entry->offset;

              nvmmio_write(dst, src, entry->len, true);
            }
            table->entries[i] = NULL;

            free_log_entry(entry, log_size, false);
            atomic_decrease(&table->count);
            continue;
          }

          /* Release the writer lock of the log entry */
          s = pthread_rwlock_unlock(entry->rwlockp);
          if (__glibc_unlikely(s != 0)) {
            handle_error("pthread_rwlock_unlock");
          }
        }
      }
    }
    address += table_size;
  }
}

static void cleanup_handler(void) {
  exit_background_table_alloc_thread();
	cleanup_logs();

	LIBNVMMIO_REPORT_TIME();
  return;
}

void init_libnvmmio(void) {
  if (__sync_bool_compare_and_swap(&initialized, false, true)) {
		LIBNVMMIO_INIT_TIMER();

    init_env();
    init_global_freelist();
    init_radixlog();
    init_uma();
    init_base_address();

    atexit(cleanup_handler);
  }
}

static inline void *get_base_mmap_addr(void *addr, size_t n) {
  void *old, *new;

  if (addr != NULL) {
    LIBNVMMIO_DEBUG("warning: addr is not NULL");
    return addr;
  }

  do {
    old = base_mmap_addr;
    new = (void *)ALIGN_TABLE((base_mmap_addr + (n + TABLE_SIZE)));
  } while (!__sync_bool_compare_and_swap(&base_mmap_addr, old, new));

  return old;
}

static inline bool filter_addr(const void *address) {
  return (min_addr <= address) && (address < max_addr);
}

void close_sync_thread(uma_t *uma) {
  int s;
  s = pthread_cancel(uma->sync_thread);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_cancel");
  }
}

static void *sync_thread_func(void *parm) {
  uma_t *uma;
  uma = (uma_t *)parm;

  LIBNVMMIO_DEBUG("%d uma thread start on %d", uma->id, sched_getcpu());

  while (true) {
    usleep(SYNC_PERIOD);
    sync_uma(uma);
  }
  return NULL;
}

static void create_sync_thread(uma_t *uma) {
  int s;

  s = pthread_create(&uma->sync_thread, NULL, sync_thread_func, uma);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_create");
  }
}

void *nvmmap(void *addr, size_t len, int prot, int flags, int fd,
             off_t offset) {
  void *mmap_addr;
  uma_t *uma;
  struct stat sb;
  int s;

  LIBNVMMIO_DEBUG("fd=%d", fd);

  if (__glibc_unlikely(!initialized)) {
    init_libnvmmio();
  }

  addr = get_base_mmap_addr(addr, len);
  flags |= MAP_POPULATE;

  mmap_addr = mmap(addr, len, prot, flags, fd, offset);
  if (__glibc_unlikely(mmap_addr == MAP_FAILED)) {
    handle_error("mmap");
  }

  s = fstat(fd, &sb);
  if (__glibc_unlikely(s != 0)) {
    handle_error("fstat");
  }

  uma = alloc_uma();

  s = pthread_rwlock_init(uma->rwlockp, NULL);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_init");
  }
  uma->start = mmap_addr;
  uma->end = mmap_addr + len;
  uma->ino = (unsigned long)sb.st_ino;
  uma->offset = offset;
  uma->epoch = 1;
  uma->policy = DEFAULT_POLICY;

  if (uma->policy == UNDO) {
    LIBNVMMIO_DEBUG("policy = UNDO");
	}
  else {
    LIBNVMMIO_DEBUG("policy = REDO");
	}

  create_sync_thread(uma);

  if (uma->start < min_addr) {
    min_addr = uma->start;
  }

  if (uma->end > max_addr) {
    max_addr = uma->end;
  }

  insert_uma_rbtree(uma);
  //insert_uma_syncthreads(uma);

  return mmap_addr;
}

int nvmunmap_uma(void *addr, size_t n, uma_t *uma) {
  if (__glibc_unlikely(uma == NULL)) {
    handle_error("find_uma() failed");
  }

  if (__glibc_unlikely(uma->start != addr || uma->end != (addr + n))) {
    handle_error("the uma must be splitted");
  }

  delete_uma_rbtree(uma);
  //delete_uma_syncthreads(uma);
  return munmap(addr, n);
}

int nvmunmap(void *addr, size_t n) {
  uma_t *uma = find_uma(addr);
	return nvmunmap_uma(addr, n, uma);
}

static void sync_entry(log_entry_t *entry, uma_t *uma) {
  void *dst, *src;

  if (entry->policy == REDO) {
    dst = entry->dst + entry->offset;
    src = entry->data + entry->offset;
    nvmmio_write(dst, src, entry->len, true);
  }
  entry->epoch = uma->epoch;
  entry->policy = uma->policy;
  entry->len = 0;
  entry->offset = 0;
  nvmmio_flush(entry, sizeof(log_entry_t), true);
}

//                (1)                  (2)                  (3)
//              _______              -------              -------
//              |     |              |     |              |     |
//  REQ_START-->|/////|  REQ_START-->|/////|  REQ_START-->|/////|
//              |/////|              |/////|              |/////|
//              |/////|  log_start-->|XXXXX|  log_start-->|XXXXX|
//    REQ_END-->|     |              |XXXXX|              |XXXXX|
//              |     |              |XXXXX|              |XXXXX|
//  log_start-->|\\\\\|              |XXXXX|              |XXXXX|
//              |\\\\\|    REQ_END-->|\\\\\|    log_end-->|/////|
//              |\\\\\|              |\\\\\|              |/////|
//    log_end-->|     |    log_end-->|     |    REQ_END-->|     |
//              -------              -------              -------
//                Log                  Log                  Log
//
//                (4)                  (5)                  (6)
//              _______              -------              -------
//              |     |              |     |              |     |
//  log_start-->|\\\\\|  log_start-->|\\\\\|  log_start-->|\\\\\|
//              |\\\\\|              |\\\\\|              |\\\\\|
//  REQ_START-->|XXXXX|  REQ_START-->|XXXXX|              |\\\\\|
//              |XXXXX|              |XXXXX|    log_end-->|     |
//              |XXXXX|              |XXXXX|              |     |
//              |XXXXX|              |XXXXX|  REQ_START-->|/////|
//    REQ_END-->|\\\\\|    log_end-->|/////|              |/////|
//              |\\\\\|              |/////|              |/////|
//    log_end-->|     |    REQ_END-->|     |    REQ_END-->|     |
//              -------              -------              -------
//                Log                  Log                  Log
//
static inline int check_overwrite(void *req_start, void *req_end,
                                  void *log_start, void *log_end) {
  if (req_start <= log_start) {
    if (req_end >= log_start) {
      if (req_end < log_end)
        return 2;
      else
        return 3;
    } else
      return 1;
  } else {
    if (req_end <= log_end)
      return 4;
    else {
      if (log_end < req_start)
        return 6;
      else
        return 5;
    }
  }
}

void nvmemcpy_read_redo(void *dest, const void *src, size_t record_size) {
  log_table_t *table;
  log_entry_t *entry;
  void *req_start, *req_end, *log_start, *log_end, *overwrite_dest;
  unsigned long req_addr, req_offset, req_len, overwrite_len;
  unsigned long next_page_addr, next_len, next_table_addr, next_table_len;
  unsigned long index;
  int s, n;
  log_size_t log_size;

  LIBNVMMIO_INIT_TIME(nvmemcpy_read_redo_time);
  LIBNVMMIO_START_TIME(nvmemcpy_read_redo_t, nvmemcpy_read_redo_time);

  nvmmio_memcpy(dest, src, record_size);

  n = (unsigned long)record_size;
  req_addr = (unsigned long)src;

  while (n > 0) {
    table = find_log_table(req_addr);

    if (table != NULL && table->count > 0) {
      log_size = table->log_size;
      index = table_index(log_size, req_addr);

      next_page_addr = (req_addr + LOG_SIZE(log_size)) & LOG_MASK(log_size);
      next_len = next_page_addr - req_addr;

    nvmemcpy_read_get_entry:
      entry = table->entries[index];

      LIBNVMMIO_INIT_TIME(check_log_time);
      LIBNVMMIO_START_TIME(check_log_t, check_log_time);

      if (entry != NULL) {
        if (pthread_rwlock_tryrdlock(entry->rwlockp) != 0)
          goto nvmemcpy_read_get_entry;

        if ((int)next_len >= n)
          req_len = n;
        else
          req_len = next_len;

        log_start = entry->data + entry->offset;
        log_end = log_start + entry->len;

        req_offset = req_addr & (LOG_SIZE(log_size) - 1);
        req_start = entry->data + req_offset;
        req_end = req_start + req_len;

        s = check_overwrite(req_start, req_end, log_start, log_end);
        switch (s) {
          case 1:
            break;
          case 2:
            overwrite_dest = dest + (log_start - req_start);
            overwrite_len = req_end - log_start;
            nvmmio_memcpy(overwrite_dest, log_start, overwrite_len);
            break;
          case 3:
            overwrite_dest = dest + (log_start - req_start);
            nvmmio_memcpy(overwrite_dest, log_start, entry->len);
            break;
          case 4:
            nvmmio_memcpy(dest, req_start, req_len);
            break;
          case 5:
            overwrite_len = log_end - req_start;
            nvmmio_memcpy(dest, req_start, overwrite_len);
            break;
          case 6:
            break;
          default:
            handle_error("check overwrite");
        }
        s = pthread_rwlock_unlock(entry->rwlockp);
        if (__glibc_unlikely(s != 0)) {
          handle_error("pthread_rwlock_unlock");
        }
      }
      req_addr = next_page_addr;
      dest += next_len;
      n -= next_len;

      LIBNVMMIO_END_TIME(check_log_t, check_log_time);
    }
    /* No Table */
    else {
      next_table_addr = (req_addr + TABLE_SIZE) & TABLE_MASK;
      next_table_len = next_table_addr - req_addr;

      req_addr = next_table_addr;
      dest += next_table_len;
      n -= next_table_len;
    }
  }
  LIBNVMMIO_END_TIME(nvmemcpy_read_redo_t, nvmemcpy_read_redo_time);
}

static inline log_size_t set_log_size(size_t record_size) {
  log_size_t log_size = LOG_4K;
  record_size = (record_size - 1) >> PAGE_SHIFT;
  while (record_size) {
    record_size = record_size >> 1;
    log_size++;
  }
  return log_size;
}

void nvmemcpy_write(void *dst, const void *src, size_t record_size,
                           uma_t *uma) {
  log_entry_t *entry;
  log_table_t *table;
  unsigned long req_addr, next_page_addr, req_offset;
  const void *source;
  void *destination, *overwrite_src;
  void *log_start, *log_end;
  void *prev_log_start, *prev_log_end;
  size_t next_len, req_len, overwrite_len;
  unsigned long index;
  log_size_t log_size;
  int s, n;

  LIBNVMMIO_INIT_TIME(nvmemcpy_write_time);
  LIBNVMMIO_START_TIME(nvmemcpy_write_t, nvmemcpy_write_time);

  s = pthread_rwlock_rdlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_rdlock");
  }

  LIBNVMMIO_INIT_TIME(indexing_log_time);
  LIBNVMMIO_START_TIME(indexing_log_t, indexing_log_time);

  destination = dst;
  source = src;
  n = (int)record_size;
  req_addr = (unsigned long)dst;

  table = get_log_table(req_addr);

  /* TODO: log_size must be updated atomically */
  if (table->count == 0) {
    log_size = set_log_size(record_size);
    table->log_size = log_size;
  } else {
    log_size = table->log_size;
  }

  index = table_index(log_size, req_addr);

  LIBNVMMIO_END_TIME(indexing_log_t, indexing_log_time);

  while (n > 0 && table != NULL) {
  nvmemcpy_write_get_entry:

    entry = table->entries[index];

    LIBNVMMIO_INIT_TIME(alloc_log_time);
    LIBNVMMIO_START_TIME(alloc_log_t, alloc_log_time);

    if (entry == NULL) {
      entry = alloc_log_entry(uma, log_size);

      if (__sync_bool_compare_and_swap(&table->entries[index], NULL, entry)) {
        atomic_increase(&table->count);
      } else {
        free_log_entry(entry, log_size, false);
        entry = table->entries[index];
      }
    }
    LIBNVMMIO_END_TIME(alloc_log_t, alloc_log_time);

    if (pthread_rwlock_trywrlock(entry->rwlockp) != 0)
      goto nvmemcpy_write_get_entry;

    if (entry->epoch < uma->epoch) {
      sync_entry(entry, uma);
    }

    req_offset = LOG_OFFSET(req_addr, log_size);
    next_page_addr = (req_addr + LOG_SIZE(log_size)) & LOG_MASK(log_size);

    log_start = entry->data + req_offset;
    next_len = next_page_addr - req_addr;

    if ((int)next_len > n)
      req_len = n;
    else
      req_len = next_len;

    if (uma->policy == UNDO) {
      nvmmio_write(log_start, dst, req_len, false);
    } else {
      nvmmio_write(log_start, src, req_len, false);
    }

    if (entry->len > 0) {  // overwrite
      log_end = log_start + req_len;
      prev_log_start = entry->data + entry->offset;
      prev_log_end = prev_log_start + entry->len;

      s = check_overwrite(log_start, log_end, prev_log_start, prev_log_end);
      switch (s) {
        case 1:
          overwrite_src = dst + req_len;
          overwrite_len = prev_log_start - log_end;
          nvmmio_write(log_end, overwrite_src, overwrite_len, false);
          entry->offset = req_offset;
          entry->len = prev_log_end - log_start;
          break;
        case 2:
          entry->offset = req_offset;
          entry->len = prev_log_end - log_start;
          break;
        case 3:
          entry->offset = req_offset;
          entry->len = req_len;
          break;
        case 4:
          break;
        case 5:
          entry->len = log_end - prev_log_start;
          break;
        case 6:
          overwrite_len = log_start - prev_log_end;
          overwrite_src = dst - overwrite_len;
          nvmmio_write(prev_log_end, overwrite_src, overwrite_len, false);
          entry->len = log_end - prev_log_start;
          break;
        default:
          handle_error("check overwrite");
      }
    } else {  // no overwrite
      entry->offset = req_offset;
      entry->len = req_len;
      entry->dst = (void *)(req_addr & PAGE_MASK);
    }
    nvmmio_flush(entry, sizeof(log_entry_t), false);

    s = pthread_rwlock_unlock(entry->rwlockp);
    if (__glibc_unlikely(s != 0)) {
      handle_error("pthread_rwlock_unlock");
    }

    req_addr = next_page_addr;
    src += next_len;
    n -= (int)next_len;
    index += 1;
    if (index == PTRS_PER_TABLE && n > 0) {
      table = get_next_table2(table, TABLE);
      index = 0;
    }
  }
  nvmmio_fence();

  if (uma->policy == UNDO) {
    nvmmio_write(destination, source, record_size, true);
  }

  s = pthread_rwlock_unlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }
  LIBNVMMIO_END_TIME(nvmemcpy_write_t, nvmemcpy_write_time);
}

static inline void nvmemcpy_f2f_write(void *dst, const void *src, size_t n,
                                      uma_t *dst_uma, uma_t *src_uma) {
  void *buf;

  if (src_uma->policy == UNDO) {
    nvmemcpy_write(dst, src, n, dst_uma);
  } else {
    buf = (void *)malloc(n);
    if (__glibc_unlikely(buf == NULL)) {
      handle_error("malloc");
    }
    nvmemcpy_read_redo(buf, src, n);
    nvmemcpy_write(dst, buf, n, dst_uma);
    free(buf);
  }
}

static size_t nvstrlen_redo(char *start, char *end, bool *next) {
  char *s;
  unsigned long offset;

  for (s = start; s < end; ++s) {
    if (!(*s)) break;
  }

  offset = (unsigned long)s & (~PAGE_MASK);
  if (offset == 0)
    *next = true;
  else
    *next = false;

  return (s - start);
}

// dst is a pointer to user buffer
// src is a pointer to memory mapped file
static void get_string_from_redo(char **dst, const char *src) {
  log_entry_t *entry;
  unsigned long req_addr, req_offset;
  void *log_start, *log_end, *req_start;
  size_t n, len = 0;
  bool next;

  req_addr = (unsigned long)src;

  do {
  get_string_from_redo_get_entry:
    entry = find_log_entry(req_addr);

    if (entry != NULL) {
      if (pthread_rwlock_tryrdlock(entry->rwlockp) != 0)
        goto get_string_from_redo_get_entry;

      req_offset = req_addr & (~PAGE_MASK);
      req_start = entry->data + req_offset;
      log_start = entry->data + entry->offset;
      log_end = log_start + entry->len;

      if (log_start <= req_start && req_start < log_end) {
        n = nvstrlen_redo(req_start, log_end, &next);

        if (len == 0) {
          if (!next)
            len = n + 1;
          else
            len = n;

          *dst = (char *)malloc(len);
          if (*dst == NULL) {
            handle_error("malloc");
          }

          memcpy(*dst, req_start, len);
        } else {
          if (!next)
            len = len + n + 1;
          else
            len = n;

          *dst = (char *)realloc(*dst, len);
          if (*dst == NULL) {
            handle_error("realloc");
          }

          strcat(*dst, req_start);
        }
      }
    }
    req_addr = (req_addr + PAGE_SIZE) & PAGE_MASK;
  } while (next);
}

void *nvmemcpy(void *dst, const void *src, size_t n) {
  uma_t *dst_uma, *src_uma;

  if (filter_addr(dst)) {
    dst_uma = find_uma(dst);

    if (dst_uma) {
      increase_uma_write_cnt(dst_uma);

      if (filter_addr(src)) {
        src_uma = find_uma(src);

        if (src_uma) {
          increase_uma_read_cnt(src_uma);

          nvmemcpy_f2f_write(dst, src, n, dst_uma, src_uma);
          goto nvmemcpy_out;
        }
      }
      nvmemcpy_write(dst, src, n, dst_uma);
      goto nvmemcpy_out;
    }
  } else {
    if (filter_addr(src)) {
      src_uma = find_uma(src);

      if (src_uma) {
        increase_uma_read_cnt(src_uma);

        if (src_uma->policy == UNDO) {
          memcpy(dst, src, n);
          goto nvmemcpy_out;
        } else {
          nvmemcpy_read_redo(dst, src, n);
          goto nvmemcpy_out;
        }
      }
    }
  }
  memcpy(dst, src, n);

nvmemcpy_out:
  return dst;
}

static void nvmsync_sync(void *addr, size_t len, unsigned long new_epoch) {
  log_table_t *table;
  log_entry_t *entry;
  log_size_t log_size;
  unsigned long address, nrpages, start, end, i;
  void *dst, *src;
  int s;

  address = (unsigned long)addr;

  table = get_log_table(address);
  log_size = table->log_size;
  nrpages = len >> LOG_SHIFT(log_size);
  start = table_index(log_size, address);

  if (NUM_ENTRIES(log_size) - start > nrpages)
    end = start + nrpages;
  else
    end = NUM_ENTRIES(log_size);

  while (nrpages > 0 && table != NULL) {
    if (table->count > 0) {
      for (i = start; i < end; i++) {
      retry_sync_nvmsync_get_entry:
        entry = table->entries[i];

        if (entry != NULL && entry->epoch < new_epoch) {
          /* lock the entry */
          if (pthread_rwlock_trywrlock(entry->rwlockp) != 0)
            goto retry_sync_nvmsync_get_entry;

          /* sync the entry */
          if (entry->epoch < new_epoch) {
            if (entry->policy == REDO) {
              dst = entry->dst + entry->offset;
              src = entry->data + entry->offset;

              nvmmio_write(dst, src, entry->len, false);
            }
            table->entries[i] = NULL;
            nvmmio_fence();

            free_log_entry(entry, log_size, false);
            atomic_decrease(&table->count);
            continue;
          }
          /* unlock the entry */
          s = pthread_rwlock_unlock(entry->rwlockp);
          if (__glibc_unlikely(s != 0)) {
            handle_error("pthread_rwlock_unlock");
          }
        }
      }
    }
    nrpages -= (end - start);
    start = 0;

    if (NUM_ENTRIES(log_size) - start > nrpages)
      end = start + nrpages;
    else
      end = NUM_ENTRIES(log_size);

    table = get_next_table(table, &nrpages);
  }

  release_local_list();
}

int nvmsync_uma(void *addr, size_t len, int flags, uma_t *uma) {
  unsigned long new_epoch;
  int s, ret;
  bool sync = false;

	LIBNVMMIO_DEBUG("uma id=%d", uma->id);

  LIBNVMMIO_INIT_TIME(fsync_time);
  LIBNVMMIO_START_TIME(fsync_t, fsync_time);

  if (offset_in_page((unsigned long)addr)) {
    ret = -1;
    goto nvmsync_out;
  }

  len = (len + (~PAGE_MASK)) & PAGE_MASK;

  s = pthread_rwlock_wrlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_wrlock");
  }

  new_epoch = uma->epoch + 1;
  uma->epoch = new_epoch;
  nvmmio_flush(&(uma->epoch), sizeof(unsigned long), true);

  if (uma->write > 0) {
    sync = true;
  }

  /* Hybrid Logging */
#if 1
  log_policy_t new_policy;
  unsigned long total, write_ratio;

  total = uma->read + uma->write;

  if (total > 0) {
    write_ratio = uma->write / total * 100;

    if (write_ratio > HYBRID_WRITE_RATIO) {
      new_policy = REDO;
    } else {
      new_policy = UNDO;
    }

    uma->read = 0;
    uma->write = 0;

    if (uma->policy != new_policy) {
      flags &= ~MS_ASYNC;
      flags |= MS_SYNC;
      uma->policy = new_policy;

      if (new_policy == UNDO) {
        LIBNVMMIO_DEBUG("REDO->UNDO");
			}
      else {
        LIBNVMMIO_DEBUG("UNDO->REDO");
			}
    }
  }
#endif

  if (sync) {
    if (flags & MS_SYNC) {
      nvmsync_sync(addr, len, new_epoch);
    }
  }

  s = pthread_rwlock_unlock(uma->rwlockp);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }

  ret = 0;

  LIBNVMMIO_END_TIME(fsync_t, fsync_time);

nvmsync_out:
  return ret;
}

int nvmsync(void *addr, size_t len, int flags) {
  uma_t *uma;

  len = (len + (~PAGE_MASK)) & PAGE_MASK;
  uma = find_uma(addr);
  if (__glibc_unlikely(uma == NULL)) {
    handle_error("find_uma() failed");
  }

	return nvmsync_uma(addr, len, flags, uma);
}

int nvmemcmp(const void *s1, const void *s2, size_t n) {
  uma_t *uma;
  void *s1_ptr, *s2_ptr;
  int ret;

  s1_ptr = (void *)s1;
  s2_ptr = (void *)s2;

  if (filter_addr(s1)) {
    uma = find_uma(s1);

    if (uma) {
      increase_uma_read_cnt(uma);

      if (uma->policy == REDO) {
        s1_ptr = malloc(n);
        if (__glibc_unlikely(s1_ptr == NULL)) handle_error("malloc");

        nvmemcpy_read_redo(s1_ptr, s1, n);
      }
    }
  }

  if (filter_addr(s2)) {
    uma = find_uma(s2);

    if (uma) {
      increase_uma_read_cnt(uma);

      if (uma->policy == REDO) {
        s2_ptr = malloc(n);
        if (__glibc_unlikely(s2_ptr == NULL)) handle_error("malloc");

        nvmemcpy_read_redo(s2_ptr, s2, n);
      }
    }
  }
  ret = memcmp(s1_ptr, s2_ptr, n);

  return ret;
}

void *nvmemset(void *s, int c, size_t n) {
  uma_t *uma;
  void *buf, *ret;

  if (filter_addr(s)) {
    uma = find_uma(s);

    if (uma) {
      buf = malloc(n);
      if (buf == NULL) handle_error("malloc");

      memset(buf, c, n);
      nvmemcpy_write(s, buf, n, uma);
      ret = s;

      free(buf);
      goto nvmemset_out;
    }
  }

  ret = memset(s, c, n);

nvmemset_out:
  return ret;
}

int nvstrcmp(const char *s1, const char *s2) {
  uma_t *uma;
  char *s1_ptr, *s2_ptr;
  int ret;

  s1_ptr = (char *)s1;
  s2_ptr = (char *)s2;

  if (filter_addr(s1)) {
    uma = find_uma(s1);

    if (uma) {
      increase_uma_read_cnt(uma);

      if (uma->policy == REDO) {
        get_string_from_redo(&s1_ptr, s1);
      }
    }
  }

  if (filter_addr(s2)) {
    uma = find_uma(s2);

    if (uma) {
      increase_uma_read_cnt(uma);

      if (uma->policy == REDO) {
        get_string_from_redo(&s2_ptr, s2);
      }
    }
  }
  ret = strcmp(s1_ptr, s2_ptr);

  return ret;
}
