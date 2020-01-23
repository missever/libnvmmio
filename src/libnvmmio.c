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

#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/uio.h>
#include "allocator.h"
#include "internal.h"
#include "list.h"
#include "stats.h"

#define PATH_SIZE 64
#define NthM(x) (67108864 << x)
#define O_ATOMIC 01000000000
#define _USE_HYBRID_LOGGING
#define HYBRID_WRITE_RATIO (40)
#define MIN_FILESIZE (1UL << 26)

int POSSIBLE_MODE = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP |
                    S_IROTH | S_IWOTH | S_IXOTH;

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

static inline void increase_read_count(uma_t *uma) {
  int old, new;

  LIBNVMMIO_INIT_TIME(increase_read_count_time);
  LIBNVMMIO_START_TIME(increase_read_count_t, increase_read_count_time);

  /* TODO: It is necessary to check whether the counter does not exceed the
   * ULONG_MAX */
  do {
    old = uma->read;
    new = old + 1;
  } while (!__sync_bool_compare_and_swap(&uma->read, old, new));

  LIBNVMMIO_END_TIME(increase_read_count_t, increase_read_count_time);
}

static inline void increase_write_count(uma_t *uma) {
  int old, new;

  LIBNVMMIO_INIT_TIME(increase_write_count_time);
  LIBNVMMIO_START_TIME(increase_write_count_t, increase_write_count_time);

  /* TODO: It is necessary to check whether the counter does not exceed the
   * ULONG_MAX */
  do {
    old = uma->write;
    new = old + 1;
  } while (!__sync_bool_compare_and_swap(&uma->write, old, new));

  LIBNVMMIO_END_TIME(increase_write_count_t, increase_write_count_time);
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
    base_mmap_addr = ALIGN_TABLE(base_mmap_addr + TABLE_SIZE);
    munmap(addr, PAGE_SIZE);
  }
}

static void sync_uma(uma_t *uma) {
  unsigned long address, len, current_epoch, nrpages, start, end, i;
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

void cleanup_handler(void) {
  exit_background_table_alloc_thread();
  report_time();
  return;
}

void init_libnvmmio(void) {
  if (__sync_bool_compare_and_swap(&initialized, false, true)) {
    init_timer();

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
    printf("[%s] warning: addr is not NULL.\n", __func__);
    return addr;
  }

  do {
    old = base_mmap_addr;
    new = (void *)ALIGN_TABLE(base_mmap_addr + (n + TABLE_SIZE));
  } while (!__sync_bool_compare_and_swap(&base_mmap_addr, old, new));

  return old;
}

static inline bool filter_addr(const void *address) {
  bool result;

  result = (min_addr <= address) && (address < max_addr);

  return result;
}

static void close_sync_thread(uma_t *uma) {
  int s;
  s = pthread_cancel(uma->sync_thread);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_cancel");
  }
}

static void *sync_thread_func(void *parm) {
  uma_t *uma;
  uma = (uma_t *)parm;

  printf("[%s] %d uma thread start on %d\n", __func__, uma->id, sched_getcpu());

  while (TRUE) {
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

  printf("[%s] fd=%d\n", __func__, fd);

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
  if (uma->policy == UNDO)
    printf("[%s] policy = UNDO\n", __func__);
  else
    printf("[%s] policy = REDO\n", __func__);

  create_sync_thread(uma);

  if (uma->start < min_addr) {
    min_addr = uma->start;
  }

  if (uma->end > max_addr) {
    max_addr = uma->end;
  }

  insert_uma_rbtree(uma);
  insert_uma_syncthreads(uma);

  return mmap_addr;
}

int nvmunmap(void *addr, size_t n) {
  int ret;
  uma_t *uma;

  uma = find_uma(addr);

  if (uma == NULL) {
    handle_error("find_uma() failed");
  }

  if (uma->start != addr || uma->end != (addr + n)) {
    handle_error("the uma must be splitted");
  }

  delete_uma_rbtree(uma);
  delete_uma_syncthreads(uma);
  ret = munmap(addr, n);

  return ret;
}

static int nvmunmap_uma(void *addr, size_t n, uma_t *uma) {
  if (__glibc_unlikely(uma == NULL)) {
    handle_error("find_uma() failed");
  }

  if (__glibc_unlikely(uma->start != addr || uma->end != (addr + n))) {
    handle_error("the uma must be splitted");
  }

  delete_uma_rbtree(uma);
  delete_uma_syncthreads(uma);
  return munmap(addr, n);
}

static void sync_entry(log_entry_t *entry, uma_t *uma) {
  void *dst, *src;

  if (uma->policy == REDO) {
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

static inline void nvmemcpy_memcpy(void *dst, const void *src, size_t n) {
  LIBNVMMIO_INIT_TIME(nvmemcpy_memcpy_time);
  LIBNVMMIO_START_TIME(nvmemcpy_memcpy_t, nvmemcpy_memcpy_time);

  memcpy(dst, src, n);

  LIBNVMMIO_END_TIME(nvmemcpy_memcpy_t, nvmemcpy_memcpy_time);
}

static void nvmemcpy_read_redo(void *dest, const void *src,
                               size_t record_size) {
  log_table_t *table;
  log_entry_t *entry;
  void *req_start, *req_end, *log_start, *log_end, *overwrite_dest;
  unsigned long req_addr, req_offset, req_len, overwrite_len;
  unsigned long next_page_addr, next_len, next_table_addr, next_table_len;
  unsigned long index;
  int s, status, n;
  log_size_t log_size;

  LIBNVMMIO_INIT_TIME(nvmemcpy_read_redo_time);
  LIBNVMMIO_START_TIME(nvmemcpy_read_redo_t, nvmemcpy_read_redo_time);

  nvmemcpy_memcpy(dest, src, record_size);

  n = (int)record_size;
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

        if (next_len >= n)
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
            nvmemcpy_memcpy(overwrite_dest, log_start, overwrite_len);
            break;
          case 3:
            overwrite_dest = dest + (log_start - req_start);
            nvmemcpy_memcpy(overwrite_dest, log_start, entry->len);
            break;
          case 4:
            nvmemcpy_memcpy(dest, req_start, req_len);
            break;
          case 5:
            overwrite_len = log_end - req_start;
            nvmemcpy_memcpy(dest, req_start, overwrite_len);
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

static void nvmemcpy_write(void *dst, const void *src, size_t record_size,
                           uma_t *uma) {
  log_entry_t *entry;
  log_table_t *table;
  unsigned long req_addr, next_page_addr, req_offset;
  const void *source;
  void *destination, *overwrite_src;
  void *log_start, *log_end;
  void *prev_log_start, *prev_log_end;
  size_t next_len, req_len, overwrite_len;
  unsigned long index, log_mask;
  log_size_t log_size;
  int s, n;
  void *test_addr;

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

    if (next_len > n)
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
    n -= next_len;
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
    if (buf == NULL) {
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
      increase_write_count(dst_uma);

      if (filter_addr(src)) {
        src_uma = find_uma(src);

        if (src_uma) {
          increase_read_count(src_uma);

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
        increase_read_count(src_uma);

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

      if (new_policy == UNDO)
        printf("[%s] REDO->UNDO\n", __func__);
      else
        printf("[%s] UNDO->REDO\n", __func__);
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
  unsigned long new_epoch;
  int s, ret;
  bool sync = false;

  len = (len + (~PAGE_MASK)) & PAGE_MASK;
  uma = find_uma(addr);
  if (__glibc_unlikely(uma == NULL)) {
    handle_error("find_uma() failed");
  }

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

      if (new_policy == UNDO)
        printf("[%s] REDO->UNDO\n", __func__);
      else
        printf("[%s] UNDO->REDO\n", __func__);
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

nvmsync_out:
  return ret;
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
      increase_read_count(uma);

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
      increase_read_count(uma);

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
      increase_read_count(uma);

      if (uma->policy == REDO) {
        get_string_from_redo(&s1_ptr, s1);
      }
    }
  }

  if (filter_addr(s2)) {
    uma = find_uma(s2);

    if (uma) {
      increase_read_count(uma);

      if (uma->policy == REDO) {
        get_string_from_redo(&s2_ptr, s2);
      }
    }
  }
  ret = strcmp(s1_ptr, s2_ptr);

  return ret;
}

typedef struct fd_mapaddr_struct {
  void *addr;
  off_t off;
  char pathname[PATH_SIZE];
  size_t mapped_size;
  size_t written_file_size;
  size_t current_file_size;
  int dup;
  int dupfd;
  int open;
  int increaseCount;
  uma_t *fd_uma;
} fd_addr;

static fd_addr fd_table[FD_LIMIT] = {
    0,
};
static int fd_indirection[FD_LIMIT] = {0};
static int lastFd;

static inline void map_fd_addr(int fd, void *addr, off_t fd_size,
                               off_t written_file_size, size_t mapped_size,
                               const char *pathname) {
  fd_table[fd].addr = addr;
  fd_table[fd].off = 0;
  memcpy(fd_table[fd].pathname, pathname, strlen(pathname));
  fd_table[fd].mapped_size = mapped_size;
  fd_table[fd].written_file_size = written_file_size;
  fd_table[fd].current_file_size = fd_size;
  fd_table[fd].fd_uma = find_uma(addr);
  fd_table[fd].dupfd = fd;
  fd_table[fd].open = 0;
  fd_table[fd].dup = 0;
  fd_table[fd].increaseCount = 1;
  // TODO
  // getdtablesize() gives the MAX fd a process can have
  // not many fds, usually 1024.
  // Just make an array to keep a fd and addr pair
}

static inline off_t get_fd_off(int fd) {
  if (fd_table[fd].dupfd == fd)
    return fd_table[fd].off;
  else
    return fd_table[fd_indirection[fd]].off;
}
static inline void *get_fd_addr_cur(int fd) {
  return fd_table[fd_indirection[fd]].addr + get_fd_off(fd);
}

static inline void *get_fd_addr_set(int fd, off_t off) {
  return fd_table[fd_indirection[fd]].addr + off;
}

static inline uma_t *get_fd_uma(int fd) {
  uma_t *uma;

  LIBNVMMIO_INIT_TIME(get_fd_uma_time);
  LIBNVMMIO_START_TIME(get_fd_uma_t, get_fd_uma_time);

  uma = fd_table[fd_indirection[fd]].fd_uma;

  LIBNVMMIO_END_TIME(get_fd_uma_t, get_fd_uma_time);
  return uma;
}

static inline int get_path_fd(const char *pathname) {
  int i = 3;
  for (i = 3; i <= lastFd; i++) {
    if (fd_table[fd_indirection[i]].pathname != NULL &&
        fd_table[fd_indirection[i]].pathname != 0) {
      if (strcmp(fd_table[fd_indirection[i]].pathname, pathname) == 0) return i;
    }
  }
  return -1;
}

static inline void trunc_fit_fd(int fd) {
  size_t written_file_size = fd_table[fd_indirection[fd]].written_file_size;
  size_t current_file_size = fd_table[fd_indirection[fd]].current_file_size;

  if (written_file_size < current_file_size) {
    if (ftruncate(fd, written_file_size) < 0) {
      printf("[%s]: ftruncate error\n", __func__);
    } else {
      fd_table[fd_indirection[fd]].current_file_size = written_file_size;
    }
  }
}

static inline size_t trunc_expand_fd(int fd, size_t current_file_size) {
  size_t ret = current_file_size;
  int indirectedFd = fd_indirection[fd];
  if (current_file_size < IO_MAP_SIZE) {
    if (posix_fallocate(indirectedFd, 0, IO_MAP_SIZE) < 0) {
      printf("[%s]: posix_fallocate error\n", __func__);
    } else {
      fd_table[indirectedFd].current_file_size = IO_MAP_SIZE;
      ret = IO_MAP_SIZE;
    }
  } else {
    if (current_file_size == IO_MAP_SIZE) return IO_MAP_SIZE;

    unsigned long long add_file_size =
        NthM(fd_table[indirectedFd].increaseCount);
    ret += add_file_size;
    if (posix_fallocate(indirectedFd, fd_table[indirectedFd].current_file_size,
                        add_file_size) < 0) {
      printf("[%s]: posix_fallocate error\n", __func__);
    } else {
      fd_table[indirectedFd].increaseCount++;
      fd_table[indirectedFd].current_file_size = ret;
    }
  }
  return ret;
}

static inline uma_t *expand_remap_fd(int fd, size_t current_file_size) {
  int indirectedFd = fd_indirection[fd];
  size_t ret = trunc_expand_fd(fd, current_file_size);

  printf("[%s]:addr:%ld, len:%ld\n", __func__,
         (long int)fd_table[indirectedFd].addr,
         fd_table[indirectedFd].written_file_size);

  nvmsync(fd_table[indirectedFd].addr, fd_table[indirectedFd].written_file_size,
          MS_SYNC);

  nvmunmap_uma(fd_table[indirectedFd].addr, fd_table[indirectedFd].mapped_size,
               get_fd_uma(fd));

  fd_table[indirectedFd].addr =
      nvmmap(NULL, ret, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

  if (fd_table[indirectedFd].addr) {
    fd_table[indirectedFd].mapped_size = ret;
    fd_table[indirectedFd].fd_uma = find_uma(fd_table[indirectedFd].addr);
  } else {
    printf("[%s]: Failed!!!\n", __func__);
  }
  return fd_table[indirectedFd].fd_uma;
}

int nvcreat(const char *filename, mode_t mode) {
  /* TODO: should change this to open */
  int fd = creat(filename, mode);

  if (fd >= 0) {
    void *addr =
        nvmmap(NULL, IO_MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (addr >= 0) map_fd_addr(fd, addr, 0, 0, IO_MAP_SIZE, filename);
  }
  return fd;
}

static inline void sanitize_flags(int *flags) {
  if (!(*flags & O_RDWR)) {
    if (!(*flags & O_WRONLY)) {
      if (!*flags & O_RDONLY) {
        printf("[%s]: open should include one of O_WRONLY, O_RDWR, O_RDONLY",
               __func__);
      }
      *flags ^= O_RDONLY;
      *flags |= O_RDWR;
    } else {
      *flags ^= O_WRONLY;
      *flags |= O_RDWR;
    }
  }
}

static inline int fd_validity(int fd) {
  return fcntl(fd, F_GETFL) != -1 || errno != EBADF;
}

int nvopen(const char *path, int flags, ...) {
  struct stat statbuf;
  off_t fd_size = 0;
  int isdir = FALSE;
  int fd, s;

  /* TODO: Implement O_NONBLOCK and O_NODELAY */

  if (!(flags & O_ATOMIC)) return open(path, flags);

  if (flags & O_PATH) {
    return open(path, flags);
  }

  s = stat(path, &statbuf);
  if (__glibc_unlikely(s != 0)) handle_error("stat");

  if (S_ISDIR(statbuf.st_mode) || strncmp(path, "/dev", 4) == 0) {
    isdir = TRUE;
  } else {
    fd_size = statbuf.st_size;
  }

  if (isdir == 1 || strncmp(path, "/dev", 4) == 0 ||
      strncmp(path, "/proc", 5) == 0 ||
      (path[strlen(path) - 1] == '.' && path[strlen(path) - 2] == '/')) {
    isdir = TRUE;
  } else {
    sanitize_flags(&flags);
  }

  if (isdir == FALSE || flags & O_CREAT) {
    va_list arg;
    int mode;

    va_start(arg, flags);
    mode = va_arg(arg, int);
    va_end(arg);

    if ((mode & POSSIBLE_MODE) == mode) {
      fd = open(path, flags, mode);
    } else {
      // This is when a file is opened with O_CREAT but with no mode specified
      // or wrong mode No exact definition on what happens when O_CREAT without
      // mode. NOVA seems like it cannot handle it. so giving 0666 as default
      // would be a good idea
      fd = open(path, flags, 0666);
    }
  } else {
    fd = open(path, flags);
    fd_table[fd].addr = NULL;
    fd_table[fd].dupfd = fd;
    fd_indirection[fd] = fd;

    if (lastFd < fd) lastFd = fd;
    return fd;
  }

  if (fd >= 0) {
    fd_table[fd].addr = NULL;
    off_t written_size = fd_size;
    size_t mapped_size;
    void *addr = 0;
    int openedFd = get_path_fd(path);

    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (openedFd > 0) {
      fd_table[fd].off = 0;
      fd_table[fd].dupfd = fd;
      fd_indirection[fd] = openedFd;
    } else {
      fd_indirection[fd] = fd;
      openedFd = fd;
      mapped_size = trunc_expand_fd(fd, fd_size);
      fd_size = mapped_size;
      addr =
          nvmmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
      if (addr >= 0)
        map_fd_addr(fd, addr, fd_size, written_size, mapped_size, path);
    }
    fd_table[openedFd].open++;
    if (lastFd < openedFd) lastFd = openedFd;
  } else {
    printf("[%s]: open failed for %s fd:%d errno:%d\n", __func__, path, fd,
           errno);
  }
  return fd;
}

int nvdup(int oldfd) {
  int newfd = dup(oldfd);

  fd_indirection[newfd] = fd_indirection[oldfd];
  fd_table[newfd].dupfd = fd_table[oldfd].dupfd;
  fd_table[fd_table[oldfd].dupfd].dup++;

  return newfd;
}

void *unmap_thread(void *vargp) {
  int fd = *((int *)vargp);

  nvmsync(fd_table[fd].addr, fd_table[fd].written_file_size, MS_SYNC);
  nvmunmap_uma(fd_table[fd].addr, fd_table[fd].mapped_size, get_fd_uma(fd));
  fd_table[fd].addr = NULL;
}

int nvclose(int fd) {
  if (get_fd_addr_cur(fd) == NULL) {
    fd_indirection[fd] = 0;
    return close(fd);
  }

  if (fd_table[fd].dupfd != fd) {
    fd_table[fd_table[fd].dupfd].dup--;
    if (fd_indirection[fd_table[fd].dupfd] == 0) {
      if (fd_table[fd_table[fd].dupfd].dup == 0 &&
          fd_indirection[fd_indirection[fd]] == 0) {
        if (fd_table[fd_indirection[fd]].open <= 2) {
          fd_table[fd].dupfd = 0;
          printf("goto\n");
          goto removeOriginalFd;
        } else
          fd_table[fd_indirection[fd]].open--;
      }
    }
    fd_table[fd].dupfd = 0;
  } else if (fd_table[fd_indirection[fd]].open > 1) {
    if (fd_table[fd].dup == 0) {
      fd_table[fd_indirection[fd]].open--;
      fd_table[fd].off = 0;
      fd_table[fd].dupfd = 0;
    }
  } else if (fd_table[fd].dup == 0) {
    void *addr;
    size_t mapped_size;
  removeOriginalFd:
    addr = fd_table[fd_indirection[fd]].addr;
    mapped_size = fd_table[fd_indirection[fd]].mapped_size;
    trunc_fit_fd(fd);
    close_sync_thread(fd_table[fd_indirection[fd]].fd_uma);

    nvmsync_uma(addr, fd_table[fd_indirection[fd]].written_file_size, MS_SYNC,
                get_fd_uma(fd));

    nvmunmap_uma(fd_table[fd_indirection[fd]].addr,
                 fd_table[fd_indirection[fd]].mapped_size, get_fd_uma(fd));

    fd_table[fd_indirection[fd]].addr = NULL;
    fd_table[fd_indirection[fd]].off = 0;
    memset(fd_table[fd_indirection[fd]].pathname, 0, PATH_SIZE);
    fd_table[fd_indirection[fd]].mapped_size = 0;
    fd_table[fd_indirection[fd]].written_file_size = 0;
    fd_table[fd_indirection[fd]].current_file_size = 0;
    fd_table[fd_indirection[fd]].fd_uma = NULL;
    fd_table[fd_indirection[fd]].open = 0;
    fd_table[fd_indirection[fd]].dup = 0;
    fd_table[fd_indirection[fd]].dupfd = 0;
    fd_table[fd_indirection[fd]].increaseCount = 0;
  } else {
    fd_table[fd_indirection[fd]].open--;
  }
  fd_indirection[fd] = 0;

  return close(fd);
}

static inline ssize_t pwriteToMap(int fd, const void *buf, size_t cnt,
                                  void *dst) {
  // void *dst = get_fd_addr_set(fd,off);
  // uma_t *dst_uma = find_uma(dst);
  uma_t *dst_uma = get_fd_uma(fd);

  /*
     if(fd_table[fd].addr == NULL){
  //printf("[%s]: Invalid write request from fd %d\n",__func__, fd);
  }
   */
  if (dst_uma) {
    // TODO Check if trunc_fit_fd is needed in libnvmmio mmap semantic
    // trunc_fit_fd(fd);
    long long int required_size =
        cnt + (dst - fd_table[fd_indirection[fd]].addr);
    if (required_size > fd_table[fd_indirection[fd]].current_file_size) {
      printf("[%s]: call expand remap fd current size:%ld required size:%lld\n",
             __func__, fd_table[fd_indirection[fd]].current_file_size,
             required_size);
      dst_uma = expand_remap_fd(fd, required_size);
      dst = get_fd_addr_cur(
          fd);  // required_size + fd_table[fd_indirection[fd]].addr;
    }
    increase_write_count(dst_uma);

    nvmemcpy_write(dst, buf, cnt, dst_uma);
  } else {
    printf("[%s]: dst_uma for fd %d->%d  doesn't exist\n", __func__, fd,
           fd_indirection[fd]);
  }
  return cnt;
}

static inline ssize_t preadFromMap(int fd, void *buf, size_t cnt, void *src) {
  uma_t *src_uma = get_fd_uma(fd);

  /*
     if(fd_table[fd_indirection[fd]].addr == NULL){
  //printf("[%s]: Invalid read request from fd %d\n",__func__, fd);
  }
   */

  if (src_uma) {
    increase_read_count(src_uma);
    if (src_uma->policy == UNDO) {
      nvmemcpy_memcpy(buf, src, cnt);
      return cnt;
    } else {
      nvmemcpy_read_redo(buf, src, cnt);
    }
  }
  return cnt;
}

ssize_t nvread(int fd, void *buf, size_t cnt) {
  void *src = get_fd_addr_cur(fd);
  if (src == NULL) {
    //	printf("[%s] Called write with unmapped fd %d\\n", __func__, fd);
    return read(fd, buf, cnt);
  }
  ssize_t ret = preadFromMap(fd, buf, cnt, src);
  if (fd_table[fd].dupfd == fd) {
    fd_table[fd].off += cnt;
  } else {
    fd_table[fd_indirection[fd]].off += cnt;
  }

  return ret;
}

ssize_t nvwrite(int fd, const void *buf, size_t cnt) {
  void *dst;

  dst = get_fd_addr_cur(fd);

  if (dst == NULL) {
    // printf("[%s] Called write with unmapped fd %d\\n", __func__, fd);
    return write(fd, buf, cnt);
  }
  ssize_t ret = pwriteToMap(fd, buf, cnt, dst);

  // printf("\t\t\t[%s]: write Length:%ld fd:%d\n", __func__, cnt, fd);
  off_t off;
  if (fd_table[fd].dupfd == fd) {
    fd_table[fd].off += cnt;
    off = fd_table[fd].off;
  } else {
    fd_table[fd_indirection[fd]].off += cnt;
    off = fd_table[fd_indirection[fd]].off;
  }
  if (off > fd_table[fd_indirection[fd]].written_file_size) {
    fd_table[fd_indirection[fd]].written_file_size = off;
  }

  return ret;
}

off_t nvlseek(int fd, off_t offset, int whence) {
  off_t off;
  switch (whence) {
    case SEEK_SET:
      // validate offset range
      if (fd_table[fd].dupfd == fd)
        fd_table[fd].off = offset;
      else
        fd_table[fd_indirection[fd]].off = offset;

      return offset;

    case SEEK_CUR:
      if (fd_indirection[fd] == 0) return -1;
      if (fd_table[fd].dupfd == fd) {
        fd_table[fd].off += offset;
        off = fd_table[fd].off;
      } else {
        fd_table[fd_indirection[fd]].off += offset;
        off = fd_table[fd_indirection[fd]].off;
      }
      return off;

    case SEEK_END:
      if (fd_table[fd].dupfd == fd) {
        fd_table[fd].off = fd_table[fd].written_file_size + offset;
        off = fd_table[fd].off;
      } else {
        fd_table[fd_indirection[fd]].off =
            fd_table[fd].written_file_size + offset;
        off = fd_table[fd_indirection[fd]].off;
      }
      return off;

    default:
      // SEEK_DATA, SEEK_HOLE if needed
      return EINVAL;
  }
}

int nvftruncate(int fd, off_t length) {
  int ret = ftruncate(fd, length);
  if (ret == 0) {
    fd_table[fd_indirection[fd]].written_file_size = length;
    fd_table[fd_indirection[fd]].current_file_size = length;
    // TODO check sparse file is posix standard
  }

  return ret;
}

int nvfsync(int fd) {
  int indirectedFd = fd_indirection[fd];
  if (get_fd_addr_cur(fd) == NULL) {
    return fsync(indirectedFd);
  }
  // trunc_fit_fd(fd);
  // printf("[%s]:addr:%ld, len:%ld\n",__func__,(long int)fd_table[fd].addr,
  // fd_table[fd].written_file_size);
  return nvmsync_uma(fd_table[indirectedFd].addr,
                     fd_table[indirectedFd].written_file_size, MS_ASYNC,
                     get_fd_uma(fd));
}

// pread does not change offset
ssize_t nvpread(int fd, void *buf, size_t cnt, off_t offset) {
  if (get_fd_addr_cur(fd) == NULL) {
    //	printf("[%s] Called write with unmapped fd %d\\n", __func__, fd);
    return pread(fd, buf, cnt, offset);
  }
  void *src = get_fd_addr_set(fd, offset);
  ssize_t ret = preadFromMap(fd, buf, cnt, src);

  return ret;
}
ssize_t nvpread64(int fd, void *buf, size_t cnt, off_t offset) {
  return nvpread(fd, buf, cnt, offset);
}

ssize_t nvpwrite(int fd, const void *buf, size_t cnt, off_t offset) {
  if (get_fd_addr_cur(fd) == NULL) {
    return pwrite(fd, buf, cnt, offset);
  }
  ssize_t ret = pwriteToMap(fd, buf, cnt, get_fd_addr_set(fd, offset));

  off_t written_size = offset + cnt;
  if (written_size > fd_table[fd_indirection[fd]].written_file_size) {
    fd_table[fd_indirection[fd]].written_file_size = written_size;
  }

  return ret;
}
ssize_t nvpwrite64(int fd, const void *buf, size_t cnt, off_t offset) {
  return nvpwrite(fd, buf, cnt, offset);
}

// TODO Implement this as multithreaded from thread pool made in init()
ssize_t nvpreadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  // TODO Stopped Here
  int i;
  ssize_t ret = 0;
  if (get_fd_addr_cur(fd) == NULL) {
    return preadv(fd_indirection[fd], iov, iovcnt, offset);
  }
  void *src = get_fd_addr_set(fd, offset);

  for (i = 0; i < iovcnt; i++) {
    ret += preadFromMap(fd, iov[i].iov_base, iov[i].iov_len, src);
    src += iov[i].iov_len;
  }

  return ret;
}

ssize_t nvpwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
  if (get_fd_addr_cur(fd) == NULL) {
    return pwritev(fd, iov, iovcnt, offset);
  }
  int i;
  ssize_t ret = 0, file_size = fd_table[fd_indirection[fd]].current_file_size,
          len = offset;
  void *dst = get_fd_addr_set(fd, offset);

  for (i = 0; i < iovcnt; i++) {
    len += iov[i].iov_len;
    if (len > file_size) {
      expand_remap_fd(fd, file_size);
    }
    ret += pwriteToMap(fd, iov[i].iov_base, iov[i].iov_len, dst);
    dst += iov[i].iov_len;
  }

  off_t written_size = offset + ret;
  if (written_size > file_size) {
    fd_table[fd_indirection[fd]].written_file_size = written_size;
  }

  return ret;
}

ssize_t nvreadv(int fd, const struct iovec *iov, int iovcnt) {
  int i;
  ssize_t ret = 0;
  void *src = get_fd_addr_cur(fd);
  if (src == NULL) {
    //	printf("[%s] Called write with unmapped fd %d\\n", __func__, fd);
    return readv(fd, iov, iovcnt);
  }

  for (i = 0; i < iovcnt; i++) {
    ret += preadFromMap(fd, iov[i].iov_base, iov[i].iov_len, src);
    src += iov[i].iov_len;
  }

  if (fd_table[fd].dupfd == fd)
    fd_table[fd].off += ret;
  else
    fd_table[fd_indirection[fd]].off += ret;

  return ret;
}

ssize_t nvwritev(int fd, const struct iovec *iov, int iovcnt) {
  int i;
  ssize_t ret = 0, file_size = fd_table[fd_indirection[fd]].current_file_size,
          len;
  void *dst = get_fd_addr_cur(fd);
  if (dst == NULL) {
    return writev(fd, iov, iovcnt);
  }

  if (fd_table[fd].dupfd == fd)
    len = fd_table[fd].off;
  else
    len = fd_table[fd_indirection[fd]].off;

  for (i = 0; i < iovcnt; i++) {
    ssize_t iovlen = iov[i].iov_len;
    len += iovlen;
    if (len > file_size) {
      expand_remap_fd(fd, file_size);
    }
    ret += pwriteToMap(fd, iov[i].iov_base, iovlen, dst);
    dst += iovlen;
  }

  if (fd_table[fd].dupfd == fd) {
    fd_table[fd].off += ret;
    if (fd_table[fd].off > file_size)
      fd_table[fd_indirection[fd]].written_file_size = fd_table[fd].off;
  } else {
    fd_table[fd_indirection[fd]].off += ret;
    if (fd_table[fd_indirection[fd]].off > file_size)
      fd_table[fd_indirection[fd]].written_file_size =
          fd_table[fd_indirection[fd]].off;
  }

  return ret;
}

int nvfdatasync(int fd) {
  if (get_fd_addr_cur(fd) == NULL) {
    // printf("\n\n%s called ", __func__);
    int ret = fdatasync(fd);
    // printf("ret : %d ", ret);
    if (ret < 0)
      // printf(" errno:%d\n", errno);
      return ret;
  }
  printf("\n\n%s called fd:%d\n\n", __func__, fd);
  return nvfsync(fd);
}

int nvfcntl(int fd, int cmd, ...) {
  va_list arg;
  struct flock *f1;
  int flags;
  switch (cmd) {
    case F_SETLK:
      va_start(arg, cmd);
      f1 = va_arg(arg, struct flock *);
      va_end(arg);
      return fcntl(fd_indirection[fd], cmd, f1);
    case F_SETFD:
      va_start(arg, cmd);
      flags = va_arg(arg, int);
      va_end(arg);
      sanitize_flags(&flags);
      return fcntl(fd_indirection[fd], cmd, flags);
    case F_GETFD:
      // return fd flags
      return fcntl(fd_indirection[fd], cmd);
    default:
      // printf("[%s]: the cmd:%d is not defined in %s\n", __func__, cmd,
      // __func__);
      return 0;
  }
}
int nvstat(const char *pathname, struct stat *statbuf) {
  int ret = stat(pathname, statbuf);
  int fd = get_path_fd(pathname);
  statbuf->st_size = fd_table[fd_indirection[fd]].written_file_size;
  return ret;
}
int nvunlink(const char *pathname) {
  int fd = get_path_fd(pathname);
  if (fd > 0) {
    nvclose(fd);
  }

  return unlink(pathname);
}
int nvrename(const char *oldpath, const char *newpath) {
  int fd = get_path_fd(oldpath);
  if (fd > 0) {
    memcpy(fd_table[fd_indirection[fd]].pathname, newpath, strlen(newpath));
  }
  return rename(oldpath, newpath);
}
int nvposix_fadvise(int fd, off_t offset, off_t len, int advice) {
  return posix_fadvise(fd_indirection[fd], offset, len, advice);
}
int nvfstat(int fd, struct stat *statbuf) {
  int ret = fstat(fd, statbuf);
  statbuf->st_size = fd_table[fd_indirection[fd]].written_file_size;
  return ret;
}
int nvsync_file_range(int fd, off64_t offset, off64_t nbytes,
                      unsigned int flags) {
  trunc_fit_fd(fd);
  printf("[%s]:addr:%ld, len:%ld\n", __func__, (long int)fd_table[fd].addr,
         fd_table[fd].written_file_size);
  return nvmsync(fd_table[fd_indirection[fd]].addr + offset, nbytes, MS_ASYNC);
}

int nvfallocate(int fd, int mode, off_t offset, off_t len) {
  // TODO: zero out unwritten area to end of file
  off_t required_len = offset + len;
  size_t current_file_size = fd_table[fd_indirection[fd]].current_file_size;
  printf("\n[%s]\n\n", __func__);

  if (current_file_size < required_len) {
    int ret = fallocate(fd, mode, offset, len);
    if (ret < 0)
      return ret;
    else {
      fd_table[fd_indirection[fd]].current_file_size = required_len;
    }
    return ret;
  } else {
    return fallocate(fd, mode, offset, len);
  }
}
