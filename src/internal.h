#ifndef _LIBNVMMIO_INTERNAL_H
#define _LIBNVMMIO_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define PAGE_SHIFT (12)
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))

#define TABLE_SHIFT (21)
#define TABLE_SIZE (1UL << TABLE_SHIFT)
#define TABLE_MASK (~(TABLE_SIZE - 1))

#define ALIGN_TABLE(addr) (void *)((unsigned long)addr & TABLE_MASK)

#define PTRS_PER_TABLE (1UL << 9) /* 512 */
#define PTRS_PER_LARGE_TABLE (1UL << 5) /* 32 */

typedef enum {
  FALSE = 0,
  TRUE = 1
} boolean_t;

typedef enum {
  UNDO,
  REDO
} log_policy_t;

typedef enum table_type_enum {
  LGD = (PTRS_PER_TABLE * PTRS_PER_TABLE * PTRS_PER_TABLE),
  LUD = (PTRS_PER_TABLE * PTRS_PER_TABLE),
  LMD = (PTRS_PER_TABLE),
  TABLE = 1
} table_type_t;


#if 1
#define DEFAULT_POLICY (UNDO)
#else
#define DEFAULT_POLICY (REDO)
#endif

#define handle_error(msg) \
  do { \
    perror(msg); \
    exit(EXIT_FAILURE); \
  } while (0)

#define handle_error_en(en, msg) \
  do { \
    errno = en; \
    perror(msg); \
    exit(EXIT_FAILURE); \
  } while (0)

#define offset_in_page(p) ((p) & ~PAGE_MASK)

typedef enum {
  LOG_4K,
  LOG_8K,
  LOG_16K,
  LOG_32K,
  LOG_64K,
  LOG_128K,
  LOG_256K,
  LOG_512K,
  LOG_1M,
  LOG_2M,
  NR_LOG_SIZES /* 10 */
} log_size_t;

#define LGD_SHIFT (39)
#define LUD_SHIFT (30)
#define LMD_SHIFT (21)
#define LOG_SHIFT(s) (LMD_SHIFT - ((LMD_SHIFT - PAGE_SHIFT) - s))
#define LOG_SIZE(s) (1UL << LOG_SHIFT(s))
#define LOG_MASK(s) (~(LOG_SIZE(s) - 1))
#define LOG_OFFSET(addr, s) (addr & (LOG_SIZE(s) - 1))
#define NUM_ENTRIES(s) (1UL << (LMD_SHIFT - LOG_SHIFT(s)))

#define MAX_FREE_NODES (1UL << 11) /* 2048 */
#define NR_FILL_NODES (MAX_FREE_NODES >> 1) /* 1024 */
#define LOG_FILE_SIZE (1UL << 32)

#define DATA_PATH "/mnt/pmem_emul/libnvmmio-data-%d.log"
#define ENTRIES_PATH "/mnt/pmem_emul/libnvmmio-entries.log"
#define UMAS_PATH "/mnt/pmem_emul/libnvmmio-umas.log"


//io.h
#define IO_MAP_SIZE (1UL << 32) /* 1GB */
#define FD_LIMIT 1024

#endif /* _LIBNVMMIO_INTERNAL_H */
