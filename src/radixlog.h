#ifndef _LIBNVMMIO_RADIXLOG_H
#define _LIBNVMMIO_RADIXLOG_H

#include "allocator.h"
#include "internal.h"
#include "uma.h"

typedef struct log_entry_struct {
  union {
    struct {
      unsigned long united;
    };
    struct {
      unsigned long epoch : 20;
      unsigned long offset : 21;
      unsigned long len : 22;
      unsigned long policy : 1;
    };
  };
  void *data;
  void *dst;
  pthread_rwlock_t *rwlockp;
} log_entry_t;

typedef struct log_table_struct {
  int count;
  log_size_t log_size;
  enum table_type_enum type;
  struct log_table_struct *parent;
  int index;
  void *entries[PTRS_PER_TABLE];
} log_table_t;

void init_radixlog(void);
unsigned long table_index(log_size_t log_size, unsigned long address);
struct log_entry_struct *find_log_entry(unsigned long address);
struct log_table_struct *find_log_table(unsigned long address);
struct log_entry_struct *get_log_entry(unsigned long address,
                                       struct mmap_area_struct *uma);
struct log_table_struct *get_log_table(unsigned long address);
struct log_table_struct *get_next_table(struct log_table_struct *table,
                                        unsigned long *nrpages);
struct log_table_struct *get_next_table2(struct log_table_struct *table,
                                         table_type_t type);
int atomic_increase(int *count);

#endif /* _LIBNVMMIO_RADIXLOG_H */
