#ifndef _LIBNVMMIO_ALLOCATOR_H
#define _LIBNVMMIO_ALLOCATOR_H

#include <stdbool.h>

#include "internal.h"
#include "radixlog.h"
#include "uma.h"

typedef struct list_node_struct {
  struct list_node_struct *next;
  void *ptr;
} list_node_t;

typedef struct free_table_struct {
  unsigned long count;
  struct log_table_struct **table_array;
} free_tables_t;

struct list_node_struct *alloc_list_node(void);
struct mmap_area_struct *alloc_uma(void);
void free_uma(struct mmap_area_struct *uma);
struct log_table_struct *alloc_log_table(struct log_table_struct *parent, int index,
                                       enum table_type_enum);
struct log_entry_struct *alloc_log_entry(struct mmap_area_struct *uma, log_size_t log_size);
void free_log_entry(struct log_entry_struct *entry, log_size_t log_size, bool sync);
void release_local_list(void);
void init_global_freelist(void);

void exit_background_table_alloc_thread(void);

#endif /* _LIBNVMMIO_ALLOCATOR_H */
