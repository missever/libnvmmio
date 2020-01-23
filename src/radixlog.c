#define _GNU_SOURCE
#include "radixlog.h"
#include "allocator.h"
#include "internal.h"
#include "stats.h"

extern free_tables_t *global_tables_list;
static log_table_t *lgd = NULL;

static inline unsigned long lgd_index(unsigned long address) {
  return (address >> LGD_SHIFT) & (PTRS_PER_TABLE - 1);
}

static inline unsigned long lud_index(unsigned long address) {
  return (address >> LUD_SHIFT) & (PTRS_PER_TABLE - 1);
}

static inline unsigned long lmd_index(unsigned long address) {
  return (address >> LMD_SHIFT) & (PTRS_PER_TABLE - 1);
}

inline unsigned long table_index(log_size_t log_size, unsigned long address) {
  // unsigned long nr_entries = 1UL << (LMD_SHIFT - LOG_SHIFT(log_size));
  // return (address >> shift) & (nr_entries - 1);
  return (address >> LOG_SHIFT(log_size)) & (NUM_ENTRIES(log_size) - 1);
}

inline int atomic_increase(int *count) {
  int old, new;

  do {
    old = *count;
    new = *count + 1;
  } while (!__sync_bool_compare_and_swap(count, old, new));

  return new;
}

log_table_t *get_log_table(unsigned long address) {
  log_table_t *lud, *lmd, *table;
  unsigned long index;

  /* LUD */
  index = lgd_index(address);
  lud = lgd->entries[index];

  if (lud == NULL) {
    lud = alloc_log_table(lgd, index, LUD);

    if (!__sync_bool_compare_and_swap(&lgd->entries[index], NULL, lud)) {
      // free(lud);
      lud = lgd->entries[index];
    }
  }

  /* LMD */
  index = lud_index(address);
  lmd = lud->entries[index];

  if (lmd == NULL) {
    lmd = alloc_log_table(lud, index, LMD);

    if (!__sync_bool_compare_and_swap(&lud->entries[index], NULL, lmd)) {
      // free(lmd);
      lmd = lud->entries[index];
    }
  }

  /* Log Table */
  index = lmd_index(address);
  table = lmd->entries[index];

  if (table == NULL) {
    table = alloc_log_table(lmd, index, TABLE);

    if (!__sync_bool_compare_and_swap(&lmd->entries[index], NULL, table)) {
      // free(table);
      table = lmd->entries[index];
    }
  }

  return table;
}

log_table_t *__get_next_table(log_table_t *table, unsigned long *nrpages) {
  log_table_t *parent = table->parent;
  unsigned long i, count;
  unsigned long index = table->index + 1;
  count = NUM_ENTRIES(table->log_size);

  while (*nrpages > 0 && parent != NULL) {
    for (i = index; i<count && * nrpages> 0; i++) {
      if (parent->entries[i]) {
        return parent->entries[i];
      }
      *nrpages -= parent->type;
    }

    if (*nrpages > 0) {
      parent = get_next_table(parent, nrpages);
      index = 0;
    }
  }
  return NULL;
}

log_table_t *get_next_table2(log_table_t *table, table_type_t type) {
  log_table_t *next_table;
  log_table_t *parent = table->parent;
  unsigned long index = table->index + 1;

  if (index == PTRS_PER_TABLE) {
    parent = get_next_table2(parent, type * PTRS_PER_TABLE);
    index = 0;
  }

  next_table = parent->entries[index];

  if (next_table == NULL) {
    next_table = alloc_log_table(parent, index, type);

    if (!__sync_bool_compare_and_swap(&parent->entries[index], NULL,
                                      next_table)) {
      free(next_table);
      next_table = parent->entries[index];
    }
  }
  return next_table;
}

log_table_t *get_next_table(log_table_t *table, unsigned long *nrpages) {
  log_table_t *ret;

  ret = __get_next_table(table, nrpages);

  return ret;
}

/*
 * Find and return the table using the virtual address.
 * If there is no table, NULL is returned.
 */
log_table_t *find_log_table(unsigned long address) {
  log_table_t *lud, *lmd, *table;
  unsigned long index;

  /* LUD */
  index = lgd_index(address);
  lud = lgd->entries[index];

  if (lud == NULL) return NULL;

  /* LMD */
  index = lud_index(address);
  lmd = lud->entries[index];

  if (lmd == NULL) return NULL;

  /* Log Table */
  index = lmd_index(address);
  table = lmd->entries[index];

  return table;
}

/*
 * Find and return the log entry using the virtual address.
 * If there is no table, NULL is returned.
 */
log_entry_t *find_log_entry(unsigned long address) {
  log_table_t *table;
  log_entry_t *entry;
  unsigned long index;

  table = find_log_table(address);

  if (table == NULL) return NULL;

  index = table_index(table->log_size, address);
  entry = table->entries[index];

  return entry;
}

log_entry_t *get_log_entry(unsigned long address, uma_t *uma) {
  log_table_t *table;
  log_entry_t *entry;
  unsigned long index;

  table = get_log_table(address);
  index = table_index(table->log_size, address);

  entry = table->entries[index];

  if (entry == NULL) {
    entry = alloc_log_entry(uma, table->log_size);

    if (__sync_bool_compare_and_swap(&table->entries[index], NULL, entry)) {
      atomic_increase(&table->count);
    } else {
      free_log_entry(entry, table->log_size, false);
      entry = table->entries[index];
    }
  }

  return entry;
}

void init_radixlog(void) {
  if (lgd == NULL) {
    lgd = alloc_log_table(NULL, 0, LGD);
  }
}
