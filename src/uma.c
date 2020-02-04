#define _GNU_SOURCE

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "allocator.h"
#include "internal.h"
#include "list.h"
#include "rbtree.h"
#include "uma.h"
#include "debug.h"

#define UMACACHE_BITS (3)
#define UMACACHE_SIZE (1U << UMACACHE_BITS)
#define UMACACHE_MASK (UMACACHE_SIZE - 1)
#define UMACACHE_HASH(addr) ((addr >> PAGE_SHIFT) & UMACACHE_MASK)

typedef struct rbtree_struct {
  struct rb_root root;
  pthread_rwlock_t rwlock;
} rbtree_t;

static list_t uma_list;
static uma_t *uma_fdarray[MAX_NR_UMAS];

static rbtree_t *uma_rbtree = NULL;
static __thread uma_t *uma_cache[UMACACHE_SIZE];

#if 0
list_t *get_uma_list(int index) {
  return &uma_list[index];
}
#endif
list_t *get_uma_list(void) { return &uma_list; }

static inline void umacache_update(unsigned long addr, uma_t *uma) {
  uma_cache[UMACACHE_HASH(addr)] = uma;
}

static inline uma_t *find_uma_cache(const void *addr) {
  uma_t *uma;
  unsigned long i;

  for (i = 0; i < UMACACHE_SIZE; i++) {
    uma = uma_cache[i];

    if (uma != NULL && uma->start <= addr && addr < uma->end) return uma;
  }
  return NULL;
}

static inline uma_t *find_uma_rbtree(const void *addr) {
  uma_t *uma;
  struct rb_node *node;
  int s;

  s = pthread_rwlock_rdlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_rdlock");
  }

  node = uma_rbtree->root.rb_node;

  while (node) {
    uma = rb_entry(node, uma_t, rb);

    if (addr < uma->end) {
      if (uma->start <= addr) {
        s = pthread_rwlock_unlock(&uma_rbtree->rwlock);
        if (__glibc_unlikely(s != 0)) {
          handle_error("pthread_rwlock_unlock");
        }
        umacache_update((unsigned long)addr, uma);
        goto find_uma_rbtree_success;
      }
      node = node->rb_left;
    } else {
      node = node->rb_right;
    }
  }

  s = pthread_rwlock_unlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }

  return NULL;

find_uma_rbtree_success:
  return uma;
}

uma_t *find_uma(const void *addr) {
  uma_t *uma;

  uma = find_uma_cache(addr);
  if (uma != NULL && uma->epoch > 0) {
    goto find_uma_out;
  }
  uma = find_uma_rbtree(addr);

find_uma_out:
  return uma;
}

void insert_uma_rbtree(uma_t *new_uma) {
  struct rb_node **node, *parent;
  uma_t *uma;
  int s;

  s = pthread_rwlock_wrlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_wrlock");
  }

  node = &uma_rbtree->root.rb_node;
  parent = NULL;

  while (*node) {
    uma = rb_entry(*node, uma_t, rb);
    parent = *node;

    if (new_uma->end <= uma->start) {
      node = &((*node)->rb_left);
    } else if (uma->end <= new_uma->start) {
      node = &((*node)->rb_right);
    } else {
      handle_error("overlapped uma");
    }
  }
  rb_link_node(&new_uma->rb, parent, node);
  rb_insert_color(&new_uma->rb, &uma_rbtree->root);

  s = pthread_rwlock_unlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }
}

void insert_uma_syncthreads(uma_t *new_uma) {
  int s;

  LIBNVMMIO_DEBUG("uma id = %d", new_uma->id);

  s = pthread_rwlock_wrlock(&uma_list.rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_wrlock");
  }

  list_add(&new_uma->list, &uma_list.header);

  s = pthread_rwlock_unlock(&uma_list.rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }
}

void insert_uma_fdarray(int fd, uma_t *new_uma) { uma_fdarray[fd] = new_uma; }

uma_t *get_uma_fdarray(int fd) { return uma_fdarray[fd]; }

void delete_uma_rbtree(uma_t *uma) {
  int s;

  s = pthread_rwlock_wrlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_wrlock");
  }

  rb_erase(&uma->rb, &uma_rbtree->root);
  free_uma(uma);

  s = pthread_rwlock_unlock(&uma_rbtree->rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }
}

void delete_uma_syncthreads(uma_t *uma) {
  int s;

  s = pthread_rwlock_wrlock(&uma_list.rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_wrlock");
  }

  list_del(&uma->list);

  s = pthread_rwlock_unlock(&uma_list.rwlock);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_unlock");
  }
}

void delete_uma_fdarray(int fd) { uma_fdarray[fd] = NULL; }

void init_uma(void) {
  unsigned long i;
  int s;

  if (uma_rbtree == NULL) {
    uma_rbtree = (rbtree_t *)malloc(sizeof(rbtree_t));

    if (__glibc_unlikely(uma_rbtree == NULL)) {
      handle_error("malloc for uma_rbtree");
    }
    uma_rbtree->root = RB_ROOT;

    /*
    for (i = 0; i < NR_SYNC_THREADS; i++) {
      INIT_LIST_HEAD(&uma_rbtree->uma_array[i]);
    }
    */

    s = pthread_rwlock_init(&uma_rbtree->rwlock, NULL);
    if (__glibc_unlikely(s != 0)) {
      handle_error("pthread_rwlock_init");
    }
  }

#if 0
  for (i = 0; i < NR_SYNC_THREADS; i++) {
    s = pthread_rwlock_init(&uma_list[i].rwlock, NULL);
    if (__glibc_unlikely(s != 0)) {
      handle_error("pthread_rwlock_init");
    }

    INIT_LIST_HEAD(&uma_list[i].header);
  }
#endif
  s = pthread_rwlock_init(&uma_list.rwlock, NULL);
  if (__glibc_unlikely(s != 0)) {
    handle_error("pthread_rwlock_init");
  }

  INIT_LIST_HEAD(&uma_list.header);

  for (i = 0; i < MAX_NR_UMAS; i++) {
    uma_fdarray[i] = NULL;
  }
}
