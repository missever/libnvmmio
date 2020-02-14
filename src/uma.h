#ifndef _LIBNVMMIO_UMA_H
#define _LIBNVMMIO_UMA_H
#define _GNU_SOURCE

#include <pthread.h>
#include <sys/types.h>

#include "list.h"
#include "rbtree.h"

#define MAX_NR_UMAS (1UL << 10)
#define SYNC_PERIOD (10)

typedef enum { UNDO, REDO } log_policy_t;

#if 0
#define DEFAULT_POLICY (UNDO)
#else
#define DEFAULT_POLICY (REDO)
#endif

typedef struct sync_thread_struct {
  int id;
  pthread_t tid[2];
  // pthread_cond_t cond;
  // pthread_mutex_t mutex;
  void *uma;
} sync_thread_t;

typedef struct mmap_area_struct {
  unsigned long epoch;
  unsigned long policy;
  void *start;
  void *end;
  unsigned long ino;
  off_t offset;
  unsigned long read;
  unsigned long write;
  struct thread_info_struct *tinfo;
  pthread_rwlock_t *rwlockp;
  struct rb_node rb;
  struct list_head list;
  int id;
  pthread_t sync_thread;
} uma_t;

typedef struct list_struct {
  struct list_head header;
  pthread_rwlock_t rwlock;
} list_t;

void init_uma(void);
void insert_uma_rbtree(struct mmap_area_struct *new_uma);
void insert_uma_syncthreads(uma_t *new_uma);
void insert_uma_fdarray(int fd, uma_t *new_uma);
uma_t *get_uma_fdarray(int fd);
struct mmap_area_struct *find_uma(const void *addr);
void delete_uma_rbtree(struct mmap_area_struct *uma);
void delete_uma_syncthreads(struct mmap_area_struct *uma);
void delete_uma_fdarray(int fd);
struct list_struct *get_uma_list(void);
void increase_uma_read_cnt(struct mmap_area_struct *uma);
void increase_uma_write_cnt(struct mmap_area_struct *uma);

#endif /* _LIBNVMMIO_UMA_H */
