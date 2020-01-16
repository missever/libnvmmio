#ifndef _LIBNVMMIO_STATS_H
#define _LIBNVMMIO_STATS_H
#define _GNU_SOURCE
//#define MEASURE_TIME
#include <sched.h>
enum time_category {
  nvmemcpy_read_redo_t,
  alloc_log_t,
  nvmemcpy_write_t,
  fsync_t,
  check_log_t,
  nvmemcpy_memcpy_t,
  get_fd_uma_t,
  increase_write_count_t,
  increase_read_count_t,
  nvmmio_fence_t,
  nvmmio_write_t,
  nvmmio_flush_t,
  indexing_log_t,
  alloc_log_entry_t,
  logging_t,
  test_t,
  NR_FUNCS,
};

struct timespec **timestats_percpu;
unsigned int **countstats_percpu;

#ifdef MEASURE_TIME
#define LIBNVMMIO_INIT_TIME(x) struct timespec x = {0}

#define LIBNVMMIO_START_TIME(name, start) \
{ \
  if (clock_gettime(CLOCK_REALTIME, &start) == -1) { \
    handle_error("clock gettime"); \
  } \
}

#define LIBNVMMIO_END_TIME(name, start) \
{ \
  LIBNVMMIO_INIT_TIME(end); \
  if (clock_gettime(CLOCK_REALTIME, &end) == -1) { \
    handle_error("clock gettime"); \
  } \
  long sec = end.tv_sec - start.tv_sec; \
  long nsec = end.tv_nsec - start.tv_nsec; \
  if (start.tv_nsec > end.tv_nsec) { \
    --sec; nsec += 1000000000; \
  } \
  int cpu = sched_getcpu(); \
  timestats_percpu[name][cpu].tv_sec += sec; \
  timestats_percpu[name][cpu].tv_nsec += nsec; \
  countstats_percpu[name][cpu] += 1; \
}
#else
#define LIBNVMMIO_INIT_TIME(x) {}
#define LIBNVMMIO_START_TIME(name, start) {}
#define LIBNVMMIO_END_TIME(name, start) {}
#endif

void init_timer(void);
void report_time(void);

#endif //_LIBNVMMIO_STATS_H
