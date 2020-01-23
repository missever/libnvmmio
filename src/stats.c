#include "stats.h"
#include <sched.h>
#include <unistd.h>
#include "internal.h"
#define BILLION 1000000000L;

const char *func_name[NR_FUNCS] = {
    "nvmemcpy_read_redo",
    "alloc_log",
    "nvmemcpy_write",
    "fsync",
    "check_log",
    "nvmemcpy_memcpy",
    "get_fd_uma",
    "increase_write_count",
    "increase_read_count",
    "nvmmio_fence",
    "nvmmio_write",
    "nvmmio_flush",
    "indexing_log",
    "alloc_log_entry",
    "logging",
    "test",
};

static int get_nrcpus(void) {
  long ret;

  ret = sysconf(_SC_NPROCESSORS_ONLN);
  if (ret < 0) handle_error("sysconf");
  return (int)ret;
}

void init_timer(void) {
  int i;
  int nrcpus = get_nrcpus();

  timestats_percpu = malloc(sizeof(struct timespec *) * NR_FUNCS);

  if (timestats_percpu == NULL) handle_error("malloc");

  for (i = 0; i < NR_FUNCS; i++) {
    timestats_percpu[i] = calloc(nrcpus, sizeof(struct timespec));

    if (timestats_percpu[i] == NULL) handle_error("calloc");
  }

  countstats_percpu = malloc(sizeof(unsigned int *) * NR_FUNCS);

  if (countstats_percpu == NULL) handle_error("malloc");

  for (i = 0; i < NR_FUNCS; i++) {
    countstats_percpu[i] = calloc(nrcpus, sizeof(unsigned int));

    if (countstats_percpu[i] == NULL) handle_error("calloc");
  }
}

void report_time(void) {
  int i, j, nrcpus;
  struct timespec time_sum;
  unsigned int count_sum;
  double total, average;

  nrcpus = get_nrcpus();

  printf("============= TIME =============\n");

  for (i = 0; i < NR_FUNCS; i++) {
    time_sum.tv_sec = 0;
    time_sum.tv_nsec = 0;
    count_sum = 0;

    for (j = 0; j < nrcpus; j++) {
      time_sum.tv_sec += timestats_percpu[i][j].tv_sec;
      time_sum.tv_nsec += timestats_percpu[i][j].tv_nsec;
      count_sum += countstats_percpu[i][j];
    }

    if (count_sum > 0) {
      total = (double)time_sum.tv_nsec;
      average = total / count_sum;
      printf("[%s] total %lf nsec, %d calls, average %lf nsec\n", func_name[i],
             total, count_sum, average);
    }
  }
}
