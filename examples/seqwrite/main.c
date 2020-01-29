#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <libnvmmio.h>

#define handle_error(msg) \
	do {                    \
		perror(msg);          \
		exit(EXIT_FAILURE);   \
	} while (0)

#define FILE_PATH "/mnt/pmem/testfile"
#define FILE_SIZE (1UL << 26)
#define BUF_SIZE (1UL << 10)

int main(void) {
	char buf[BUF_SIZE];
	off_t i;
	int fd, s;

	memset(buf, 0, BUF_SIZE);

	fd = open(FILE_PATH, O_CREAT | O_RDWR | O_ATOMIC);
	if (fd == -1) {
		handle_error("open");
	}

	for (i = 0; i < FILE_SIZE; i += BUF_SIZE) {
		write(fd, buf, BUF_SIZE);
	}

	s = close(fd);
	if (s != 0) {
		handle_error("close");
	}
	return 0;
}
