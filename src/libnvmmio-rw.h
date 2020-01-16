#ifndef _LIBNVMMIO_IO_H
#define _LIBNVMMIO_IO_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <sys/uio.h>
#include <sys/stat.h>

extern int nvunlink(const char *pathname);

#define creat(filename,mode) nvcreat(filename,mode)
extern int nvcreat(const char *filename, mode_t mode);
#define open(...) nvopen( __VA_ARGS__)
extern int nvopen(const char* Path, int flags , ...);
#define close(fd) nvclose(fd)
extern int nvclose(int fd);
#define read(fd,buf,cnt) nvread(fd,buf,cnt)
extern ssize_t nvread (int fd, void* buf, size_t cnt);
#define write(fd,buf,cnt) nvwrite(fd,buf,cnt)
extern ssize_t nvwrite(int fd, const void* buf, size_t cnt);
#define lseek(fd,offset,whence) nvlseek(fd,offset,whence)
extern off_t nvlseek(int fd, off_t offset, int whence);
#define truncate(fd,length) nvtruncate(fd,length)
extern int nvftruncate(int fd, off_t length);
#define fsync(fd) nvfsync(fd)
extern int nvfsync(int fd);

#define pread(fd, buf, count, offset) nvpread(fd, buf, count, offset)
extern ssize_t nvpread(int fd, void *buf, size_t cnt, off_t offset);
#define pwrite(fd, buf, count, offset) nvpwrite(fd, buf, count, offset)
extern ssize_t nvpwrite(int fd, const void *buf, size_t cnt, off_t offset);
/*
#define fdatasync(fd) nvfdatasync(fd)
extern int nvfdatasync(int fd);
*/
#define preadv(fd, iov, iovcnt, offset) nvpreadv(fd, iov, iovcnt, offset)
extern ssize_t nvpreadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
#define pwritev(fd, iov, iovcnt, offset) nvpwritev(fd, iov, iovcnt, offset)
extern ssize_t nvpwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
#define readv(fd, iov, iovcnt) nvreadv(fd, iov, iovcnt)
extern ssize_t nvreadv(int fd, const struct iovec *iov, int iovcnt);
#define writev(fd, iov, iovcnt) nvwritev(fd, iov, iovcnt)
extern ssize_t nvwritev(int fd, const struct iovec *iov, int iovcnt);
//***********************
/*
#define fcntl(...) nvfcntl(__VA_ARGS__)
extern int nvfcntl(int fd, int cmd, ...); //F_FULLFSYNC F_SETLK F_SETFD  F_GETFD
#define stat(pathname, statbuf) nvstat(pathname, statbuf)
extern int nvstat(const char *pathname, struct stat *statbuf);
#define unlink(pathname) nvunlink(pathname)
extern int nvunlink(const char *pathname);
#define rename(oldpath, newpath) nvrename(oldpath, newpath)
extern int nvrename(const char *oldpath, const char *newpath);
#define posix_fadvise(fd, offset, len, advice) nvposix_fadvise(fd, offset, len, advice)
extern int nvposix_fadvise(int fd, off_t offset, off_t len, int advice);

sqlite

#define access() nvaccess()
extern nvaccess();
#define getcwd() nvgetcwd()
extern nvcwd();
#define openDirectory() nvopenDirectory()
extern nvopenDirectory();
#define fchown() nvfchown()
extern nvfchown();
#define fchmod() nvfchmod()
extern nvfchmod();
#define ioctl() nvioctl()
extern nvioctl();
#define getpagesize() nvgetpagesize()
extern nvgetpagesize();
*/
#define fstat(fd, statbuf) nvfstat(fd, statbuf)
extern int nvfstat(int fd, struct stat *statbuf);
//#define sync_file_range(fd, offset, nbytes, flags) nvsync_file_range(fd, offset, nbytes, flags)
//extern int nvsync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags);
#define fallocate(fd, mode, offset, len) nvfallocate(fd, mode, offset, len)
extern int nvfallocate(int fd, int mode, off_t offset, off_t len);
#define posix_fallocate(fd, offset, len) nvposix_fallocate(fd, offset, len)
extern int nvposix_fallocate(int fd, off_t offset, off_t len);
#define pread64(fd, buf, count, offset) nvpread64(fd, buf, count, offset)
extern ssize_t nvpread64(int fd, void *buf, size_t cnt, off_t offset);
#define pwrite64(fd, buf, count, offset) nvpwrite64(fd, buf, count, offset)
extern ssize_t nvpwrite64(int fd, const void *buf, size_t cnt, off_t offset);
/*
#define readlink() nvreadlink()
extern nvreadlink();
#define lstat() nvlstat()
extern nvlstat();
*/

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _LIBNVMMIO_IO_H
