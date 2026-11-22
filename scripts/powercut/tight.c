/* Calls with nothing between them, for scripts/powercut/ext4.sh (case 4o).
 *
 * usage: tight <directory> <fsync|fdatasync>
 *
 * In the directory: writes a file and makes it and the directory durable,
 * unlinks the file "victim" (which the caller made and synced), overwrites
 * the first file inside its length, and syncs it. A shell puts
 * milliseconds between such calls; here the overwrite may fall within the
 * tick of the kernel's clock in which the file was last changed, and then
 * change nothing in its inode. Whether it did is printed: the coarse clock
 * (the one file times are taken from) is read after the first write and
 * after the overwrite. The file is not looked at with stat, which would
 * make the kernel take a finer time for its next change.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *what) {
    perror(what);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int data_only = strcmp(argv[2], "fdatasync") == 0;
    int dir = open(argv[1], O_RDONLY | O_DIRECTORY);
    if (dir < 0) return fail("open directory");
    int fd = openat(dir, "over", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return fail("open");
    struct timespec before, after;
    if (write(fd, "0123456789", 10) != 10) return fail("write");
    clock_gettime(CLOCK_REALTIME_COARSE, &before);
    if (fsync(fd) != 0) return fail("fsync");
    if (fsync(dir) != 0) return fail("fsync directory");
    if (unlinkat(dir, "victim", 0) != 0) return fail("unlink");
    if (pwrite(fd, "XXXX", 4, 0) != 4) return fail("pwrite");
    clock_gettime(CLOCK_REALTIME_COARSE, &after);
    if ((data_only ? fdatasync(fd) : fsync(fd)) != 0) return fail("sync");
    close(fd);
    close(dir);
    if (before.tv_sec == after.tv_sec && before.tv_nsec == after.tv_nsec)
        printf("within one tick");
    else
        printf("%ld us apart by the coarse clock", (long)((after.tv_sec - before.tv_sec) * 1000000 + (after.tv_nsec - before.tv_nsec) / 1000));
    return 0;
}
