#include <sys/types.h>
#include <unistd.h>

#include "readwrite.h"

int
subread(int fd, void *buf, int size)
{
	return (int)read(fd, buf, size);
}

int
subwrite(int fd, void *buf, int size)
{
	return (int)write(fd, buf, size);
}

