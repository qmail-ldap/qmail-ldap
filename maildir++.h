#ifndef __MAILDIRPP_H__
#define __MAILDIRPP_H__

typedef struct {
	unsigned long quota_size;
	unsigned long quota_count;
	long size;
	long count;
} quota_t;

void quota_add(int fd, unsigned long size, unsigned long count);
void quota_rm(int fd, unsigned long size, unsigned long count);
int quota_calc(char *dir, int *fd, quota_t *q);
int quota_recalc(char *dir, int *fd, quota_t *q);
int quota_check(quota_t *q, unsigned long size, unsigned long count, int *perc);
void quota_get(quota_t *q, char *quota);

#endif
