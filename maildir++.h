#ifndef __MAILDIRPP_H__
#define __MAILDIRPP_H__

typedef struct {
	unsigned long quota_size;
	unsigned long quota_count;
	long size;
	long count;
} quota_t;

void quota_add(int , unsigned long , unsigned long);
void quota_rm(int , unsigned long , unsigned long);
int quota_calc(const char *, int *fd, quota_t *);
int quota_recalc(const char *, int *fd, quota_t *);
int quota_check(quota_t *, unsigned long , unsigned long , int *);
void quota_get(quota_t *, char const *);

#endif
