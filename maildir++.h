#ifndef __MAILDIRPP_H__
#define __MAILDIRPP_H__

void quota_add(int fd, long int size, int count, char *quota, char *dir);
void quota_rm(int fd, long int size, int count);
int quota_maildir(char *dir, char *quota, int *fd, long int mailsize, 
				  int mailcount);
void get_quota(char *quota, long int *size, int *count);

#endif
