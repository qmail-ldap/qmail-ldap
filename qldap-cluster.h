#ifndef __QLDAP_CLUSTER_H__
#define __QLDAP_CLUSTER_H__

int cluster_init(void);
int cluster(char *mailhost);
stralloc *cluster_me(void);

#endif
