#ifndef __CHECKPASSWORD_H__
#define __CHECKPASSWORD_H__

struct credentials {
	int		uid;
	int		gid;
	stralloc	home;
	stralloc	maildir;
	stralloc	forwarder;
};

int check(stralloc *, stralloc *, struct credentials *, int);
int check_ldap(stralloc *, stralloc *, struct credentials *, int);
void check_credentials(struct credentials *);
void change_uid(int, int);
void setup_env(char *, struct credentials *);
void chdir_or_make(char *, char *);

#ifdef QLDAP_CLUSTER
void forward(char *, char *, struct credentials *);
#endif

#endif
