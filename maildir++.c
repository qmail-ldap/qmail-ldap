#include <sys/types.h>
#include <sys/stat.h>
#include "readwrite.h"
#include "stralloc.h"
#include "str.h"
#include "open.h"
#include "substdio.h"
#include "getln.h"
#include "error.h"
#include <dirent.h>
#include "strerr.h"
#include "fmt.h"
#include "scan.h"
#include "now.h"
#include "seek.h"
#include "sig.h"
#include "maildir++.h"

static void temp_nomem() { strerr_die1x(111,"Out of memory. (QUOTA #)"); }

static int check_maxtime(char *dir, time_t time);
static void calc_size(char *dir, long int *size, int *count, time_t *maxtime);
static int parse_quota(substdio *ss, long int *size, int *count, int *lines);
static unsigned int replace(char *s, register unsigned int len,
							register char f, register char r);

static stralloc	foo = {0};
static stralloc	foo2 = {0};
static stralloc	maildirsize ={0};
static char		buf[1024];

/* alarm handler */
static void sigalrm() { unlink(foo.s); 
	strerr_die1x(111,"Timeout while writing maildirsize. (QUOTA #)"); }

void quota_add(int fd, long int size, int count)
/* add size and count to the quota (maildirsize) */
{
	char		num[FMT_ULONG];
	seek_pos	pos;
	substdio	ss;
	
	seek_end(fd);
	pos = seek_cur(fd); /* for savety */
	
	substdio_fdbuf(&ss,write,fd,buf,sizeof(buf));
	/* create string of the form '1232 12\n' and add it to the quota */
	if ( ! stralloc_ready(&foo2, 2*FMT_ULONG+2) ) temp_nomem();
	if ( ! stralloc_copyb(&foo2, num, fmt_ulong(num, (long) size) ) ) 
		temp_nomem();
	if ( ! stralloc_cats(&foo2, " ") ) temp_nomem();
	if ( ! stralloc_catb(&foo2, num, fmt_ulong(num, (long) count) ) ) 
		temp_nomem();
	if ( ! stralloc_cats(&foo2, "\n") ) temp_nomem();
	if (substdio_put(&ss, foo2.s, foo2.len) == -1) goto addfail;
	if (substdio_flush(&ss) == -1) goto addfail; 
	if (fsync(fd) == -1) goto addfail; 
	if (close(fd) == -1) goto addfail; 
	return;
	
addfail:
	strerr_warn3("Unable to add quota: ", error_str(errno), ". (QUOTA #)",0);
	seek_trunc(fd,pos); /* recover from error */
	close(fd);
	_exit(111);
}
			
void quota_rm(int fd, long int size, int count)
/* remove size and count from the quota (maildirsize) *
 * both size and count are POSITVE integers           */
{
	char		num[FMT_ULONG];
	seek_pos	pos;
	substdio	ss;
	
	seek_end(fd);
	pos = seek_cur(fd); /* again savety */
	
	substdio_fdbuf(&ss,write,fd,buf,sizeof(buf));
	/* create string of the form '-1232 -12\n' and add it to the quota */
	if ( ! stralloc_ready(&foo2, 2*FMT_ULONG+4) ) temp_nomem();
	if ( ! stralloc_copys(&foo2, "-") ) temp_nomem();
	if ( ! stralloc_catb(&foo2, num, fmt_ulong(num, (long) size) ) ) 
		temp_nomem();
	if ( ! stralloc_cats(&foo2, " -") ) temp_nomem();
	if ( ! stralloc_catb(&foo2, num, fmt_ulong(num, (long) count) ) ) 
		temp_nomem();
	if ( ! stralloc_cats(&foo2, "\n") ) temp_nomem();
	if (substdio_put(&ss, foo2.s, foo2.len) == -1) goto rmfail;
	if (substdio_flush(&ss) == -1) goto rmfail; 
	if (fsync(fd) == -1) goto rmfail; 
	if (close(fd) == -1) goto rmfail; 
	return;
	
rmfail:
	strerr_warn3("Unable to remove quota: ", error_str(errno), ". (QUOTA #)",0);
	seek_trunc(fd,pos); /* recover form error */
	close(fd);
	_exit(111);
}

int quota_maildir(char *dir, char *quota, int *fd, long int mailsize, 
				  int mailcount)
/* quota dir and subdirs, return the percentage of the quota use (0-100)  *
 * -1 is an error (race condition). Add mailsize and mailcount to the     *
 * current calculations. Quota is the acctual quota in maildirsize fromat *
 * if the quota is NULL then the old quota is used                        */
{
	char		num[FMT_ULONG];
	long int	size = 0;
	long int	q_size;
	int			count = 0;
	int			q_count;
	int			match;
	int			newf = 0;
	int			loop;
	int			pid;
	int			lines = -1;
	struct stat	st;
	substdio	ss;
	time_t		maxtime;
	time_t		tm;
	char		*s;

	tm = now();
	
	if ( ! stralloc_copys(&maildirsize, dir) ) temp_nomem();
	if ( ! stralloc_cats(&maildirsize, "/maildirfolder") ) temp_nomem();
	if ( ! stralloc_0(&maildirsize) ) temp_nomem();
	
	if ( stat(maildirsize.s, &st) == -1 ) { /* are we in a subdir ? */
		if ( errno != error_noent ) goto fail;
	} else {
		size = str_len(dir);
		while( dir <= (dir + --size) ) {
			if ( dir[size] == '/' ) {
				dir[size] = '\0';
				break;
			}
		}
		return quota_maildir(dir, quota, fd, mailsize, mailcount);
	}
	/* we are not in a subdir, test if maildirsize is present */
	if ( ! stralloc_copys(&maildirsize, dir) ) temp_nomem();
	if ( ! stralloc_cats(&maildirsize, "/maildirsize") ) temp_nomem();
	if ( ! stralloc_0(&maildirsize) ) temp_nomem();

	errno = 0;	
	if ( stat(maildirsize.s, &st) == -1 && errno != error_noent ) goto fail;

	if (quota) 
		get_quota(quota, &q_size, &q_count); 
		/* if a quota was specified get the figures */
	if ( errno == error_noent || st.st_size >= 5120 ) { 
		/* get_quota dosn't change errno */
		if ( !quota ) {
			/* if no quota was specified, we can not calculate 
			 *  the current percentage */
			*fd = -1;
			return -1;
		}
		newf = 1;
		/* maildirsize is not present or to big, recalculate ... */
		calc_size(dir, &size, &count, &maxtime);
	} else {
		/* maildirsize is present, try to read it */
		if ( ( *fd = open_read(maildirsize.s) ) == -1 ) goto fail;

		substdio_fdbuf(&ss,read,*fd,buf,sizeof(buf));
		/* get the first line and check if the entry is still correct */
		if (getln(&ss,&foo,&match,'\n') != 0) {
			/* bad thing happened ... */
			if ( unlink(maildirsize.s) == -1 && errno != error_noent ) 
				goto fail;
			newf = 1;
			calc_size(dir, &size, &count, &maxtime);
		} else {
			if (!match && !foo.len) {
				/* maildirsize seems to be empty ... */
				if ( unlink(maildirsize.s) == -1 && errno != error_noent ) 
					goto fail;
				newf = 1;
				calc_size(dir, &size, &count, &maxtime);
			} else {
				/* get the quota settings */
				if ( ! stralloc_0(&foo) ) temp_nomem();
				get_quota(foo.s, &size, &count);
				if ( quota ) {
					/* compare if the settings have changed */
					if ( size == q_size || count == q_count ) {
						/* finaly parse the maildirsize */
						size = 0; count = 0;
						if ( parse_quota(&ss, &size, &count, &lines) == -1 || 
								lines == 0 ) {
							if ( unlink(maildirsize.s) == -1 && 
									errno != error_noent ) goto fail;
							newf = 1;
							calc_size(dir, &size, &count, &maxtime);
						}
					} else {
						if ( unlink(maildirsize.s) == -1 && 
								errno != error_noent ) goto fail;
						size = 0; count = 0;
						/* rewrite and recalculate the file */
						newf = 1;
						calc_size(dir, &size, &count, &maxtime);
					}
				} else {
					if ( parse_quota(&ss, &size, &count, &lines) == -1 || 
							lines == 0 ) {
						*fd = -1;
						return -1;
					}
				}
			}
		}
		close(*fd);
	}
	
	match = -1;
	if ( newf ) {
		if ( check_maxtime(dir, maxtime) ) {
			/* race condition, delete maildir size */
			unlink(maildirsize.s);
			*fd = -1;
			return -1;
		} else {
			/* write maildirsize in standart Maildir manner */
			sig_alarmcatch(sigalrm);
			for (loop = 0; ; ++loop) {
				maxtime = now();
				pid = getpid();
				if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
				if ( ! stralloc_cats(&foo, "/tmp/maildirsize.") ) temp_nomem();
				if ( ! stralloc_readyplus(&foo, 2*FMT_ULONG+2) ) temp_nomem();
				if ( ! stralloc_0(&foo) ) temp_nomem();
				s = foo.s;
				while (*s) s++;
				s += fmt_ulong(s,maxtime); *s++ = '.';
				s += fmt_ulong(s,pid); *s++ = 0;
				if (stat(foo.s,&st) == -1) if (errno == error_noent) break;
				/* really should never get to this point */
				if (loop == 2) _exit(1);
				sleep(2);
			}

			alarm(86400);
			
			if ( ( *fd = open_excl(foo.s) ) == -1 ) goto fail;
			substdio_fdbuf(&ss,write,*fd,buf,sizeof(buf));
			if (substdio_puts(&ss,quota) == -1) goto fail;
			if (substdio_puts(&ss,"\n") == -1) goto fail;
			if ( ! stralloc_ready(&foo2, 2*FMT_ULONG+2) ) temp_nomem();
			if ( ! stralloc_copyb(&foo2, num, fmt_ulong(num, (long) size) ) ) 
				temp_nomem();
			if ( ! stralloc_cats(&foo2, " ") ) temp_nomem();
			if ( ! stralloc_catb(&foo2, num, fmt_ulong(num, (long) count) ) ) 
			   temp_nomem();
			if ( ! stralloc_cats(&foo2, "\n") ) temp_nomem();
			if (substdio_put(&ss, foo2.s, foo2.len) == -1) goto fail;
			if (substdio_flush(&ss) == -1) goto fail; 
			if (fsync(*fd) == -1) goto fail; 
			if (close(*fd) == -1) goto fail; /* NFS dorks */
			if ( unlink(maildirsize.s) == -1 && errno != error_noent ) 
				goto fail;
			if (link(foo.s,maildirsize.s) == -1) goto fail;
			unlink(foo.s);
			
			/* unset the alarm, else %*#! may happen */
			alarm(0);
			sig_alarmdefault();
		}
	}
	match = 0;
	
	/* open file in appendmode for later use */
	if ( ( *fd = open_append(maildirsize.s) ) == -1 ) goto fail;
	
	/* now calculate the acctual quota percentage */
	if ( q_size ) {
		size = (int) ( ( (size + mailsize)*100.0 )/(double) q_size );
		size = (size > 100) ? 100 : size;
	} else
		size = 0;
	if ( q_count ) {
		count = (int) ( ( (count + mailcount)*100.0)/(double) q_count );
		count = (count > 100) ? 100 : count;
	} else 
		count = 0;
	if ( count == 100 || size == 100 ) {
		/* if over quota and maildirsize longer then 1 line or older then 
		 * 15 min dump maildirsize and recalculate the quota */
		if ( !newf && (lines > 1 || tm > st.st_mtime + 15*60) ) {
			if ( unlink(maildirsize.s) == -1 && errno != error_noent ) 
				goto fail;
			return quota_maildir(dir, quota, fd, mailsize, mailcount);
		}
	}
	/* release some buffers */
	if ( ! stralloc_copys(&foo, "") ) temp_nomem();
	if ( ! stralloc_copys(&foo2, "") ) temp_nomem();
	if ( ! stralloc_copys(&maildirsize, "") ) temp_nomem();

	return (count>size) ? count : size;
	/* 100 is quota full 0 is quota empty */

	fail: 
		strerr_warn3("Problems while trying to get maildirsize: ", 
					 error_str(errno), ". (QUOTA #)", 0);
		if ( match == -1 ) unlink(foo.s);
		_exit(111);
}

static int check_maxtime(char *dir, time_t time)
/* check if a directory has changed, to avoid race conditions */
{
	struct dirent *dp;
	DIR *dirp;
	struct stat filest;
	
	dirp = opendir(dir);
	while ( dirp && (dp = readdir(dirp)) != 0) {
		if ( dp->d_name[0] == '.' && dp->d_name[1] != '\0' && 
			   dp->d_name[1] != '.' && !str_diff( ".Trash", dp->d_name) ) {
			if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
			if ( ! stralloc_cats(&foo, dp->d_name) ) temp_nomem();
			if ( ! stralloc_cats(&foo, "/cur") ) temp_nomem();
			if ( ! stralloc_0(&foo) ) temp_nomem();
			if ( stat( foo.s, &filest ) == 0 && filest.st_mtime > time) {
				return 1;
			}
			if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
			if ( ! stralloc_cats(&foo, dp->d_name) ) temp_nomem();
			if ( ! stralloc_cats(&foo, "/new") ) temp_nomem();
			if ( ! stralloc_0(&foo) ) temp_nomem();
			if ( stat( foo.s, &filest ) == 0 && filest.st_mtime > time) {
				return 1;
			}
		}
		if ( !str_diff( "new", dp->d_name ) ) {
			if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
			if ( ! stralloc_cats(&foo, "/new") ) temp_nomem();
			if ( stat(foo.s, &filest ) == 0 && filest.st_mtime > time) {
				return 1;
			}
		}
		if ( !str_diff( "cur", dp->d_name ) ) {
			if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
			if ( ! stralloc_cats(&foo, "/cur") ) temp_nomem();
			if ( stat(foo.s, &filest ) == 0 && filest.st_mtime > time) {
				return 1;
			}
		}
	}
	return 0;
}

static int get_file_size(char *dir, char *name, struct stat *st)
/* get the filesize of the file name in dir, via the name or a stat */
{
	char	*s = dir;

	while (*s) {
		if ( *s != ',' || s[1] != 'S' || s[2] != '=' ) {
			s++;
		} else {
			s += 3;
			st->st_size = 0;
			while ( *s > '0' && *s < '9' )
				st->st_size = st->st_size*10 + (*s - '0');
			return 0;
		}
	}
	/* stat the file */
	if ( ! stralloc_copys(&foo2, dir) ) temp_nomem();
	if ( ! stralloc_cats(&foo2, name) ) temp_nomem();
	if ( ! stralloc_0(&foo2) ) temp_nomem();

	if ( stat( foo2.s, st) == 0 ) return 0;
	return -1;
}

static void calc_curnew(char *dir, long int *size, int *count, time_t *maxtime)
/* calculate the size of the two dirs new and cur of a maildir 
 * (uses get_file_size) */
{
	struct dirent	*dp;
	DIR				*dirp;
	struct stat		filest;
	char			*f;

	if ( ! stralloc_copys(&foo, dir) ) temp_nomem();
	if ( ! stralloc_cats(&foo, "/new/") ) temp_nomem();
	if ( ! stralloc_0(&foo) ) temp_nomem();
	
	/* update the latest modified time to avoid race conditions */
	if ( stat( foo.s, &filest ) == 0 && filest.st_mtime > *maxtime)
		*maxtime = filest.st_mtime;
		
	dirp = opendir(foo.s);
	/* start with new */
	while ( dirp && (dp = readdir(dirp)) != 0) {
		f = dp->d_name;
		if ( *f == '.' ) continue; /* ignore all dot-files */
		while(*f) {
			if ( *f != ':' || f[1] != '2' || f[2] != ',' ) {
				f++;
			} else {
				f += 3;
				while( *f >= 'A' && *f <= 'Z' && *f != 'T' ) f++;
				break;
			}
		}
		if ( *f == 'T' ) continue;
		/* get the file size */
		if( get_file_size(foo.s, dp->d_name, &filest) == 0 ) {
			(*count)++;
			*size += filest.st_size;
		} 
	}

	foo.s[foo.len-3] = 'r';
	foo.s[foo.len-4] = 'u';
	foo.s[foo.len-5] = 'c';
	/* the same thing with cur */
	
	if ( stat( foo.s, &filest ) == 0 && filest.st_mtime > *maxtime)
		*maxtime = filest.st_mtime;
		
	dirp = opendir(foo.s);
	while ( dirp && (dp = readdir(dirp)) != 0) {
		f = dp->d_name;
		if ( *f == '.' ) continue; /* ignore all dot-files */
		while(*f) {
			if ( *f != ':' || f[1] != '2' || f[2] != ',' ) {
				f++;
			} else {
				f += 3;
				while( *f >= 'A' && *f <= 'Z' && *f != 'T' ) f++;
				break;
			}
		}
		if ( *f == 'T' ) continue;

		if( get_file_size(foo.s, dp->d_name, &filest) == 0 ) {
			(*count)++;
			*size += filest.st_size;
		}
	}

	if ( ! stralloc_copys(&foo, "") ) temp_nomem();
	if ( ! stralloc_copys(&foo2, "") ) temp_nomem();
}

static void calc_size(char *dir, long int *size, int *count, time_t *maxtime)
/* one of the tow main calculating routines, get the size via a scan through 
 * all dirs */
{
	struct dirent *dp;
	DIR *dirp;

	*size = 0;
	*count = 0;
	
	dirp = opendir(dir);
	while ( dirp && (dp = readdir(dirp)) != 0) {
		if ( dp->d_name[0] == '.' && dp->d_name[1] != '\0' && 
				dp->d_name[1] != '.' && !str_diff( ".Trash", dp->d_name) ) {
			if ( ! stralloc_copys(&foo2, dir) ) temp_nomem();
			if ( ! stralloc_cats(&foo2, dp->d_name) ) temp_nomem();
			if ( ! stralloc_0(&foo2) ) temp_nomem();
	
			calc_curnew(foo2.s, size, count, maxtime);
		}
	}
	calc_curnew(dir, size, count, maxtime);
}

static int parse_quota(substdio *ss, long int *size, int *count, int *lines)
/* the other main routine, parse the maildirsize file to get the used space */
{
	int			match;
	char		*s;
	long int	fig;

	*lines = 0;
	*size = 0;
	*count = 0;
	
	while (1) {
		if (getln(ss,&foo,&match,'\n') != 0) {
			strerr_warn1("Parse error in maildirsize: (QUOTA #)", 0 );
			return -1; /* Uh oh we made a booboo */
		}
		/* test if at the end */
		if (!match && !foo.len) break;
		(*lines)++; /* line counter for later use */
		/* get the 2 space separated figures */
		s = foo.s;
		if ( replace(s,foo.len, ' ', '\0') !=1 ) continue;
		s[foo.len-1] = 0;
		/* first the size */
		if ( *s == '-' ) {
			if (! scan_ulong(s++, &fig) ) continue;
			fig *= -1;
		} else {
			if (! scan_ulong(s++, &fig) ) continue;
		}
		*size += fig;
		/* then the file count */
		while (*s++) ;
		if ( *s == '-' ) {
			if (! scan_ulong(s++, &fig) ) continue;
			fig *= -1;
		} else {
			if (! scan_ulong(s++, &fig) ) continue;
		}
		*count += fig;
	}
	return 0;
}			
			
void get_quota(char *quota, long int *size, int *count)
/* get the count and the size from the quota string */
{
	unsigned long int i;

	*size = 0;
	*count = 0;
	
	while (quota && *quota) {
		if (*quota < '0' || *quota > '9') {
			quota++;
			continue;
		}
		i=0;
		while (*quota >= '0' && *quota <= '9')
			i = i*10 + (*quota++ - '0');

		switch (*quota) {
			case 'S':
				*size = i;
				break;
			case 'C':
				*count = i;
				break;
			default: /* perhaps we should ignore the rest ... */
				strerr_die1x(100, 
					"The quota specification has the wrong format. (QUOTA #)");
		}
	}
}

static unsigned int replace(char *s, register unsigned int len, 
							register char f, register char r)
/* char replacement */
{
   register char *t;
   register int count = 0;
   
   t=s;
   for(;;) {
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
   }
}

