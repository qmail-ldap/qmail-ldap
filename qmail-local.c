#include <sys/types.h>
#include <sys/stat.h>
#include "readwrite.h"
#include "sig.h"
#include "env.h"
#include "byte.h"
#include "exit.h"
#include "fork.h"
#include "open.h"
#include "wait.h"
#include "lock.h"
#include "seek.h"
#include "substdio.h"
#include "getln.h"
#include "strerr.h"
#include "subfd.h"
#include "sgetopt.h"
#include "alloc.h"
#include "error.h"
#include "stralloc.h"
#include "fmt.h"
#include "str.h"
#include "now.h"
#include "case.h"
#include "quote.h"
#include "qmail.h"
#include "slurpclose.h"
#include "myctime.h"
#include "gfrom.h"
#include "auto_patrn.h"

/* #define QLDAP *//* enable LDAP for qmail, done by the Makefile */

#ifdef QLDAP /* includes for LDAP mode */
#include "qmail-ldap.h"
#include <dirent.h>
#include "auto_qmail.h"
#include "scan.h"

#endif

void usage() { strerr_die1x(100,"qmail-local: usage: qmail-local [ -nN ] user homedir local dash ext domain sender aliasempty"); }

void temp_nomem() { strerr_die1x(111,"Out of memory. (#4.3.0)"); }
void temp_rewind() { strerr_die1x(111,"Unable to rewind message. (#4.3.0)"); }
void temp_childcrashed() { strerr_die1x(111,"Aack, child crashed. (#4.3.0)"); }
void temp_fork() { strerr_die3x(111,"Unable to fork: ",error_str(errno),". (#4.3.0)"); }
void temp_read() { strerr_die3x(111,"Unable to read message: ",error_str(errno),". (#4.3.0)"); }
void temp_slowlock()
{ strerr_die1x(111,"File has been locked for 30 seconds straight. (#4.3.0)"); }
void temp_qmail(fn) char *fn;
{ strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (#4.3.0)"); }

int flagdoit;
int flag99;

char *user;
char *homedir;
char *local;
char *dash;
char *ext;
char *host;
char *sender;
char *aliasempty;

#ifdef QLDAP /* define the global variables */
unsigned long int g_quota;
#endif

stralloc safeext = {0};
stralloc ufline = {0};
stralloc rpline = {0};
stralloc envrecip = {0};
stralloc dtline = {0};
stralloc qme = {0};
stralloc ueo = {0};
stralloc cmds = {0};
stralloc messline = {0};
stralloc foo = {0};

char buf[1024];
char outbuf[1024];

/* child process */

char fntmptph[80 + FMT_ULONG * 2];
char fnnewtph[80 + FMT_ULONG * 2];
void tryunlinktmp() { unlink(fntmptph); }
void sigalrm() { tryunlinktmp(); _exit(3); }

void maildir_child(dir)
char *dir;
{
 unsigned long pid;
 unsigned long time;
 char host[64];
 char *s;
 int loop;
 struct stat st;
 int fd;
 substdio ss;
 substdio ssout;

 sig_alarmcatch(sigalrm);
 if (chdir(dir) == -1) {
#ifdef AUTOMAILDIRMAKE
   /* this one handles the case where the aliasempty is not "./" */
   if (errno == error_noent) {
     umask(077);
     if (mkdir(dir,0700) == -1) { if (error_temp(errno)) _exit(9); _exit(9); }
     if (chdir(dir) == -1) { if (error_temp(errno)) _exit(9); _exit(9); }
     if (mkdir("tmp",0700) == -1) { if (error_temp(errno)) _exit(9); _exit(9); }
     if (mkdir("new",0700) == -1) { if (error_temp(errno)) _exit(9); _exit(9); }
     if (mkdir("cur",0700) == -1) { if (error_temp(errno)) _exit(9); _exit(9); }
   } else
#endif
   if (error_temp(errno)) _exit(9); else _exit(9);
 }
#ifdef AUTOMAILDIRMAKE
 /* this one handles the case where the aliasempty is "./" */
 if (stat("tmp", &st) == -1) {
   if (errno == error_noent) {
     umask(077);
     if (mkdir("tmp",0700) == -1) { if (error_temp(errno)) _exit(10); _exit(10); }
     if (mkdir("new",0700) == -1) { if (error_temp(errno)) _exit(10); _exit(10); }
     if (mkdir("cur",0700) == -1) { if (error_temp(errno)) _exit(10); _exit(10); }
   } else
   if (error_temp(errno)) _exit(10); else _exit(10);
 }

 if (chdir(dir) == -1) { if (error_temp(errno)) _exit(10); else _exit(10); }

#endif
   
/* XXX this looks weird and doesn't fit */
#ifdef AUTOMAILDIRMAKE_PARANOIA_XXX /* disabled */
   umask(077);
   if (stat("new", &st) == -1) {
     if (errno == error_noent) {
       if (mkdir("new",0700) == -1) { if (error_temp(errno)) _exit(1); _exit(2); }
     } else { 
       _exit(5);
     }
   } else if (! S_ISDIR(st.st_mode) ) _exit(5);
   if (stat("cur", &st) == -1) {
     if (errno == error_noent) {
      if (mkdir("cur",0700) == -1) { if (error_temp(errno)) _exit(1); _exit(2); }
     } else { 
       _exit(5);
     }
   } else if (! S_ISDIR(st.st_mode) ) _exit(5);
   if (stat("tmp", &st) == -1) {      
     if (errno == error_noent) {        
      if (mkdir("tmp",0700) == -1) { if (error_temp(errno)) _exit(1); _exit(2); }
     } else {         
       _exit(5);
     }        
   } else if (! S_ISDIR(st.st_mode) ) _exit(5);
#endif

 pid = getpid();
 host[0] = 0;
 gethostname(host,sizeof(host));
 for (loop = 0;;++loop)
  {
   time = now();
   s = fntmptph;
   s += fmt_str(s,"tmp/");
   s += fmt_ulong(s,time); *s++ = '.';
   s += fmt_ulong(s,pid); *s++ = '.';
   s += fmt_strn(s,host,sizeof(host)); *s++ = 0;
   if (stat(fntmptph,&st) == -1) if (errno == error_noent) break;
   /* really should never get to this point */
   if (loop == 2) _exit(1);
   sleep(2);
  }
 str_copy(fnnewtph,fntmptph);
 byte_copy(fnnewtph,3,"new");

 alarm(86400);
 fd = open_excl(fntmptph);
 if (fd == -1) _exit(1);

 substdio_fdbuf(&ss,read,0,buf,sizeof(buf));
 substdio_fdbuf(&ssout,write,fd,outbuf,sizeof(outbuf));
 if (substdio_put(&ssout,rpline.s,rpline.len) == -1) goto fail;
 if (substdio_put(&ssout,dtline.s,dtline.len) == -1) goto fail;

 switch(substdio_copy(&ssout,&ss))
  {
   case -2: tryunlinktmp(); _exit(4);
   case -3: goto fail;
  }

 if (substdio_flush(&ssout) == -1) goto fail;
 if (fsync(fd) == -1) goto fail;
 if (close(fd) == -1) goto fail; /* NFS dorks */

 if (link(fntmptph,fnnewtph) == -1) goto fail;
   /* if it was error_exist, almost certainly successful; i hate NFS */
 tryunlinktmp(); _exit(0);

 fail: tryunlinktmp(); _exit(1);
}

/* end child process */

#ifdef QLDAP /* quota handling maildir */

void quota_bounce(void) { strerr_die1x(100, "The users mailbox is over the allowed quota (size)."); }

void quota_warning(char *fn)
{
 int child;
 char *(args[3]);
 int wstat;

 if (!env_get(ENV_QUOTAWARNING) ) return;
 if (!stralloc_copys(&foo, auto_qmail)) temp_nomem();
 if (!stralloc_cats(&foo, "/bin/qmail-quotawarn")) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     args[0] = foo.s; args[1] = fn; args[2] = 0;
     sig_pipedefault();
     execv(*args,args);
     strerr_die5x(111,"Unable to run quotawarn program: ", foo.s, ": ",error_str(errno),". (LDAP-ERR #2.3.0)");
  }

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 111: _exit(111);
   case 0: break;
   default: _exit(100);
  }

}

unsigned long int maildirsize (dir)
char *dir;
{
   struct dirent *dp;
   DIR *dirp;
   struct stat filest;
   stralloc file = {0};
   unsigned long int temp = 0;
   
   if ( (dirp = opendir(dir)) == 0 )
     if ( errno != error_noent )
       strerr_die5x(111,"Unable to quota: can not open ",dir,": ",error_str(errno),". (LDAP-ERR #2.4.2)");
     else
       return 0;
   while ((dp = readdir(dirp)) != 0) {
     if (!stralloc_copys(&file,dir)) temp_nomem();
     if (!stralloc_cats(&file,dp->d_name)) temp_nomem();
     if (!stralloc_0(&file)) temp_nomem();
     if (stat(file.s, &filest) == 0) {
       if ( S_ISREG(filest.st_mode) )
         temp += filest.st_size;
     } else if (! S_ISLNK(filest.st_mode) ) {
       strerr_warn5("Unable to quota ", file.s, ": ",error_str(errno),". (LDAP-ERR #2.4.3)",0);
     }
   }
   closedir(dirp);
   return temp;
}
   
#endif /* end -- quota handling maildir */

void maildir(fn)
char *fn;
{
 int child;
 int wstat;

#ifdef QLDAP /* quota handling maildir */
 struct stat mailst;
 unsigned long int totalsize, size = 0;
 stralloc dir = {0};

 if(g_quota != 0 ) {
   if (fstat(0, &mailst) != 0)
       strerr_die5x(111,"Unable to open for quota ", "mail", ": ",error_str(errno),". (LDAP-ERR #2.4.1)");

   if (!stralloc_copys(&dir,fn)) temp_nomem();
   if (!stralloc_cats(&dir,"cur/")) temp_nomem();
   if (!stralloc_0(&dir)) temp_nomem();
   size += maildirsize(dir.s);
   if (!stralloc_copys(&dir,fn)) temp_nomem();
   if (!stralloc_cats(&dir,"new/")) temp_nomem();
   if (!stralloc_0(&dir)) temp_nomem();
   size += maildirsize(dir.s);
   if (!stralloc_copys(&dir,fn)) temp_nomem();
   if (!stralloc_cats(&dir,"tmp/")) temp_nomem();
   if (!stralloc_0(&dir)) temp_nomem();
   size += maildirsize(dir.s);
   
   totalsize = size + mailst.st_size;
   if ( totalsize > g_quota ) {
     /* probably we could do a second check (to deliver big messages) */
     quota_bounce();
   } else if ( totalsize > g_quota/100UL*80UL ) /* drop a warning when mailbox is around 80% full */
     quota_warning(fn);
 }
 
#endif /* end -- quota handling maildir */

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     maildir_child(fn);
     _exit(111);
  }

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 0: break;
   case 2: strerr_die1x(111,"Unable to chdir to maildir. (#4.2.1)");
   case 3: strerr_die1x(111,"Timeout on maildir delivery. (#4.3.0)");
   case 4: strerr_die1x(111,"Unable to read message. (#4.3.0)");
#ifdef AUTOMAILDIRMAKE
   case 5: strerr_die1x(111,"Unable to make maildirs. (LDAP-ERR #2.4.4)");
   case 9: strerr_die1x(111,"Boom with normal aliasempty (LDAP-ERR #2.4.4)");
   case 10: strerr_die1x(111,"Boom with ./ aliasempty (LDAP-ERR #2.4.4)");
#endif
   default: strerr_die1x(111,"Temporary error on maildir delivery. (#4.3.0)");
  }
}

void mailfile(fn)
char *fn;
{
 int fd;
 substdio ss;
 substdio ssout;
 int match;
 seek_pos pos;
 int flaglocked;

#ifdef QLDAP /* quota handling mbox */
 struct stat filest, mailst;
 unsigned long int totalsize;

 if (seek_begin(0) == -1) temp_rewind();
 
 if(g_quota != 0 ) {
   if (stat(fn, &filest) == -1)
     if ( errno != error_noent) { /* FALSE if file doesn't exist */
       strerr_die5x(111,"Unable to quota ", fn, ": ",error_str(errno), ". (LDAP-ERR #2.4.5)");
       filest.st_size = 0;        /* size of nonexisting maildir */
     }
   if (fstat(0, &mailst) != 0)
     strerr_die5x(111,"Unable to quota ", "mail", ": ",error_str(errno), ". (LDAP-ERR #2.4.6)");
   
   totalsize = filest.st_size + mailst.st_size;
   if ( totalsize > g_quota ) {
     /* probably we could do a second check (to deliver very big messages) */
     quota_bounce();
   } else if ( totalsize > g_quota/100UL*80UL ) /* drop a warning when mailbox is around 80% full */
     quota_warning(fn);
 }
 
#endif /* end -- quota handling mbox */

 if (seek_begin(0) == -1) temp_rewind();

 fd = open_append(fn);
 if (fd == -1)
   strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (#4.2.1)");

 sig_alarmcatch(temp_slowlock);
 alarm(30);
 flaglocked = (lock_ex(fd) != -1);
 alarm(0);
 sig_alarmdefault();

 seek_end(fd);
 pos = seek_cur(fd);

 substdio_fdbuf(&ss,read,0,buf,sizeof(buf));
 substdio_fdbuf(&ssout,write,fd,outbuf,sizeof(outbuf));
 if (substdio_put(&ssout,ufline.s,ufline.len)) goto writeerrs;
 if (substdio_put(&ssout,rpline.s,rpline.len)) goto writeerrs;
 if (substdio_put(&ssout,dtline.s,dtline.len)) goto writeerrs;
 for (;;)
  {
   if (getln(&ss,&messline,&match,'\n') != 0) 
    {
     strerr_warn3("Unable to read message: ",error_str(errno),". (#4.3.0)",0);
     if (flaglocked) seek_trunc(fd,pos); close(fd);
     _exit(111);
    }
   if (!match && !messline.len) break;
   if (gfrom(messline.s,messline.len))
     if (substdio_bput(&ssout,">",1)) goto writeerrs;
   if (substdio_bput(&ssout,messline.s,messline.len)) goto writeerrs;
   if (!match)
    {
     if (substdio_bputs(&ssout,"\n")) goto writeerrs;
     break;
    }
  }
 if (substdio_bputs(&ssout,"\n")) goto writeerrs;
 if (substdio_flush(&ssout)) goto writeerrs;
 if (fsync(fd) == -1) goto writeerrs;
 close(fd);
 return;

 writeerrs:
 strerr_warn5("Unable to write ",fn,": ",error_str(errno),". (#4.3.0)",0);
 if (flaglocked) seek_trunc(fd,pos);
 close(fd);
 _exit(111);
}

void mailprogram(prog)
char *prog;
{
 int child;
 char *(args[4]);
 int wstat;

 if (seek_begin(0) == -1) temp_rewind();

 switch(child = fork())
  {
   case -1:
     temp_fork();
   case 0:
     args[0] = "/bin/sh"; args[1] = "-c"; args[2] = prog; args[3] = 0;
     sig_pipedefault();
     execv(*args,args);
     strerr_die3x(111,"Unable to run /bin/sh: ",error_str(errno),". (#4.3.0)");
  }

 wait_pid(&wstat,child);
 if (wait_crashed(wstat))
   temp_childcrashed();
 switch(wait_exitcode(wstat))
  {
   case 100:
   case 64: case 65: case 70: case 76: case 77: case 78: case 112: _exit(100);
   case 0: break;
   case 99: flag99 = 1; break;
   default: _exit(111);
  }
}

unsigned long mailforward_qp = 0;

void mailforward(recips)
char **recips;
{
 struct qmail qqt;
 char *qqx;
 substdio ss;
 int match;

 if (seek_begin(0) == -1) temp_rewind();
 substdio_fdbuf(&ss,read,0,buf,sizeof(buf));

 if (qmail_open(&qqt) == -1) temp_fork();
 mailforward_qp = qmail_qp(&qqt);
 qmail_put(&qqt,dtline.s,dtline.len);
 do
  {
   if (getln(&ss,&messline,&match,'\n') != 0) { qmail_fail(&qqt); break; }
   qmail_put(&qqt,messline.s,messline.len);
  }
 while (match);
 qmail_from(&qqt,ueo.s);
 while (*recips) qmail_to(&qqt,*recips++);
 qqx = qmail_close(&qqt);
 if (!*qqx) return;
 strerr_die3x(*qqx == 'D' ? 100 : 111,"Unable to forward message: ",qqx + 1,".");
}

void bouncexf()
{
 int match;
 substdio ss;

 if (seek_begin(0) == -1) temp_rewind();
 substdio_fdbuf(&ss,read,0,buf,sizeof(buf));
 for (;;)
  {
   if (getln(&ss,&messline,&match,'\n') != 0) temp_read();
   if (!match) break;
   if (messline.len <= 1)
     break;
   if (messline.len == dtline.len)
     if (!str_diffn(messline.s,dtline.s,dtline.len))
       strerr_die1x(100,"This message is looping: it already has my Delivered-To line. (#5.4.6)");
  }
}

void checkhome()
{
 struct stat st;

 if (stat(".",&st) == -1)
   strerr_die3x(111,"Unable to stat home directory: ",error_str(errno),". (#4.3.0)");
 if (st.st_mode & auto_patrn)
   strerr_die1x(111,"Uh-oh: home directory is writable. (#4.7.0)");
 if (st.st_mode & 01000)
   if (flagdoit)
     strerr_die1x(111,"Home directory is sticky: user is editing his .qmail file. (#4.2.1)");
   else
     strerr_warn1("Warning: home directory is sticky.",0);
}

int qmeox(dashowner)
char *dashowner;
{
 struct stat st;

 if (!stralloc_copys(&qme,".qmail")) temp_nomem();
 if (!stralloc_cats(&qme,dash)) temp_nomem();
 if (!stralloc_cat(&qme,&safeext)) temp_nomem();
 if (!stralloc_cats(&qme,dashowner)) temp_nomem();
 if (!stralloc_0(&qme)) temp_nomem();
 if (stat(qme.s,&st) == -1)
  {
   if (error_temp(errno)) temp_qmail(qme.s);
   return -1;
  }
 return 0;
}

int qmeexists(fd,cutable)
int *fd;
int *cutable;
{
  struct stat st;

  if (!stralloc_0(&qme)) temp_nomem();

  *fd = open_read(qme.s);
  if (*fd == -1) {
    if (error_temp(errno)) temp_qmail(qme.s);
    if (errno == error_perm) temp_qmail(qme.s);
    if (errno == error_acces) temp_qmail(qme.s);
    return 0;
  }

  if (fstat(*fd,&st) == -1) temp_qmail(qme.s);
  if ((st.st_mode & S_IFMT) == S_IFREG) {
    if (st.st_mode & auto_patrn)
      strerr_die1x(111,"Uh-oh: .qmail file is writable. (#4.7.0)");
    *cutable = !!(st.st_mode & 0100);
    return 1;
  }
  close(*fd);
  return 0;
}

/* "" "": "" */
/* "-/" "": "-/" "-/default" */
/* "-/" "a": "-/a" "-/default" */
/* "-/" "a-": "-/a-" "-/a-default" "-/default" */
/* "-/" "a-b": "-/a-b" "-/a-default" "-/default" */
/* "-/" "a-b-": "-/a-b-" "-/a-b-default" "-/a-default" "-/default" */
/* "-/" "a-b-c": "-/a-b-c" "-/a-b-default" "-/a-default" "-/default" */

void qmesearch(fd,cutable)
int *fd;
int *cutable;
{
  int i;

  if (!stralloc_copys(&qme,".qmail")) temp_nomem();
  if (!stralloc_cats(&qme,dash)) temp_nomem();
  if (!stralloc_cat(&qme,&safeext)) temp_nomem();
  if (qmeexists(fd,cutable)) {
    if (safeext.len >= 7) {
      i = safeext.len - 7;
      if (!byte_diff("default",7,safeext.s + i))
	if (i <= str_len(ext)) /* paranoia */
	  if (!env_put2("DEFAULT",ext + i)) temp_nomem();
    }
    return;
  }

  for (i = safeext.len;i >= 0;--i)
    if (!i || (safeext.s[i - 1] == '-')) {
      if (!stralloc_copys(&qme,".qmail")) temp_nomem();
      if (!stralloc_cats(&qme,dash)) temp_nomem();
      if (!stralloc_catb(&qme,safeext.s,i)) temp_nomem();
      if (!stralloc_cats(&qme,"default")) temp_nomem();
      if (qmeexists(fd,cutable)) {
	if (i <= str_len(ext)) /* paranoia */
	  if (!env_put2("DEFAULT",ext + i)) temp_nomem();
        return;
      }
    }

  *fd = -1;
}

unsigned long count_file = 0;
unsigned long count_forward = 0;
unsigned long count_program = 0;
char count_buf[FMT_ULONG];

void count_print()
{
 substdio_puts(subfdoutsmall,"did ");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_file));
 substdio_puts(subfdoutsmall,"+");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_forward));
 substdio_puts(subfdoutsmall,"+");
 substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,count_program));
 substdio_puts(subfdoutsmall,"\n");
 if (mailforward_qp)
  {
   substdio_puts(subfdoutsmall,"qp ");
   substdio_put(subfdoutsmall,count_buf,fmt_ulong(count_buf,mailforward_qp));
   substdio_puts(subfdoutsmall,"\n");
  }
 substdio_flush(subfdoutsmall);
}

void sayit(type,cmd,len)
char *type;
char *cmd;
int len;
{
 substdio_puts(subfdoutsmall,type);
 substdio_put(subfdoutsmall,cmd,len);
 substdio_putsflush(subfdoutsmall,"\n");
}

#ifdef QLDAP /* various handling routines for LDAP stuff */

/* char replacement */
unsigned int replace(s, len, f, r)
char *s;
register unsigned int len;
register char f;
register char r;
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

#endif /* end -- various LDAP funtions */

void main(argc,argv)
int argc;
char **argv;
{
 int opt;
 int i;
 int j;
 int k;
 int fd;
 int numforward;
 char **recips;
 datetime_sec starttime;
 int flagforwardonly;
 char *x;

#ifdef QLDAP /* set up the variables */
 int slen;
 int qmode;
 int mboxdelivery;
 int localdelivery;
 int ldapprogdelivery;
 char *s;
 
 mboxdelivery = 1; localdelivery = 0; ldapprogdelivery = 0;
#endif


 umask(077);
 sig_pipeignore();

 if (!env_init()) temp_nomem();

 flagdoit = 1;
 while ((opt = getopt(argc,argv,"nN")) != opteof)
   switch(opt)
    {
     case 'n': flagdoit = 0; break;
     case 'N': flagdoit = 1; break;
     default:
       usage();
    }
 argc -= optind;
 argv += optind;

 if (!(user = *argv++)) usage();
 if (!(homedir = *argv++)) usage();
 if (!(local = *argv++)) usage();
 if (!(dash = *argv++)) usage();
 if (!(ext = *argv++)) usage();
 if (!(host = *argv++)) usage();
 if (!(sender = *argv++)) usage();
 if (!(aliasempty = *argv++)) usage();
 if (*argv) usage();

 if (homedir[0] != '/') usage();
 if (chdir(homedir) == -1) {
#ifdef AUTOHOMEDIRMAKE
   if (! (s = env_get(ENV_HOMEDIRMAKE)) ) {
     strerr_die5x(111,"Unable to switch to ",homedir,": ",error_str(errno),". (#4.3.0)");
   } else {
     if (errno == error_noent) {
       /* do the auto homedir creation */
       int child;
       char *(dirargs[4]);
       int wstat;

       switch(child = fork()) {
       case -1:
         temp_fork();
       case 0:
         dirargs[0] = s; dirargs[1] = homedir;
         dirargs[2] = aliasempty; dirargs[3] = 0;
         execv(*dirargs,dirargs);
         strerr_die5x(111,"Error while running automatic dirmaker:",s,": ",error_str(errno),". (LDAP-ERR #2.3.0)");
       }

       wait_pid(&wstat,child);
       if (wait_crashed(wstat))
          temp_childcrashed();
       switch(wait_exitcode(wstat)) {
       case 0: break;
       default:
         strerr_die3x(111,s,": exited non zero",". (LDAP-ERR #2.3.0)");
       }
       if (chdir(homedir) == -1) 
          strerr_die5x(111,"Unable to switch to ",homedir," even after running dirmaker: ",error_str(errno),". (LDAP-ERR #2.3.0)");
     } else {
       strerr_die5x(111,"Unable to switch to ",homedir,", it does exist but is not accessable: ",error_str(errno),". (LDAP-ERR #2.3.0)");
     }
   }
#else
   strerr_die5x(111,"Unable to switch to ",homedir,": ",error_str(errno),". (#4.3.0)");
#endif
 }
 checkhome();

 if (!env_put2("HOST",host)) temp_nomem();
 if (!env_put2("HOME",homedir)) temp_nomem();
 if (!env_put2("USER",user)) temp_nomem();
 if (!env_put2("LOCAL",local)) temp_nomem();

 if (!stralloc_copys(&envrecip,local)) temp_nomem();
 if (!stralloc_cats(&envrecip,"@")) temp_nomem();
 if (!stralloc_cats(&envrecip,host)) temp_nomem();

 if (!stralloc_copy(&foo,&envrecip)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("RECIPIENT",foo.s)) temp_nomem();

 if (!stralloc_copys(&dtline,"Delivered-To: ")) temp_nomem();
 if (!stralloc_cat(&dtline,&envrecip)) temp_nomem();
 for (i = 0;i < dtline.len;++i) if (dtline.s[i] == '\n') dtline.s[i] = '_';
 if (!stralloc_cats(&dtline,"\n")) temp_nomem();

 if (!stralloc_copy(&foo,&dtline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("DTLINE",foo.s)) temp_nomem();

 if (flagdoit)
   bouncexf();

 if (!env_put2("SENDER",sender)) temp_nomem();

 if (!quote2(&foo,sender)) temp_nomem();
 if (!stralloc_copys(&rpline,"Return-Path: <")) temp_nomem();
 if (!stralloc_cat(&rpline,&foo)) temp_nomem();
 for (i = 0;i < rpline.len;++i) if (rpline.s[i] == '\n') rpline.s[i] = '_';
 if (!stralloc_cats(&rpline,">\n")) temp_nomem();

 if (!stralloc_copy(&foo,&rpline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("RPLINE",foo.s)) temp_nomem();

 if (!stralloc_copys(&ufline,"From ")) temp_nomem();
 if (*sender)
  {
   int len; int i; char ch;

   len = str_len(sender);
   if (!stralloc_readyplus(&ufline,len)) temp_nomem();
   for (i = 0;i < len;++i)
    {
     ch = sender[i];
     if ((ch == ' ') || (ch == '\t') || (ch == '\n')) ch = '-';
     ufline.s[ufline.len + i] = ch;
    }
   ufline.len += len;
  }
 else
   if (!stralloc_cats(&ufline,"MAILER-DAEMON")) temp_nomem();
 if (!stralloc_cats(&ufline," ")) temp_nomem();
 starttime = now();
 if (!stralloc_cats(&ufline,myctime(starttime))) temp_nomem();

 if (!stralloc_copy(&foo,&ufline)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("UFLINE",foo.s)) temp_nomem();

 x = ext;
 if (!env_put2("EXT",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT2",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT3",x)) temp_nomem();
 x += str_chr(x,'-'); if (*x) ++x;
 if (!env_put2("EXT4",x)) temp_nomem();

 if (!stralloc_copys(&safeext,ext)) temp_nomem();
 case_lowerb(safeext.s,safeext.len);
 for (i = 0;i < safeext.len;++i)
   if (safeext.s[i] == '.')
     safeext.s[i] = ':';

 i = str_len(host);
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST2",foo.s)) temp_nomem();
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST3",foo.s)) temp_nomem();
 i = byte_rchr(host,i,'.');
 if (!stralloc_copyb(&foo,host,i)) temp_nomem();
 if (!stralloc_0(&foo)) temp_nomem();
 if (!env_put2("HOST4",foo.s)) temp_nomem();

 flagforwardonly = 0;

#ifdef QLDAP /* quota, dotmode and forwarding handling - part 1 */
   /* setting the quota */
   if ( s = env_get(ENV_QUOTA) ) {
      if (! scan_ulong(s, &g_quota) )
         strerr_die3x(100,"Format error: the quota is not a number: ",s,". (LDAP-ERR #2.0.1)");
      g_quota *= 1024; /* we need bytes not kbytes as quota */
      if (!flagdoit) sayit("quota in kB ",s,str_len(s) );
   } else {
      g_quota = 0;
      if (!flagdoit) sayit("unlimited quota",s,0 );
   }
   
   if ( s = env_get(ENV_DOTMODE) ) {
      case_lowers(s);
      if ( !str_diff(DOTMODE_LDAPONLY, s) ) {
         if (!flagdoit) sayit("DOTMODE_LDAPONLY ",s,0);
         qmode = DO_LDAP;
      } else if ( !str_diff(DOTMODE_LDAPWITHPROG, s) ) {
         if (!flagdoit) sayit("DOTMODE_LDAPWITHPROG ",s,0);
         qmode = DO_LDAP;
         ldapprogdelivery = 1;
      } else if ( !str_diff(DOTMODE_DOTONLY, s) ) {
         if (!flagdoit) sayit("DOTMODE_DOTONLY ",s,0);
         qmode = DO_DOT;
      } else if ( !str_diff(DOTMODE_BOTH, s) ) {
         if (!flagdoit) sayit("DOTMODE_BOTH ",s,0);
         qmode = DO_BOTH;
      } else if ( !str_diff(DOTMODE_NONE, s) ){
         ++count_file;
         if (!stralloc_copys(&foo,aliasempty)) temp_nomem();
         if (!stralloc_0(&foo)) temp_nomem();
         if (foo.s[foo.len - 2] == '/')
            if (flagdoit) maildir(foo.s);
            else sayit("maildir ",foo.s, foo.len);
         else
            if (flagdoit) mailfile(foo.s);
            else sayit("mbox ",foo.s, foo.len);
         count_print();
         _exit(0); 
      } else {
         strerr_die3x(100,"Error: No valid dot-mode found: ",s,". (LDAP-ERR #2.0.2)");
      }
   } else qmode = DO_DOT;  /* no qmailmode, so I use standard .qmail */
	   
 /* prepare the cmds string to hold all the commands from the ldap server and the .qmail file */
 if (!stralloc_ready(&cmds,0)) temp_nomem();
 cmds.len = 0;
 
 if ( qmode & DO_LDAP ) {
   /* get the infos from the ldap server (environment) */
   /* setting the NEWSENDER so echo and forward will work */
   if (!stralloc_copys(&ueo,sender)) temp_nomem();
   if (!stralloc_0(&ueo)) temp_nomem();
   if (!env_put2("NEWSENDER",ueo.s)) temp_nomem();

   if ( s = env_get(ENV_MODE) ) {
     case_lowers(s);
     if (!stralloc_copys(&foo, s)) temp_nomem();
     if (!stralloc_0(&foo)) temp_nomem();

     i = replace(foo.s, foo.len, ',', '\0') + 1;
     s = foo.s;
     slen = foo.len-1;
     for( ; i > 0; i--) {
       if ( !str_diff(MODE_FORWARD, s) ) {
         if (!flagdoit) sayit("forwardonly ",s,0);
         flagforwardonly = 0;
       } else if ( !str_diff(MODE_REPLY, s) ) {
         if( *sender ) {
           ++count_forward;
           if ( s = env_get(ENV_REPLYTEXT) ) {
             if ( flagdoit ) {
               mailprogram("qmail-reply");
             } else {
               sayit("reply to ",sender,str_len(sender));
               sayit("replytext ",s,str_len(s));
             }
           } else {
             strerr_warn1("Error: Reply mode is on but there is no reply text (ignored). (LDAP-ERR #2.1.1)", 0);
           }
         }
       } else if ( !str_diff(MODE_ECHO, s) ) {
         if (*sender) {
           ++count_forward;
           recips = (char **) alloc(2 * sizeof(char *));
           recips[0] = sender;
           recips[1] = 0;
           if (flagdoit) {
             mailforward(recips);
           } else sayit("echo to ",sender,str_len(sender));
         }
         count_print();
         _exit(0);
       } else if ( !str_diff(MODE_NOMBOX, s) ) {
         if (!flagdoit) sayit("no mbox delivery ",s,0);
         mboxdelivery = 0;
       } else if ( !str_diff(MODE_NORMAL, s) ) {
         if (!flagdoit) sayit("reseting delivery to normal",s,0);
         mboxdelivery = 1;
         flagforwardonly = 0;
         localdelivery = 0;
       } else if ( !str_diff(MODE_LDELIVERY, s) ) {
         if (!flagdoit) sayit("force local delivery ",s,0);
         localdelivery = 1;
       } else strerr_warn1("Error: undefined mail mode (ignored). (LDAP-ERR #2.1.2)", 0);
       
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }
   if ( localdelivery ) {
         if (!stralloc_cats(&cmds,aliasempty)) temp_nomem();
         if (!stralloc_cats(&cmds, "\n")) temp_nomem();
   }    
   if ( s = env_get(ENV_FORWARDS) ) {
     if (!stralloc_copys(&foo, s)) temp_nomem();
     if (!stralloc_0(&foo)) temp_nomem();
     replace(foo.s, foo.len, ',', '\0');
     s = foo.s;
     slen = foo.len-1;
     for (;;) {
       if (!stralloc_cats(&cmds, "&")) temp_nomem();
       if (!stralloc_cats(&cmds, s)) temp_nomem();
       if (!stralloc_cats(&cmds, "\n")) temp_nomem();
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }
   if ( ldapprogdelivery && (s = env_get(ENV_PROGRAM)) ) {
     if (!stralloc_copys(&foo, s)) temp_nomem();
     if (!stralloc_0(&foo)) temp_nomem();
     replace(foo.s, foo.len, ',', '\0');
     s = foo.s;
     slen = foo.len-1;
     for (;;) {
       if (!stralloc_cats(&cmds, "|")) temp_nomem();
       if (!stralloc_cats(&cmds, s)) temp_nomem();
       if (!stralloc_cats(&cmds, "\n")) temp_nomem();
       j = byte_chr(s,slen,0); if (j++ == slen) break; s += j; slen -= j;
     }
   }

 } 
 if ( qmode & DO_DOT ) { /* start dotqmail */
#endif
   qmesearch(&fd,&flagforwardonly);
   if (fd == -1)
     if (*dash)
#ifdef QLDAP
       if ( qmode == DO_DOT ) /* XXX: OK ??? */
#endif
         strerr_die1x(100,"Sorry, no mailbox here by that name. (#5.1.1)");

   if (!stralloc_copys(&ueo,sender)) temp_nomem();
   if (str_diff(sender,""))
     if (str_diff(sender,"#@[]"))
       if (qmeox("-owner") == 0) {
         if (qmeox("-owner-default") == 0) {
           if (!stralloc_copys(&ueo,local)) temp_nomem();
           if (!stralloc_cats(&ueo,"-owner-@")) temp_nomem();
           if (!stralloc_cats(&ueo,host)) temp_nomem();
           if (!stralloc_cats(&ueo,"-@[]")) temp_nomem();
         } else {
           if (!stralloc_copys(&ueo,local)) temp_nomem();
           if (!stralloc_cats(&ueo,"-owner@")) temp_nomem();
           if (!stralloc_cats(&ueo,host)) temp_nomem();
         }
       }
 
   if (!stralloc_0(&ueo)) temp_nomem();
   if (!env_put2("NEWSENDER",ueo.s)) temp_nomem();

#ifndef QLDAP /* need to "comment" the next two lines else everything from above is canceled */
   if (!stralloc_ready(&cmds,0)) temp_nomem();
   cmds.len = 0;
#endif
   if (fd != -1)
     if (slurpclose(fd,&cmds,256) == -1) temp_nomem();

#ifdef QLDAP
 } else if (! qmode & DO_LDAP ) /* XXX: If non of DO_LDAP, DO-DOT */
   strerr_die1x(100,"Error: No valid delivery mode selected. (LDAP-ERR #2.0.3)");
#endif
 if (!cmds.len)
  {
   if (!stralloc_copys(&cmds,aliasempty)) temp_nomem();
   flagforwardonly = 0;
  }
 if (!cmds.len || (cmds.s[cmds.len - 1] != '\n'))
   if (!stralloc_cats(&cmds,"\n")) temp_nomem();

 numforward = 0;
 i = 0;
 for (j = 0;j < cmds.len;++j)
   if (cmds.s[j] == '\n')
    {
     switch(cmds.s[i]) { case '#': case '.': case '/': case '|': break;
       default: ++numforward; }
     i = j + 1;
    }

 recips = (char **) alloc((numforward + 1) * sizeof(char *));
 if (!recips) temp_nomem();
 numforward = 0;

 flag99 = 0;

 i = 0;
 for (j = 0;j < cmds.len;++j)
   if (cmds.s[j] == '\n')
    {
     cmds.s[j] = 0;
     k = j;
     while ((k > i) && (cmds.s[k - 1] == ' ') || (cmds.s[k - 1] == '\t'))
       cmds.s[--k] = 0;
     switch(cmds.s[i])
      {
       case 0: /* k == i */
	 if (i) break;
         strerr_die1x(111,"Uh-oh: first line of .qmail file is blank. (#4.2.1)");
       case '#':
         break;
       case '.':
       case '/':
#ifdef QLDAP
	 if (! mboxdelivery ) break;
#endif
	 ++count_file;
	 if (flagforwardonly) strerr_die1x(111,"Uh-oh: .qmail has file delivery but has x bit set. (#4.7.0)");
	 if (cmds.s[k - 1] == '/')
           if (flagdoit) maildir(cmds.s + i);
           else sayit("maildir ",cmds.s + i,k - i);
	 else
           if (flagdoit) mailfile(cmds.s + i);
           else sayit("mbox ",cmds.s + i,k - i);
         break;
       case '|':
	 ++count_program;
	 if (flagforwardonly) strerr_die1x(111,"Uh-oh: .qmail has prog delivery but has x bit set. (#4.7.0)");
         if (flagdoit) mailprogram(cmds.s + i + 1);
         else sayit("program ",cmds.s + i + 1,k - i - 1);
         break;
       case '+':
	 if (str_equal(cmds.s + i + 1,"list"))
	   flagforwardonly = 1;
	 break;
       case '&':
         ++i;
       default:
	 ++count_forward;
         if (flagdoit) recips[numforward++] = cmds.s + i;
         else sayit("forward ",cmds.s + i,k - i);
         break;
      }
     i = j + 1;
     if (flag99) break;
    }

 if (numforward) if (flagdoit)
  {
   recips[numforward] = 0;
   mailforward(recips);
  }

 count_print();
 _exit(0);
}
