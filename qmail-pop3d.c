#include <sys/types.h>
#include <sys/stat.h>
/* XXX unable to include stdio.h for rename because of puts() */
#include <unistd.h>
#include "commands.h"
#include "sig.h"
#include "getln.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "alloc.h"
#include "open.h"
#include "prioq.h"
#include "scan.h"
#include "fmt.h"
#include "str.h"
#include "exit.h"
#include "maildir.h"
#include "readwrite.h"
#include "timeoutread.h"
#include "timeoutwrite.h"

#include "env.h"
#include "maildir++.h"
#include "qmail-ldap.h"

int qfd;
 
/* level 0 = no logging
         1 = fatal errors
         2 = login/logout accounting
         3 = session errors
	 4 = verbose
 */
int loglevel = 0;
stralloc logs_pidhostinfo = {0};
unsigned long log_bytes = 0;

void log(int l, const char *s) { if(l <= loglevel) substdio_puts(subfderr,s);}
void logf(int l, const char *s) {
	if(l > loglevel) return;
	substdio_puts(subfderr,s);
	substdio_putsflush(subfderr,"\n");
}

void log_quit()
{
  char strnum[FMT_ULONG];

  log(2, "acct:");
  log(2, logs_pidhostinfo.s);
  log(2, "logout ");
  strnum[fmt_ulong(strnum,log_bytes)] = 0;
  log(2, strnum); logf(2, " bytes transferred");
}

void die() { log_quit(); _exit(0); }

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutread(1200,fd,buf,len);
  if (r <= 0) die();
  return r;
}

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(1200,fd,buf,len);
  if (r <= 0) die();
  return r;
}

char ssoutbuf[1024];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

char ssinbuf[128];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

void put(buf,len) char *buf; int len;
{
  substdio_put(&ssout,buf,len);
}
void puts(s) char *s;
{
  substdio_puts(&ssout,s);
}
void flush()
{
  substdio_flush(&ssout);
}
void err(s) char *s;
{
  puts("-ERR ");
  puts(s);
  puts("\r\n");
  flush();
}

void die_nomem() { err("out of memory");
	logf(1, "panic: out of memory"); die(); }
void die_nomaildir() { err("this user has no $HOME/Maildir");
	logf(1, "panic: this user has no $HOME/Maildir"); die(); }
void die_scan() { err("unable to scan $HOME/Maildir");
	logf(1, "unable to scan $HOME/Maildir"); die(); }

void err_syntax() { err("syntax error"); logf(3, "error: syntax error"); }
void err_unimpl() { err("unimplemented"); logf(3, "error: unimplemented"); }
void err_deleted() { err("already deleted"); logf(3, "already deleted"); }
void err_nozero() { err("messages are counted from 1"); logf(3, "messages are counted from 1"); }
void err_toobig() { err("not that many messages"); logf(3, "not that many messages"); }
void err_nosuch() { err("unable to open that message"); logf(3, "unable to open that message"); }
void err_nounlink() { err("unable to unlink all deleted messages"); logf(3, "unable to unlink all deleted messages"); }

void okay() { puts("+OK \r\n"); flush(); }

void printfn(fn) char *fn;
{
  fn += 4;
  put(fn,str_chr(fn,':'));
}

void log_init()
{
  char strnum[FMT_ULONG];
  const char *remotehost;
  const char *remoteip;
  const char *remoteinfo;
  const char *user;
  char *l;
  unsigned long v;
  
  l = env_get("POP3_LOGLEVEL");
  if (l) { scan_ulong(l,&v); loglevel = v; };

  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");
  if (!remoteinfo) remoteinfo = "";
  user = env_get("USER");
  if (!user) user = "unknown";

  if (!stralloc_copys(&logs_pidhostinfo, " pid ")) die_nomem();
  strnum[fmt_ulong(strnum,getpid())] = 0;
  if (!stralloc_cats(&logs_pidhostinfo, strnum)) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, ": ")) die_nomem();

  if (!stralloc_cats(&logs_pidhostinfo, remotehost)) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, ":")) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, remoteip)) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, ":")) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, remoteinfo)) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, " ")) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, user)) die_nomem();
  if (!stralloc_cats(&logs_pidhostinfo, " ")) die_nomem();
  if (!stralloc_0(&logs_pidhostinfo)) die_nomem();

  log(2, "acct:"); log(2, logs_pidhostinfo.s); logf(2, "login");
}


char strnum[FMT_ULONG];
stralloc line = {0};

void blast(ssfrom,limit)
substdio *ssfrom;
unsigned long limit;
{
  int match;
  int inheaders = 1;
 
  for (;;) {
    if (getln(ssfrom,&line,&match,'\n') != 0) die();
    if (!match && !line.len) break;
    if (match) --line.len; /* no way to pass this info over POP */
    if (limit) if (!inheaders) if (!--limit) break;
    if (!line.len)
      inheaders = 0;
    else
      if (line.s[0] == '.')
        put(".",1);
    put(line.s,line.len);
    put("\r\n",2);
    log_bytes += line.len + 2;
    if (!match) break;
  }
  put("\r\n.\r\n",5);
  flush();
}

stralloc filenames = {0};
prioq pq = {0};

struct message {
  int flagdeleted;
  unsigned long size;
  char *fn;
} *m;
int numm;

int last = 0;

void getlist()
{
  struct prioq_elt pe;
  struct stat st;
  int i;
 
  maildir_clean(&line);
  if (maildir_scan(&pq,&filenames,1,1) == -1) die_scan();
 
  numm = pq.p ? pq.len : 0;
  m = (struct message *) alloc(numm * sizeof(struct message));
  if (!m) die_nomem();
 
  for (i = 0;i < numm;++i) {
    if (!prioq_min(&pq,&pe)) { numm = i; break; }
    prioq_delmin(&pq);
    m[i].fn = filenames.s + pe.id;
    m[i].flagdeleted = 0;
    if (stat(m[i].fn,&st) == -1)
      m[i].size = 0;
    else
      m[i].size = st.st_size;
  }
}

void pop3_stat()
{
  int i;
  unsigned long total;
  unsigned int count;
 
  logf(4, "comm: stat");
  total = 0;
  count = 0;
  for (i = 0;i < numm;++i) if (!m[i].flagdeleted) {
    total += m[i].size;
    count += 1;
  }
  puts("+OK ");
  put(strnum,fmt_uint(strnum,count));
  puts(" ");
  put(strnum,fmt_ulong(strnum,total));
  puts("\r\n");
  flush();
}

void pop3_rset()
{
  int i;

  logf(4, "comm: rset");
  for (i = 0;i < numm;++i) m[i].flagdeleted = 0;
  last = 0;
  okay();
}

void pop3_last()
{
  logf(4, "comm: last");
  puts("+OK ");
  put(strnum,fmt_uint(strnum,last));
  puts("\r\n");
  flush();
}

void pop3_quit()
{
  int i;
  quota_t q;
  
  logf(4, "comm: quit");
/* qmail-ldap stuff */
/* this is just minimal support, because pop3 can not produce new mail */
  quota_get(&q, env_get(ENV_QUOTA));
  if (quota_calc(".",&qfd, &q) == -1) {
    /* second chance */
    sleep(3);
    quota_calc(".",&qfd, &q);
  }
  for (i = 0;i < numm;++i)
    if (m[i].flagdeleted) {
      if ( qfd != -1 ) quota_rm(qfd, m[i].size, 1);
/* end qmail-ldap stuff */
      if (unlink(m[i].fn) == -1) err_nounlink();
    }
    else
      if (str_start(m[i].fn,"new/")) {
	if (!stralloc_copys(&line,"cur/")) die_nomem();
	if (!stralloc_cats(&line,m[i].fn + 4)) die_nomem();
	if (!stralloc_cats(&line,":2,")) die_nomem();
	if (!stralloc_0(&line)) die_nomem();
	rename(m[i].fn,line.s); /* if it fails, bummer */
      }
  okay();
  if ( qfd != -1 ) close(qfd);
  die();
}

int msgno(arg) char *arg;
{
  unsigned long u;
  if (!scan_ulong(arg,&u)) { err_syntax(); return -1; }
  if (!u) { err_nozero(); return -1; }
  --u;
  if (u >= numm) { err_toobig(); return -1; }
  if (m[u].flagdeleted) { err_deleted(); return -1; }
  return u;
}

void pop3_dele(arg) char *arg;
{
  int i;

  log(4, "comm: dele: "); logf(4, arg);
  i = msgno(arg);
  if (i == -1) return;
  m[i].flagdeleted = 1;
  if (i + 1 > last) last = i + 1;
  okay();
}

void list(i,flaguidl)
int i;
int flaguidl;
{
  put(strnum,fmt_uint(strnum,i + 1));
  puts(" ");
  if (flaguidl) printfn(m[i].fn);
  else put(strnum,fmt_ulong(strnum,m[i].size));
  puts("\r\n");
}

void dolisting(arg,flaguidl) char *arg; int flaguidl;
{
  unsigned int i;
  if (*arg) {
    i = msgno(arg);
    if (i == -1) return;
    puts("+OK ");
    list(i,flaguidl);
  }
  else {
    okay();
    for (i = 0;i < numm;++i)
      if (!m[i].flagdeleted)
	list(i,flaguidl);
    puts(".\r\n");
  }
  flush();
}

void pop3_uidl(arg) char *arg; { 
  log(4, "comm: uidl: "); logf(4, arg); dolisting(arg,1); }
void pop3_list(arg) char *arg; {
  log(4, "comm: list: "); logf(4, arg); dolisting(arg,0); }

substdio ssmsg; char ssmsgbuf[1024];

void pop3_top(arg) char *arg;
{
  int i;
  unsigned long limit;
  int fd;
#ifdef MAKE_NETSCAPE_WORK /* Based on a patch by sven@megabit.net */
  char foo[FMT_ULONG];
#endif
 
  log(4, "comm: retr/top: "); logf(4, arg);
  i = msgno(arg);
  if (i == -1) return;
 
  arg += scan_ulong(arg,&limit);
  while (*arg == ' ') ++arg;
  if (scan_ulong(arg,&limit)) ++limit; else limit = 0;
 
  fd = open_read(m[i].fn);
  if (fd == -1) { err_nosuch(); return; }

#ifdef MAKE_NETSCAPE_WORK /* Based on a patch by sven@megabit.net */
  puts("+OK ");
  foo[fmt_uint(foo,m[i].size)] = 0;
  puts(foo);

  puts(" octets \r\n");
  flush();
#else
  okay();
#endif

  substdio_fdbuf(&ssmsg,subread,fd,ssmsgbuf,sizeof(ssmsgbuf));
  blast(&ssmsg,limit);
  close(fd);
}

struct commands pop3commands[] = {
  { "quit", pop3_quit, 0 }
, { "stat", pop3_stat, 0 }
, { "list", pop3_list, 0 }
, { "uidl", pop3_uidl, 0 }
, { "dele", pop3_dele, 0 }
, { "retr", pop3_top, 0 }
, { "rset", pop3_rset, 0 }
, { "last", pop3_last, 0 }
, { "top", pop3_top, 0 }
, { "noop", okay, 0 }
, { 0, err_unimpl, 0 }
} ;

int main(argc,argv)
int argc;
char **argv;
{
/* qmail-ldap stuff */
  char *env;
  
  sig_alarmcatch(die);
  sig_pipeignore();
  
  /* if MAILDIR is defined us this as Maildir and not the argument */
  if ( (env = env_get("MAILDIR") ) && *env ) argv[1] = env;

  if (!argv[1]) die_nomaildir();
  if (chdir(argv[1]) == -1) {
    die_nomaildir();
  } 
/* qmail-ldap stuff */

  log_init();
  getlist();

  okay();
  commands(&ssin,pop3commands);
  log_quit();
  return 0;
}
