#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "alloc.h"
#include "auto_qmail.h"
#include "byte.h"
#include "control.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "ip.h"
#include "now.h"
#include "readwrite.h"
#include "str.h"
#include "stralloc.h"
#include "substdio.h"
#include "timeoutread.h"
#include "timeoutwrite.h"


static void die() { _exit(1); }

static int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = timeoutwrite(1200,fd,buf,len);
  if (r <= 0) die();
  return r;
}

char ssoutbuf[128];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

char sserrbuf[128];
substdio sserr = SUBSTDIO_FDBUF(safewrite,2,sserrbuf,sizeof sserrbuf);

static void puts(char *s)
{
  substdio_puts(&ssout,s);
}
static void flush()
{
  substdio_flush(&ssout);
}
static void err(char *s)
{
  puts(s);
  puts("\r\n");
  flush();
}
static void log(char* s)
{
  substdio_puts(&sserr,s);
  substdio_puts(&sserr,"\n");
  substdio_flush(&sserr);  
}

void die_usage()
{
  err("554 pop before smtp subprogram uncorrectly installedi (#5.3.5)");
  log("usage: pbscheck subprogram ...");
  die();
}
void die_exec()
{
  err("554 unable to start smtp daemon (#5.3.5)");
  log("pbscheck: unable to start smtp daemon");
  die();
}
void die_badenv()
{
  err("554 unable to read $TCPREMOTEIP (#5.3.5)");
  log("pbscheck: unable to read $TCPREMOTEIP");
  die();
}
void die_env() { log("pbscheck: unable to set environment"); }
void die_control()
{
  err("554 unable to read controls (#5.3.5)");
  log("pbscheck unable to read controls");
  die();
}
void die_nomem()
{
  err("421 out of memory (#4.3.0)");
  log("pbscheck out of memory");
  die();
}

char buf[1024];

stralloc addresses = {0};
struct ip_address *servers;
int numservers = 0;
unsigned int serverport = 2821;


void setup(void)
{
  char* s;
  int i;
  int len;
  
  if (chdir(auto_qmail) == -1) die_control();

  if (control_readfile(&addresses,"control/pbsservers",0) != 1) die_control();
  if (!stralloc_0(&addresses) ) die_nomem();

  if (control_readint(&serverport,"control/pbsport") == -1) die_control();
  if (serverport > 65000) die_control();
 
  for( i = 0; i < addresses.len; i++)
    if( addresses.s[i] == '\0' ) numservers++;
  
  servers = (struct ip_address*)alloc(numservers * sizeof(struct ip_address));
  if (! servers ) die_nomem();
  
  s = addresses.s;
  for( i = 0; i < numservers; i++ ) {
    len = ip_scan(s, &servers[i]);
    if ( len == 0 && len > 15 ) die_control();
    while( *s++ );
  }
}


int sendrequest(int fd, char* buf, int len, struct ip_address *ip)
{
  struct sockaddr_in sin;
  char *x;
  
  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,ip);
  x = (char *) &sin.sin_port;
  x[1] = serverport; serverport >>= 8; x[0] = serverport;
  sin.sin_family = AF_INET;
  
  return sendto(fd, buf, len, 0, (struct sockaddr*)&sin, sizeof(sin));
}

char **envsnap;

int env_snap()
{
  int i;
  int en;
  for (en = 0;environ[en];++en) ;
  envsnap = (char **) alloc((en + 1) * sizeof(char *));
  if (!envsnap) return 0;
  for (en = 0;environ[en];++en)
  {
    envsnap[en] = alloc(str_len(environ[en]) + 1);
    if (!envsnap[en])
    {
      for (i = 0;i < en;++i) alloc_free(envsnap[i]);
      alloc_free(envsnap);
      return 0;
    }
    str_copy(envsnap[en],environ[en]);
  }
  envsnap[en] = 0;
}

void setenv(char *env, int envlen)
{
  int numenv;
  int elen;
  int nlen;
  int i;
  
  if (!env_snap()) die_nomem();
  
  numenv=(unsigned char)*env++; envlen--;
  
  nlen=(unsigned char)*env++; envlen--;
  for(i=0; i < numenv; i++) {
    elen=nlen;
    if (envlen <= 0) {
      environ = envsnap;
      return;
    }
    nlen=(unsigned char)*(env+elen);
    *(env+elen)=0;
    if (!env_put(env)) die_nomem();
    env+=elen+1; envlen-=(elen+1);
  }
}

int main (int argc, char** argv)
{
  struct ip_address ip;
  char **childargs;
  char *ipstr;
  char *x;
  char *s;
  unsigned long t;
  int sfd;
  int len;
  int i;
  
  childargs = argv + 1;
  if (!*childargs) die_usage();
    
  x = env_get("RELAYCLIENT");
  if (x) {
    /* do we need the additional environment from pbsdbd? */
    execvp(*childargs,childargs);
    /* should never reach this point */
    die_exec();
  }
  
  setup();
  
  t = now() ^ getpid(); /* at least on OpenBSD this is mostly random */
  t %= numservers;

  ipstr = env_get("TCPREMOTEIP");
  if (!ipstr) die_badenv();
  len = ip_scan(ipstr, &ip);
  if ( len == 0 && len > 15 ) die_badenv();
  
  sfd = socket(AF_INET,SOCK_DGRAM,0);
  if ( sfd == -1 ) goto start_daemon;
  
  /* create request */
  s = buf; len = 0;
  *s++ = 'Q'; len++; /* Query */
  *s++ = 4; len++;   /* Size of address in bytes (4 IPv4|16 IPv6) */
  byte_copy(s, 4, &ip); s+=4; len+=4;
  *s++ = 0; len++;   /* status */
  
  i = sendrequest(sfd, buf, len, &servers[t]);
  if(i<=0) goto start_daemon;
  t = 0;
  do {
    /* wait a seconds for answer */
    i = timeoutread(1, sfd, buf, sizeof(buf));
    if(i!=-1) break;
    if(i==-1 && errno != error_timeout) goto start_daemon;

    if(t >= numservers) {
      log("pbscheck: no response from server");
      goto start_daemon; /* no response */
    }
    
    i = sendrequest(sfd, buf, len, &servers[t]);
    if(i<=0) goto start_daemon;
    t++;

  } while(1);
  
  if(buf[0] != 'R') goto start_daemon; /* R = Reply */
  if(buf[1] != 4) goto start_daemon;
  if(byte_diff(buf + 2, 4, &ip)) goto start_daemon; /* check address */
  if(*(buf + 2 + buf[1]) == 'R') {
    if (!env_put("RELAYCLIENT=")) die_nomem();
  }
  setenv(buf + 3 + buf[1], i - buf[1] - 3);
  
start_daemon:
  close(sfd); /* try to close socket */
  
  /* start smtpd */
  execvp(*childargs,childargs);
  /* should never reach this point */
  die_exec();
}
