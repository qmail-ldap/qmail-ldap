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
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"


static void die() { _exit(1); }

char sserrbuf[128];
substdio sserr = SUBSTDIO_FDBUF(write,2,sserrbuf,sizeof sserrbuf);

char **childargs;

static void log(char* s)
{
  substdio_puts(&sserr,s);
  substdio_puts(&sserr,"\n");
  substdio_flush(&sserr);  
}

void die_badenv() { log("pbsadd unable to read $TCPREMOTEIP"); die(); }
void die_control() { log("pbsadd unable to read controls"); die(); }
void die_dir() { log("pbsadd unable to open current directory: "); die(); }
void die_dirback() { log("pbsadd unable to switch back to source directory: "); die(); }
void die_secret() { log("pbsadd control/pbssecret is to long"); die(); }
void die_exec() { log("pbsadd unable to start pop3 daemon"); die(); }
void die_usage() { log("usage: pbsadd subprogram ..."); die(); }
void log_socket() { log("pbsadd socket syscall failed"); }
void log_nomem()
{
  log("pbsadd out of memory"); 
  execvp(*childargs,childargs);
  /* should never reach this point */
  die_exec();
}

char buf[512];

stralloc addresses = {0};
stralloc secret = {0};
struct ip_address *servers;
int numservers = 0;
unsigned int serverport = 2821;


void setup(void)
{
  char* s;
  int i;
  int fdsourcedir;
  int len;
  
  fdsourcedir = open_read(".");
  if (fdsourcedir == -1)
    die_dir();
  
  if (chdir(auto_qmail) == -1) die_control();

  if (control_readfile(&addresses,"control/pbsservers",0) == -1) die_control();
  
  if (control_readint(&serverport,"control/pbsport") == -1) die_control();
  if (serverport > 65000) die_control();
  if (control_rldef(&secret,"control/pbssecret",0, 0) != 1) die_control();
  if ( secret.len > 255 ) die_secret();

  if (fchdir(fdsourcedir) == -1)
    die_dirback();

  if (!stralloc_0(&addresses) ) log_nomem();

  for( i = 0; i < addresses.len; i++)
    if( addresses.s[i] == '\0' ) numservers++;
  
  servers = (struct ip_address*)alloc(numservers * sizeof(struct ip_address));
  if (! servers ) log_nomem();
  
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


int main (int argc, char** argv)
{
  struct ip_address ip;
  char *ipstr;
  char *s;
  int sfd;
  int len;
  int i;
  
  childargs = argv + 1;
  if (!*childargs) die_usage();
    
  setup();
  
  ipstr = env_get("TCPREMOTEIP");
  if (!ipstr) die_badenv();
  len = ip_scan(ipstr, &ip);
  if ( len == 0 && len > 15 ) die_badenv();
  
  sfd = socket(AF_INET,SOCK_DGRAM,0);
  if ( sfd == -1 ) {
    log_socket();
    goto done;
  }
  
  /* create request */
  s = buf; len = 0;
  *s++ = 'A'; len++; /* ADD */
  *s++ = 4; len++;   /* Size of address in bytes (4 IPv4|16 IPv6) */
  byte_copy(s, 4, &ip); s+=4; len+=4;
  *s++ = secret.len; len++;   /* secret length */
  byte_copy(s, secret.len, secret.s); s+=secret.len; len+=secret.len;
  
  /* send update notification to all servers */
  for ( i = 0; i < numservers; i++) {
    sendrequest(sfd, buf, len, &servers[i]);
  }
    
  close(sfd); /* try to close socket */
done:
  execvp(*childargs,childargs);
  /* should never reach this point */
  die_exec();
}