#include "sig.h"
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "rcpthosts.h"
#include "rbl.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "dns.h"
#include "smtpcall.h"
#ifdef SMTPEXECCHECK
#include "execcheck.h"
#endif
#ifdef TLS_SMTPD
#include <openssl/ssl.h>
SSL *ssl = NULL;
#endif
#ifdef DATA_COMPRESS
/* zlib needs to be after openssl includes or build will fail */
#include <zlib.h>
#endif

#define MAXHOPS 100
unsigned int databytes = 0;
int timeout = 1200;

#ifdef TLS_SMTPD
int flagtimedout = 0;
void sigalrm()
{
 flagtimedout = 1;
}
int ssl_timeoutread(int tout, int fd, char *buf, int n)
{
 int r; int saveerrno;
 if (flagtimedout) { errno = error_timeout; return -1; }
 alarm(tout);
 r = SSL_read(ssl,buf,n);
 saveerrno = errno;
 alarm(0);
 if (flagtimedout) { errno = error_timeout; return -1; }
 errno = saveerrno;
 return r;
}
int ssl_timeoutwrite(int tout, int fd, char *buf, int n)
{
 int r; int saveerrno;
 if (flagtimedout) { errno = error_timeout; return -1; }
 alarm(tout);
 r = SSL_write(ssl,buf,n);
 saveerrno = errno;
 alarm(0);
 if (flagtimedout) { errno = error_timeout; return -1; }
 errno = saveerrno;
 return r;
}
#endif

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef TLS_SMTPD
  if (ssl)
    r = ssl_timeoutwrite(timeout,fd,buf,len);
  else
#endif
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) _exit(1);
  return r;
}

char ssoutbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

void flush() { substdio_flush(&ssout); }
void out(s) char *s; { substdio_puts(&ssout,s); }

/* level 0 = no logging
         1 = fatal errors
         2 = connection setup and warnings
         3 = verbose */

int loglevel = 0;

void logpid(level) int level;
{
  char pidstring[FMT_ULONG];
  if (level > loglevel) return;
  substdio_puts(subfderr,"qmail-smtpd ");
  pidstring[fmt_ulong(pidstring,(unsigned long) getpid())] = 0;
  substdio_puts(subfderr,pidstring);
  substdio_puts(subfderr,": ");
}

void logline(level,string) int level; char *string;
{
  if (level > loglevel) return;
  logpid(level);
  substdio_puts(subfderr,string);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void logstring(level,string) int level; char *string;
{
  if (level > loglevel) return;
  substdio_puts(subfderr,string);
}

void logflush(level) int level;
{
  if (level > loglevel) return;
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void die_read() { logline(1,"read error, connection closed"); _exit(1); }
void die_alarm() { out("451 timeout (#4.4.2)\r\n"); logline(1,"connection timed out, closing connection"); flush(); _exit(1); }
void die_nomem() { out("421 out of memory (#4.3.0)\r\n"); logline(1,"out of memory, closing connection"); flush(); _exit(1); }
void die_control() { out("421 unable to read controls (#4.3.0)\r\n"); logline(1,"unable to read controls, closing connection"); flush(); _exit(1); }
void die_ipme() { out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); logline(1,"unable to figure out my IP address, closing connection"); flush(); _exit(1); }
void err_dns() { out("421 DNS temporary failure at return MX check, try again later (#4.3.0)\r\n"); }
void straynewline() { out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); logline(1,"stray new line detected, closing connection"); flush(); _exit(1); }
void err_qqt() { out("451 qqt failure (#4.3.0)\r\n"); }
void err_ldapsoft() { out("451 temporary ldap lookup failure, try again later\r\n"); logline(1,"temporary ldap lookup failure"); }

void err_bmf() { out("553 sorry, your mail was administratively denied (#5.7.1)\r\n"); }
void err_bmfunknown() { out("553 sorry, your mail from a host without valid reverse DNS was administratively denied (#5.7.1)\r\n"); }
void err_maxrcpt() { out("553 sorry, too many recipients (#5.7.1)\r\n"); }
void err_nogateway(char *arg) { out("553 sorry, relaying denied from your location ["); out(arg); out("] (#5.7.1)\r\n"); }
void err_badbounce() { out("550 sorry, I don't accept bounce messages with more than one recipient. Go read RFC2821. (#5.7.1)\r\n"); }
void err_unimpl(arg) char *arg; { out("502 unimplemented (#5.5.1)\r\n"); logpid(3); logstring(3,"unrecognized command: "); logstring(3,arg); logflush(3); }
void err_size() { out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n"); logline(3,"message denied because: 'SMTP SIZE' too big"); }
void err_syntax() { out("555 syntax error (#5.5.4)\r\n"); }
void err_relay() { out("553 we don't relay (#5.7.1)\r\n"); }
void err_wantmail() { out("503 MAIL first (#5.5.1)\r\n"); logline(3,"'mail from' first"); }
void err_wantrcpt() { out("503 RCPT first (#5.5.1)\r\n"); logline(3,"'rcpt to' first"); }

void err_noop() { out("250 ok\r\n"); logline(3,"'noop'"); }
void err_vrfy(arg) char *arg; { out("252 send some mail, i'll try my best\r\n"); logpid(3); logstring(3,"vrfy for: "); logstring(3,arg); logflush(3); }

void err_rbl(arg) char *arg; { out("553 sorry, your mailserver is rejected by "); out(arg); out("\r\n"); }
void err_deny() { out("553 sorry, mail from your location is administratively denied (#5.7.1)\r\n"); }
void err_badrcptto() { out("553 sorry, mail to that recipient is not accepted (#5.7.1)\r\n"); }
void err_554msg(const char *arg) { out("554 sorry, "); out(arg); out("\r\n"); logstring(3,"message denied because: "); logstring(3,arg); logflush(3); }


stralloc me = {0};
stralloc greeting = {0};
stralloc cookie = {0};

void smtp_greet(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_puts(&ssout,me.s);
  substdio_puts(&ssout," ESMTP ");
  substdio_put(&ssout,greeting.s,greeting.len);
  if (cookie.len > 0) {
    substdio_puts(&ssout," ");
    substdio_put(&ssout,cookie.s,cookie.len);
  }
  out("\r\n");
}
void smtp_line(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_puts(&ssout,me.s);
  substdio_puts(&ssout," ");
  substdio_put(&ssout,greeting.s,greeting.len);
  out("\r\n");
}
void smtp_help()
{
  out("214-qmail home page: http://pobox.com/~djb/qmail.html\r\n");
  out("214 qmail-ldap patch home page: http://www.nrg4u.com\r\n");
  logline(3,"help requested");
}
void smtp_quit()
{
  smtp_line("221 ");
  logline(3,"quit, closing connection");
  flush(); _exit(0);
}
void err_quit()
{
  logline(3,"force closing connection");
  flush(); _exit(0);
}

char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *relayclient;
char *relayok;
char *greeting550;
int  spamflag = 0;

stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */

void dohelo(arg) char *arg; {
  if (!stralloc_copys(&helohost,arg)) die_nomem(); 
  if (!stralloc_0(&helohost)) die_nomem(); 
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
}

int liphostok = 0;
stralloc liphost = {0};
int bmfok = 0;
stralloc bmf = {0};
struct constmap mapbmf;
int bmfunknownok = 0;
stralloc bmfunknown = {0};
struct constmap mapbmfunknown;
int rmfok = 0;
stralloc rmf = {0};
struct constmap maprmf;
int brtok = 0;
stralloc brt = {0};
struct constmap mapbadrcptto;
int localsok = 0;
stralloc locals = {0};
struct constmap maplocals;
int gmaok = 0;
stralloc gma = {0};
struct constmap mapgma;
int rblok = 0;
int rbloh = 0;
int errdisconnect = 0;
int nobounce = 0;
int sanitycheck = 0;
int returnmxcheck = 0;
int blockrelayprobe = 0;
int tarpitcount = 0;
int tarpitdelay = 5;
int maxrcptcount = 0;
int sendercheck = 0;
int rcptcheck = 0;
int ldapsoftok = 0;
int flagauth = 0;
int needauth = 0;
int needssl = 0;
int authenticated = 0;
char *authprepend;

void setup()
{
  char *x, *l;
  unsigned long u, v;

  l = env_get("LOGLEVEL");
  if (l) { scan_ulong(l,&v); loglevel = v; };

  if (control_init() == -1) die_control();

  if (control_readline(&me,"control/me") != 1)
    die_control();
  if (!stralloc_0(&me)) die_nomem();

  if (control_rldef(&greeting,"control/smtpgreeting", 0, "") == -1)
    die_control();

  if (control_rldef(&cookie,"control/smtpclustercookie", 0, "") == -1)
    die_control();
  if (cookie.len > 32) cookie.len = 32;

  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();

  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;

  x = env_get("TARPITCOUNT");
  if (x) { scan_ulong(x,&u); tarpitcount = u; };
  if (tarpitcount < 0) tarpitcount = 0;

  x = env_get("TARPITDELAY");
  if (x) { scan_ulong(x,&u); tarpitdelay = u; };
  if (tarpitdelay < 0) tarpitdelay = 0;

  x = env_get("MAXRCPTCOUNT");
  if (x) { scan_ulong(x,&u); maxrcptcount = u; };
  if (maxrcptcount < 0) maxrcptcount = 0;

  if (rcpthosts_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  bmfunknownok = control_readfile(&bmfunknown,"control/badmailfrom-unknown",0);
  if (bmfunknownok == -1) die_control();
  if (bmfunknownok)
    if (!constmap_init(&mapbmfunknown,bmfunknown.s,bmfunknown.len,0))
      die_nomem();

  rmfok = control_readfile(&rmf,"control/relaymailfrom",0);
  if (rmfok == -1) die_control();
  if (rmfok)
    if (!constmap_init(&maprmf,rmf.s,rmf.len,0)) die_nomem();

  brtok = control_readfile(&brt,"control/badrcptto",0);
  if (brtok == -1) die_control();
  if (brtok)
    if (!constmap_init(&mapbadrcptto,brt.s,brt.len,0)) die_nomem();

  localsok = control_readfile(&locals,"control/locals",0);
  if (localsok == -1) die_control();
  if (localsok)
    if (!constmap_init(&maplocals,locals.s,locals.len,0)) die_nomem();

  gmaok = control_readfile(&gma,"control/goodmailaddr",0);
  if (gmaok == -1) die_control();
  if (gmaok)
    if (!constmap_init(&mapgma,gma.s,gma.len,0)) die_nomem();

  if (env_get("RBL")) {
    rblok = rblinit();
    if (rblok == -1) die_control();
    if (env_get("RBLONLYHEADER")) rbloh = 1;
  }

  if (env_get("SMTP550DISCONNECT")) errdisconnect = 1;
  if (env_get("NOBOUNCE")) nobounce = 1;
  if (env_get("SANITYCHECK")) sanitycheck = 1;
  if (env_get("RETURNMXCHECK")) returnmxcheck = 1;
  if (env_get("BLOCKRELAYPROBE")) blockrelayprobe = 1;
  if (env_get("SENDERCHECK"))
  {
    sendercheck = 1;
    if (!case_diffs("LOOSE",env_get("SENDERCHECK"))) sendercheck = 2;
    if (!case_diffs("STRICT",env_get("SENDERCHECK"))) sendercheck = 3;
  }
  if (env_get("RCPTCHECK")) rcptcheck = 1;
  if (env_get("LDAPSOFTOK")) ldapsoftok = 1;
  greeting550 = env_get("550GREETING");
  relayok = relayclient = env_get("RELAYCLIENT");

  if (env_get("SMTPAUTH")) {
    flagauth = 1;
    if (!case_diffs("TLSREQUIRED", env_get("SMTPAUTH"))) needssl = 1;
  }
  if (env_get("AUTHREQUIRED")) needauth = 1;
  authprepend = env_get("AUTHPREPEND");

#ifdef SMTPEXECCHECK
  execcheck_setup();
#endif

  if (control_readint(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;
 
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");

  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";

  logpid(2);
  logstring(2,"connection from "); logstring(2,remoteip);
  logstring(2," ("); logstring(2,remotehost);
  if (remoteinfo) { logstring(2,", "); logstring(2,remoteinfo); }
  logstring(2,") to "); logstring(2,local);
  logflush(2);

  logpid(2);
  logstring(2, "enabled options: ");
  if (greeting550) logstring(2,"greeting550");
  if (relayclient) logstring(2,"relayclient ");
  if (sanitycheck) logstring(2,"sanitycheck ");
  if (returnmxcheck) logstring(2,"returnmxcheck ");
  if (blockrelayprobe) logstring(2,"blockrelayprobe ");
  if (nobounce) logstring(2,"nobounce ");
  if (rblok) logstring(2,"rblcheck ");
  if (rbloh) logstring(2,"rblonlyheader ");
  if (sendercheck) logstring(2,"sendercheck");
  if (sendercheck == 1) logstring(2," ");
  if (sendercheck == 2) logstring(2,"-loose ");
  if (sendercheck == 3) logstring(2,"-strict ");
  if (rcptcheck) logstring(2,"rcptcheck ");
  if (ldapsoftok) logstring(2,"ldapsoftok ");
  if (flagauth) logstring(2, "smtp-auth");
  if (needssl) logstring(2, "-tls-required ");
  else logstring(2, " ");
  if (needauth) logstring(2, "authrequired ");
#ifdef SMTPEXECCHECK
  if (execcheck_on()) logstring(2, "rejectexecutables ");
#endif
  if (errdisconnect) logstring(2,"smtp550disconnect ");
#ifdef ALTQUEUE
  if (env_get("QMAILQUEUE")) {
    logstring(2,"qmailqueue ");
    logstring(2,env_get("QMAILQUEUE"));
  }
#endif
  logflush(2);

  dohelo(remotehost);
}


stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */

int addrparse(arg)
char *arg;
{
  int i;
  char ch;
  char terminator;
  struct ip_address ip;
  int flagesc;
  int flagquoted;
 
  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    while (*arg == ' ') ++arg;
  }

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0;ch = arg[i];++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[')
        if (!addr.s[i + 1 + ip_scanbracket(addr.s + i + 1,&ip)])
          if (ipme_is(&ip)) {
            addr.len = i + 1;
            if (!stralloc_cat(&addr,&liphost)) die_nomem();
            if (!stralloc_0(&addr)) die_nomem();
          }
  }

  if (addr.len > 900) return 0;
  return 1;
}

stralloc checkhost = {0};

int badmxcheck(dom)
char *dom;
{
  ipalloc checkip = {0};
  int ret = 0;
  unsigned long random;

  if (!*dom) return (DNS_HARD);
  if (!stralloc_copys(&checkhost,dom)) return (DNS_SOFT);

  random = now() + (getpid() << 16);
  switch (dns_mxip(&checkip,&checkhost,random))
  {
    case DNS_MEM:
    case DNS_SOFT:
         ret = DNS_SOFT;
         break;
    case DNS_HARD:
         ret = DNS_HARD;
         break;
    case 1:
         if (checkip.len == 0) ret = DNS_HARD;
         break;
    default:
         ret = 0;
         break;
  }
  return (ret);
}

stralloc parameter = {0};

char *getparameter(arg, name)
char *arg;
char *name;
{
  int i;
  char ch;
  char terminator;
  int flagesc;
  int flagquoted;

  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    while (*arg == ' ') ++arg;
  }

  flagesc = 0;
  flagquoted = 0;
  for (i = 0;(ch = arg[i]);++i) { /* skipping addr, respecting quotes */
    if (flagesc) {
      flagesc = 0;
    } else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: break;
      }
    }
  }
  if (!arg[i++]) return (char *)0; /* no parameters */
  arg += i;
  do {
    while (*arg == ' ') if (!*arg++) return (char *)0;
    if (case_diffb(arg, str_len(name), name) == 0) {
      arg += str_len(name);
      if (*arg++ == '=') {
	i = str_chr(arg, ' ');
	if (!stralloc_copyb(&parameter, arg, i)) die_nomem();
	if (!stralloc_0(&parameter)) die_nomem();
	return parameter.s;
      }
    }
    while (*arg != ' ') if (!*arg++) return (char *)0;
  } while (1);
}

int sizelimit(arg)
char *arg;
{
  char *size;
  unsigned long sizebytes = 0;

  size = getparameter(arg, "SIZE");
  if (!size) return 1;

  scan_ulong(size, &sizebytes);
  return (unsigned long)databytes >= sizebytes;
}


int bmfcheck()
{
  int j;
  if (!bmfok) return 0;
  if (constmap(&mapbmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
  {
    if (constmap(&mapbmf,addr.s + j,addr.len - j - 1)) return 1;
    if (constmap(&mapbmf,addr.s, j + 1)) return 1;
  }
  return 0;
}

int bmfunknowncheck()
{
  int j;
  if (!bmfunknownok) return 0;
  if (case_diffs(remotehost,"unknown")) return 0;
  if (constmap(&mapbmfunknown,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbmfunknown,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}

int seenmail = 0;
stralloc mailfrom = {0};
stralloc rcptto = {0};
int rcptcount;

int rmfcheck()
{
  int j;
  if (!rmfok) return 0;
  if (constmap(&maprmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&maprmf,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}

int addrallowed()
{
  int r;
  int j;
  if (localsok)
  {
    j = byte_rchr(addr.s,addr.len,'@');
    if (j < addr.len)
      if (constmap(&maplocals,addr.s + j + 1,addr.len - j - 2)) return 1;
  }
  r = rcpthosts(addr.s,str_len(addr.s));
  if (r == -1) die_control();
  return r;
}

int rcptdenied()
{
  int j;
  if (!brtok) return 0;
  if (constmap(&mapbadrcptto, addr.s, addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbadrcptto, addr.s + j, addr.len - j - 1))
      return 1;
  return 0;
}

int addrlocals()
{
  int j;
  if (!localsok) return 0;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&maplocals, addr.s + j + 1, addr.len - j - 2))
      return 1;
  return 0;
}

int goodmailaddr()
{
  int j;
  if (!gmaok) return 0;
  if (constmap(&mapgma, addr.s, addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapgma, addr.s + j, addr.len - j - 1))
      return 1;
  return 0;
}

int ldaplookup()
{
  return 1;
}

int relayprobe() /* relay probes trying stupid old sendwhale bugs */
{
  int j;
  j = addr.len;
  while(--j >= 0)
    if (addr.s[j] == '@') break;
  if (j < 0) j = addr.len;
  while(--j >= 0) {
    if (addr.s[j] == '@') return 1; /* double @ */
    if (addr.s[j] == '%') return 1; /* percent relaying */
    if (addr.s[j] == '!') return 1; /* UUCP bang path */
  }
  return 0;
}


void smtp_helo(arg) char *arg;
{
  smtp_line("250 ");
  seenmail = 0; dohelo(arg);
  logpid(3); logstring(3,"remote helo: "); logstring(3,arg); logflush(3);
}

char smtpsize[FMT_ULONG];
void smtp_ehlo(arg) char *arg;
{
  smtp_line("250-");
  out("250-PIPELINING\r\n");
  smtpsize[fmt_ulong(smtpsize,(unsigned long) databytes)] = 0;
  out("250-SIZE "); out(smtpsize); out("\r\n");
#ifdef DATA_COMPRESS
  out("250-DATAZ\r\n");
#endif
#ifdef TLS_SMTPD
  if (!ssl)
    out("250-STARTTLS\r\n");
#endif
#ifdef TLS_SMTPD
  if (!needssl || ssl)
#endif
  if (flagauth)
    out("250-AUTH LOGIN PLAIN\r\n");
  out("250 8BITMIME\r\n");

  seenmail = 0; dohelo(arg);
  logpid(3); logstring(3,"remote ehlo: "); logstring(3,arg); logflush(3);
  logpid(3); logstring(3,"max msg size: "); logstring(3,smtpsize); logflush(3);
}

void smtp_rset()
{
  seenmail = 0;
  relayclient = relayok; /* restore original relayclient setting */
  out("250 flushed\r\n");
  logline(3,"remote rset");
  if (errdisconnect) err_quit();
}

struct qmail qqt;

void smtp_mail(arg) char *arg;
{
  int i,j;
  char *rblname;
  int bounceflag = 0;

  logpid(3); logstring(3,"remote sent 'mail from': "); logstring(3,arg); logflush(3);

  /* address syntax check */
  if (!addrparse(arg))
  {
    err_syntax(); 
    logpid(2); logstring(2,"RFC2821 syntax error in mail from: "); logstring(2,arg); logflush(2);
    if (errdisconnect) err_quit();
    return;
  }
  logpid(3); logstring(3,"mail from: "); logstring(3,addr.s); logflush(3);

  if (needauth && !authenticated) {
    out("530 authentication needed\r\n");
    logline(2, "auth needed");
    if (errdisconnect) err_quit();
    return;
  }

  /* smtp size check */
  if (databytes && !sizelimit(arg))
  {
    err_size(); /* logging is done in error routine */
    if (errdisconnect) err_quit();
    return;
  }

  /* bad mailfrom check */
  if (bmfcheck())
  {
    err_bmf();
    logpid(2); logstring(2,"bad mailfrom: "); logstring(2,addr.s); logflush(2);
    if (errdisconnect) err_quit();
    return;
  }
  /* bad mailfrom unknown check */
  if (bmfunknowncheck())
  {
    err_bmfunknown();
    logpid(2); logstring(2,"bad mailfrom unknown: ");
    logstring(2,addr.s); logflush(2);
    if (errdisconnect) err_quit();
    return;
  }

  /* NOBOUNCE check */
  if (!addr.s[0] || !str_diff("#@[]", addr.s))
  {
    bounceflag = 1;
    if (nobounce)
    {
      err_554msg("RFC2821 bounces are administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
  }

  /* Sanity checks */
  if (sanitycheck && !bounceflag)
  {
    /* Invalid Mailfrom */
    if ((i=byte_rchr(addr.s,addr.len,'@')) >= addr.len)
    {
      err_554msg("mailfrom without @ is administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    if ( i == 0 || addr.s[i+1] == '\0' ) {
      err_554msg("mailfrom without user or domain part is administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    /* No '.' in domain.TLD */
    if ((j = byte_rchr(addr.s+i, addr.len-i, '.')) >= addr.len-i)
    {
      err_554msg("mailfrom without . in domain part is administratively denied");
      if (errdisconnect) err_quit();
      return;
    }
    /* check tld length */
    j = addr.len-(i+1+j+1);
    if (j < 2 || j > 6)
    {
      /* XXX: This needs adjustment when new TLD's are constituded.
       * OK, now after the candidates are nominated we know new TLD's
       * may contain up to six characters.
       */
      err_554msg("mailfrom without country or top level domain is administratively denied");
      if (errdisconnect) err_quit();
      return;
     }
  }

  /* relay mail from check (allow relaying based on evelope sender address) */
  if (!relayok)
  {
    if (rmfcheck())
    {
      relayclient = "";
      logline(2,"relaying allowed for mailfrom");
    }
  }

  /* Check RBL only if relayclient is not set */
  if (rblok && !relayclient)
  {
    switch(rblcheck(remoteip, &rblname, rbloh))
    {
      case 2: /* soft error lookup */
        /*
         * continue if  RBL DNS has a problem. if a RBL is unreachable
         * we dont want to fail. accept message anyway. a false negative
         * is better in this case than rejecting every message just
         * because one RBL failed. play safe, might be an important mail.
         */
        break;
      case 1: /* host is listed in RBL */
        err_rbl(rblname);
        if (errdisconnect) err_quit();
        return;
      default: /* ok, go ahead */
        logline(3,"RBL checking completed");
        break;
    }
  }

  /* return MX check */
  if (returnmxcheck && !bounceflag)
  {
    if ((i=byte_rchr(addr.s,addr.len,'@')) < addr.len)
      switch (badmxcheck(&addr.s[i+1]))
      {
	case 0:
	  break; /* valid */
	case DNS_SOFT:
	  err_dns();
	  logline(3,"refused mailfrom because return MX lookup failed temporarly");
	  if (errdisconnect) err_quit();
	  return;
	case DNS_HARD:
	default:
	  err_554msg("refused mailfrom because return MX does not exist");
	  if (errdisconnect) err_quit();
	  return;
      }
  }

  /* check if sender exists in ldap */
  if (sendercheck && !bounceflag)
  {
    if (!goodmailaddr()) /* good mail addrs go through anyway */
    {
      if (addrlocals())
      {
        switch (ldaplookup())
        {
          case 1: /* valid */
            break;
          case 0: /* invalid */
            err_554msg("refused mailfrom because sender address does not exist");
            if (errdisconnect) err_quit();
            return;
          case -1:
          default: /* other error, treat as soft 4xx */
            if (ldapsoftok)
              break;
            err_ldapsoft();
            if (errdisconnect) err_quit();
            return;
        }
      } else {
        /* not in addrlocals, ldap lookup is useless */
        /* normal mode: let through, it's just an external mail coming in */
        /* loose mode: see if sender is in rcpthosts, if no reject here */
        if (sendercheck == 2 && !addrallowed())
        {
          err_554msg("refused mailfrom because valid local sender address required");
          if (errdisconnect) err_quit();
          return;
        }
        /* strict mode: we require validated sender so reject here right out */
        if (sendercheck == 3)
        {
          err_554msg("refused mailfrom because valid local sender address required");
          if (errdisconnect) err_quit();
          return;
        }
      }
    }
  }

  seenmail = 1;
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();
  rcptcount = 0;
  out("250 ok\r\n");
}

void smtp_rcpt(arg) char *arg; {
  if (!seenmail)
  {
    err_wantmail();
    if (errdisconnect) err_quit();
    return;
  }
  logpid(3); logstring(3,"remote sent 'rcpt to': "); logstring(3,arg); logflush(3);

  /* syntax check */
  if (!addrparse(arg))
  {
    err_syntax();
    logpid(2); logstring(2,"syntax error in 'rcpt to': "); logstring(2,arg); logflush(2);
    if (errdisconnect) err_quit();
    return;
  }
  logpid(3); logstring(3,"rcpt to: "); logstring(3,addr.s); logflush(3);

  /* block stupid and bogus sendwhale bug relay probing */
  if (blockrelayprobe) /* don't enable this if you use percenthack */
  {
    if (relayprobe())
    {
      err_relay();
      logline(3,"'rcpt to' denied = looks like bogus sendwhale bug relay probe");
      if (errdisconnect) err_quit();
      return;
    }
  }

  /* do we block this recipient */
  if (rcptdenied())
  {
    err_badrcptto();
    logpid(2); logstring(2,"'rcpt to' denied: "); logstring(2,arg); logflush(2);
    if (errdisconnect) err_quit();
    return;
  }

  /* XXX now this is a ugly hack */
  if (authenticated && relayclient == 0) relayclient = "";
  
  /* is sender ip allowed to relay */
  if (relayclient)
  {
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  } else {
    if (!addrallowed())
    { 
      err_nogateway(remoteip);
      logpid(2); logstring(2,"no mail relay for 'rcpt to': ");
      logstring(2,arg); logflush(2);
      if (errdisconnect) err_quit();
      return; 
    }
  }
  ++rcptcount;

  /* maximum recipient limit reached */
  if (maxrcptcount && rcptcount > maxrcptcount)
  {
    err_maxrcpt();
    logline(1,"message denied because of more 'RCPT TO' than allowed by MAXRCPTCOUNT");
    if (errdisconnect) err_quit();
    return;
  }

  /* only one recipient for bounce messages */
  if (rcptcount > 1 && (!mailfrom.s[0] || !str_diff("#@[]", mailfrom.s)))
  {
    err_badbounce();
    logline(1,"bounce message denied because it has more than one recipient");
    if (errdisconnect) err_quit();
    return;
  }

  /* check if recipient exists in ldap */
  if (rcptcheck)
  {
    if (!goodmailaddr())
    {
      if (addrlocals())
      {
        switch (ldaplookup(&addr))
        {
          case 1: /* valid */
            break;
          case 0: /* invalid */
            err_554msg("message rejected because recipient does not exist");
            if (errdisconnect) err_quit();
            return;
          case -1:
          default: /* other error, treat as soft 4xx */
            if (ldapsoftok)
              break;
            err_ldapsoft();
            if (errdisconnect) err_quit();
            return;
        }
      } /* else this is relaying, don't do anything */
    }
  }

  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();
  if (tarpitcount && tarpitdelay && rcptcount >= tarpitcount)
  {
    logline(2,"tarpitting");
    while (sleep(tarpitdelay));
  }
  out("250 ok\r\n");
}

#ifdef DATA_COMPRESS
z_stream stream;
char zbuf[4096];
int wantcomp = 0;
int compdata = 0;

int compression_init(void)
{
  compdata = 1;
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_in = 0;
  stream.next_in = zbuf;
  if (inflateInit(&stream) != Z_OK) {
    out("451 Initalizing data compression failed: ");
    out(stream.msg); out(" #(4.3.0)\r\n"); flush();
    return -1;
  }
  return 0;
}
int compression_done(void)
{
  char num[FMT_ULONG];
  int r;

  compdata = 0;
  if (stream.avail_out != sizeof(zbuf)) {
    /* there is some left data, ignore */
  }
  if (inflateEnd(&stream) != Z_OK) {
    out("451 Finishing data compression failed: ");
    out(stream.msg); out(" #(4.3.0)\r\n"); flush();
    return -1;
  }
  r = 100 - (int)(100.0*stream.total_in/stream.total_out);
  if (r < 0) {
    num[0] = '-';
    r *= -1;
  } else
    num[0] = ' ';
  num[fmt_ulong(num+1,r)+1] = 0;
  logpid(1);
  logstring(1,"Dynamic data compression saved ");
  logstring(1,num); logstring(1,"%"); logflush(1);
  return 0;
}
#endif

int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  flush();
#ifdef DATA_COMPRESS
  if (compdata) {
    stream.avail_out = len;
    stream.next_out = buf;
    do {
      if (stream.avail_in == 0) {
#ifdef TLS_SMTPD
	if (ssl)
	  r = ssl_timeoutread(timeout,fd,zbuf,sizeof(zbuf));
	else
#endif
	r = timeoutread(timeout,fd,zbuf,sizeof(zbuf));
	if (r == -1) if (errno == error_timeout) die_alarm();
	if (r <= 0) die_read();
	stream.avail_in = r;
	stream.next_in = zbuf;
      }
      r = inflate(&stream, 0);
      switch (r) {
      case Z_OK:
	if (stream.avail_out == 0)
	  return len;
	break;
      case Z_STREAM_END:
	compdata = 0;
	return len - stream.avail_out;
      default:
	out("451 Receiving compressed data failed: ");
	out(stream.msg); out(" #(4.3.0)\r\n");
	flush();
	die_read();
      }
      if (stream.avail_out == len) continue;
      return len - stream.avail_out;
    } while (1);
  }
#endif
#ifdef TLS_SMTPD
  if (ssl)
    r = ssl_timeoutread(timeout,fd,buf,len);
  else
#endif
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

unsigned int bytestooverflow = 0;
unsigned int bytesreceived = 0;

void put(ch)
char *ch;
{
#ifdef SMTPEXECCHECK
  execcheck_put(&qqt, ch);
#endif
  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
  ++bytesreceived;
}

void blast(hops)
int *hops;
{
  char ch;
  int state;
  int flaginheader;
  int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */
 
  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
      }
      ++pos;
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    switch(state) {
      case 0:
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 4; continue; }
        break;
      case 1: /* \r\n */
        if (ch == '\n') straynewline();
        if (ch == '.') { state = 2; continue; }
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 2: /* \r\n + . */
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 3; continue; }
        state = 0;
        break;
      case 3: /* \r\n + .\r */
        if (ch == '\n') return;
        put(".");
        put("\r");
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 4: /* + \r */
        if (ch == '\n') { state = 1; break; }
        if (ch != '\r') { put("\r"); state = 0; }
    }
    put(&ch);
  }
}

char accept_buf[FMT_ULONG];
void acceptmessage(qp) unsigned long qp;
{
  datetime_sec when;
  when = now();
  out("250 ok ");
  accept_buf[fmt_ulong(accept_buf,(unsigned long) when)] = 0;
  out(accept_buf);
  logpid(2); logstring(2,"message queued: "); logstring(2,accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out(" by ");
  out(me.s);
  out("\r\n");
  logstring(2," qp "); logstring(2,accept_buf); logflush(2);
}

#ifdef TLS_SMTPD
stralloc protocolinfo = {0};
#endif

char receivedbytes[FMT_ULONG];
void smtp_data() {
  int hops;
  unsigned long qp;
  char *qqx;

#ifdef DATA_COMPRESS
  if (wantcomp) logline(3,"smtp dataz");
  else
#endif
  logline(3,"smtp data");

  if (!seenmail) {
    err_wantmail();
    if (errdisconnect) err_quit();
    return;
  }
  if (!rcptto.len) {
    err_wantrcpt();
    if (errdisconnect) err_quit();
    return;
  }
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;
#ifdef SMTPEXECCHECK
  execcheck_start();
#endif
  if (qmail_open(&qqt) == -1) {
    err_qqt();
    logline(1,"failed to start qmail-queue");
    return;
  }
  qp = qmail_qp(&qqt);
  out("354 go ahead punk, make my day\r\n"); logline(3,"go ahead");
  rblheader(&qqt);

#ifdef TLS_SMTPD
  if(ssl){
    if (!stralloc_copys(&protocolinfo,
       SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)))) die_nomem();
#ifdef DATA_COMPRESS
    if (wantcomp) {
      if (!stralloc_cats(&protocolinfo, " encrypted compressed SMTP"))
	die_nomem();
    } else
#endif
    if (!stralloc_cats(&protocolinfo, " encrypted SMTP")) die_nomem();
  } else {
#ifdef DATA_COMPRESS
    if (wantcomp) {
      if (!stralloc_copys(&protocolinfo,"compressed SMTP")) die_nomem();
    } else
#endif
    if (!stralloc_copys(&protocolinfo,"SMTP")) die_nomem();
  }
  if (!stralloc_0(&protocolinfo)) die_nomem();
  received(&qqt,protocolinfo.s,local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
#else 
#ifdef DATA_COMPRESS
  if (wantcomp)
    received(&qqt,"compressed SMTP",local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
  else
#endif
    received(&qqt,"SMTP",local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
#endif

#ifdef DATA_COMPRESS
  if (wantcomp) { if (compression_init() != 0) return; }
#endif
  blast(&hops);
#ifdef DATA_COMPRESS
  if (wantcomp) { if (compression_done() != 0) return; }
#endif

  receivedbytes[fmt_ulong(receivedbytes,(unsigned long) bytesreceived)] = 0;
  logpid(3); logstring(3,"data bytes received: "); logstring(3,receivedbytes); logflush(3);

  hops = (hops >= MAXHOPS);
  if (hops)
    qmail_fail(&qqt);
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);
 
  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) {
    out("554 too many hops, this message is looping (#5.4.6)\r\n");
    logline(2,"too many hops, message is looping");
    if (errdisconnect) err_quit();
    return;
  }
  if (databytes) if (!bytestooverflow) {
    out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n");
    logline(2,"datasize limit exceeded");
    if (errdisconnect) err_quit();
    return;
  }
#ifdef SMTPEXECCHECK
  if (execcheck_flag()) {
    out("552 we don't accept email with executable content (#5.3.4)\r\n");
    logline(2,"windows executable detected");
    if (errdisconnect) err_quit();
    return;
  }
#endif
  logpid(1);
  if (*qqx == 'D') {
    out("554 "); logstring(1,"message permanently not accepted because: ");
  } else {
    out("451 "); logstring(1,"message temporarly not accepted because: ");
  }
  out(qqx + 1);
  logstring(1,qqx + 1); logflush(1);
  out("\r\n");
}

#ifdef DATA_COMPRESS
void smtp_dataz()
{
  wantcomp = 1;
  smtp_data();
}
#endif

stralloc line = {0};

void smtp_auth(char *arg)
{
  struct call cct;
  char *type;
  const char *status;

  if (!flagauth) {
    err_unimpl();
    return;
  }
  logline(3,"smtp auth");
  if (authenticated) {
    out("503 you are already authenticated\r\n");
    logline(2,"reauthentication attempt rejected");
    if (errdisconnect) err_quit();
    return;
  }
#ifdef TLS_SMTPD
  if (needssl && !ssl) {
    out("538 Encryption required for requested authentication mechanism");
    logline(2,"TLS encryption required for authentication");
    if (errdisconnect) err_quit();
    return;
  }
#endif
  type = arg;
  while (*arg != '\0' && *arg != ' ') ++arg;
  if (*arg) {
    *arg++ = '\0';
    while (*arg == ' ') ++arg;
  }
  
  if (case_diffs(type, "login") == 0) {
    logline(3,"auth login");
    if (call_open(&cct, "bin/auth_smtp", 30, 1) == -1) goto fail;
    call_puts(&cct, "login"); call_put(&cct, "", 1);
    if (*arg) {
      call_puts(&cct, arg); call_put(&cct, "", 1);
    } else {
      out("334 VXNlcm5hbWU6\r\n"); flush(); /* base64 for 'Username:' */
      if (call_getln(&ssin, &line) <= 0) die_read();
      call_puts(&cct, line.s); call_put(&cct, "", 1);
    }
    out("334 UGFzc3dvcmQ6\r\n"); flush(); /* base64 for 'Password:' */
    if (call_getln(&ssin, &line) <= 0) die_read();
    call_puts(&cct, line.s); call_putflush(&cct, "", 1);
  } else if (case_diffs(type, "plain") == 0) {
    logline(3,"auth plain");
    if (call_open(&cct, "bin/auth_smtp", 30, 1) == -1) goto fail;
    call_puts(&cct, "plain"); call_put(&cct, "", 1);
    if (*arg) {
      call_puts(&cct, arg); call_putflush(&cct, "", 1);
    } else {
      out("334 \r\n"); flush();
      if (call_getln(&ssin, &line) <= 0) die_read();
      call_puts(&cct, line.s); call_putflush(&cct, "", 1);
    }
  } else {
    out("504 authentication type not supported\r\n");
    logstring(2,"authentication type ");
    logstring(2,type);
    logstring(2,": not supported");
    logflush(2);
    if (errdisconnect) err_quit();
    return;
  }
fail:
  status = auth_close(&cct, &line, authprepend);
  switch (*status) {
  case '2':
    authenticated = 1;
    remoteinfo = line.s;
    out(status);
    logline(2,"authentication success");
    break;
  case '4':
  case '5':
    sleep(1);
    out(status);
    logstring(2, "authentication failed: ");
    logstring(2, status + 4);
    logflush();
    sleep(4);
    if (errdisconnect) err_quit();
    break;
  }
}

#ifdef TLS_SMTPD
RSA *tmp_rsa_cb(ssl,export,keylength) SSL *ssl; int export; int keylength; 
{
  RSA* rsa;
  BIO* in;

  if (!export || keylength == 512)
   if (in=BIO_new(BIO_s_file_internal()))
    if (BIO_read_filename(in,"control/rsa512.pem") > 0)
     if (rsa=PEM_read_bio_RSAPrivateKey(in,NULL,NULL,NULL))
      return rsa;
  return (RSA_generate_key(export?keylength:512,RSA_F4,NULL,NULL));
}

void smtp_tls(arg) char *arg; 
{
  SSL_CTX *ctx;

  if (*arg)
  {
    out("501 Syntax error (no parameters allowed) (#5.5.4)\r\n");
    logline(1,"aborting TLS negotiations, no parameters to starttls allowed");
    return;
  }

  SSLeay_add_ssl_algorithms();
  if(!(ctx=SSL_CTX_new(SSLv23_server_method())))
  {
    out("454 TLS not available: unable to initialize ctx (#4.3.0)\r\n"); 
    logline(1,"aborting TLS negotiations, unable to initialize local SSL context");
    return;
  }
  if(!SSL_CTX_use_RSAPrivateKey_file(ctx, "control/cert.pem", SSL_FILETYPE_PEM))
  {
    out("454 TLS not available: missing RSA private key (#4.3.0)\r\n");
    logline(1,"aborting TLS negotiations, RSA private key invalid or unable to read ~control/cert.pem");
    return;
  }
  if(!SSL_CTX_use_certificate_file(ctx, "control/cert.pem", SSL_FILETYPE_PEM))
  {
    out("454 TLS not available: missing certificate (#4.3.0)\r\n"); 
    logline(1,"aborting TLS negotiations, local cert invalid or unable to read ~control/cert.pem");
    return;
  }
  SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
 
  out("220 ready for tls\r\n"); flush();

  if(!(ssl=SSL_new(ctx))) 
  {
    logline(2,"aborting TLS connection, unable to set up SSL session");
    die_read();
  }
  SSL_set_fd(ssl,0);
  if(SSL_accept(ssl)<=0)
  {
    logline(2,"aborting TLS connection, unable to finish SSL accept");
    die_read();
  }
  substdio_fdbuf(&ssout,SSL_write,ssl,ssoutbuf,sizeof(ssoutbuf));

  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  dohelo(remotehost);
}
#endif

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
#ifdef TLS_SMTPD
, { "starttls", smtp_tls, flush }
#endif
#ifdef DATA_COMPRESS
, { "dataz", smtp_dataz, flush }
#endif
, { "auth", smtp_auth, flush }
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { 0, err_unimpl, flush }
} ;

void main()
{
#ifdef TLS_SMTPD
  sig_alarmcatch(sigalrm);
#endif
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  if (ipme_init() != 1) die_ipme();
  if (greeting550) {
    stralloc_copys(&greeting,greeting550);
    if (greeting.len != 0)
      stralloc_copys(&greeting,"sorry, your mail was administratively denied. (#5.7.1)");
    smtp_line("553 ");
    err_quit();
  }
  smtp_greet("220 ");
  if (commands(&ssin,&smtpcommands) == 0) die_read();
  die_nomem();
}
