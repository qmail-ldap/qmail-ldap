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
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "dns.h"

#define MAXHOPS 100
unsigned int databytes = 0;
int timeout = 1200;

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
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
  char buf[FMT_ULONG];
  if (level > loglevel) return;
  substdio_puts(subfderr,"qmail-smtpd ");
  buf[fmt_ulong(buf,(unsigned long) getpid())] = 0;
  substdio_puts(subfderr,buf);
  substdio_puts(subfderr,": ");
}

void logline(level,string) int level; char *string;
{
  if (level > loglevel) return;
  logpid();
  substdio_puts(subfderr,string);
  substdio_puts(subfderr,"\n");
  substdio_flush(subfderr);
}

void logstring(level,string) int level; char *string;
{
  if (level > loglevel) return;
  substdio_puts(subfderr,string);
  substdio_puts(subfderr," ");
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
void die_control() { out("421 unable to read controls (#4.3.0)\r\n"); logline(1,"unable to real controls, closing connection"); flush(); _exit(1); }
void die_ipme() { out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); logline(1,"unable to figure out my IP address, closing connection"); flush(); _exit(1); }
void straynewline() { out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); logline(1,"stray new line detected, closing connection"); flush(); _exit(1); }

void err_bmf() { out("553 syntax error, please forward to your postmaster (#5.7.1)\r\n"); }
void err_nogateway() { out("553 sorry, that domain isn't in my list of allowed rcpthosts (#5.7.1)\r\n"); }
void err_unimpl(arg) char *arg; { out("502 unimplemented (#5.5.1)\r\n"); logpid(3); logstring(3,"unrecognized command ="); logstring(3,arg); logflush(3); }
void err_syntax() { out("555 syntax error (#5.5.4)\r\n"); }
void err_wantmail() { out("503 MAIL first (#5.5.1)\r\n"); logline(3,"'mail from' first"); }
void err_wantrcpt() { out("503 RCPT first (#5.5.1)\r\n"); logline(3,"'rcpt to' first"); }
void err_noop() { out("250 ok\r\n"); logline(3,"'noop'"); }
void err_vrfy(arg) char *arg; { out("252 send some mail, i'll try my best\r\n"); logpid(3); logstring(3,"vrfy for ="); logstring(3,arg); logflush(3); }
void err_qqt() { out("451 qqt failure (#4.3.0)\r\n"); }
void err_dns() { out("451 DNS temporary failure (#4.3.0)\r\n"); }
void err_spam() { out("553 sorry, mail from your location is not accepted here (#5.7.1)\r\n"); }
void err_badrcptto() { out("553 sorry, mail to that recipient is not accepted on this system (#5.7.1)\r\n"); }


stralloc greeting = {0};
int brtok = 0;
stralloc brt = {0};
struct constmap mapbadrcptto;

void smtp_greet(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_put(&ssout,greeting.s,greeting.len);
}
void smtp_help()
{
  out("214 qmail home page: http://pobox.com/~djb/qmail.html\r\n");
  out("214 qmail-ldap patch home page: http://www.nrg4u.com\r\n");
  logline(3,"help requested");
}
void smtp_quit()
{
  smtp_greet("221 "); out("\r\n");
  logline(3,"quit, closing connection");
  flush(); _exit(0);
}

char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *relayclient;
int spamflag = 0;
char *denymail;

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
int tarpitcount = 0;
int tarpitdelay = 5;

void setup()
{
  char *x, *l;
  unsigned long u, v;

  l = env_get("LOGLEVEL");
  if (l) { scan_ulong(l,&v); loglevel = v; };

  if (control_init() == -1) die_control();
  if (control_rldef(&greeting,"control/smtpgreeting",1,(char *) 0) != 1)
    die_control();
  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();

  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;

  if (control_readint(&tarpitcount,"control/tarpitcount") == -1) die_control();
  if (tarpitcount < 0) tarpitcount = 0;
  x = env_get("TARPITCOUNT");
  if (x) { scan_ulong(x,&u); tarpitcount = u; };
  if (control_readint(&tarpitdelay,"control/tarpitdelay") == -1) die_control();
  if (tarpitdelay < 0) tarpitdelay = 0;
  x = env_get("TARPITDELAY");
  if (x) { scan_ulong(x,&u); tarpitdelay = u; };

  if (rcpthosts_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  brtok = control_readfile(&brt,"control/badrcptto",0);
  if (brtok == -1) die_control();
  if (brtok)
    if (!constmap_init(&mapbadrcptto,brt.s,brt.len,0)) die_nomem();
 
  if (control_readint(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;
 
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  logpid(2); logstring(2,"connection from"); logstring(2,remoteip);
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  logstring(2,"("); logstring(2,remotehost);
  remoteinfo = env_get("TCPREMOTEINFO");
  if (remoteinfo) { logstring(2,","); logstring(2,remoteinfo); }
  logstring(2,") to");

  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
  logstring(2,local);

  relayclient = env_get("RELAYCLIENT");
  if (relayclient) { logstring(2,", relayclient set"); }
  denymail = env_get("DENYMAIL");
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

int badmxcheck(dom) char *dom;
{
  ipalloc checkip = {0};
  int ret=0;
  stralloc checkhost = {0};

  if (!*dom) return (DNS_HARD);
  if (!stralloc_copys(&checkhost,dom)) return (DNS_SOFT);
  
  switch (dns_mxip(&checkip,&checkhost,1))
  {
    case DNS_MEM:
    case DNS_SOFT:
         ret=DNS_SOFT;
         break;
         
    case DNS_HARD: 
         ret=DNS_HARD; 
         break;
    case 1:
         if (checkip.len <= 0) ret=DNS_HARD; 
         break;
  }

  return (ret);
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

int seenmail = 0;
int flagbarf; /* defined if seenmail */
stralloc mailfrom = {0};
stralloc rcptto = {0};
int rcptcount;


int addrallowed()
{
  int r,j;
  j = byte_rchr(addr.s,addr.len,'@');
  if (brtok)
    if (constmap(&mapbadrcptto, addr.s, addr.len - 1) ||
        constmap(&mapbadrcptto, addr.s + j, addr.len - j - 1))
       { logpid(2); logstring(2,addr.s); logflush(2); return 2; }
  r = rcpthosts(addr.s,str_len(addr.s));
  if (r == -1) die_control();
  return r;
}


void smtp_helo(arg) char *arg;
{
  smtp_greet("250 "); out("\r\n");
  seenmail = 0; dohelo(arg);
  logpid(3); logstring(3,"remote helo ="); logstring(3,arg); logflush(3);
}
void smtp_ehlo(arg) char *arg;
{
  smtp_greet("250-"); out("\r\n250-PIPELINING\r\n250 8BITMIME\r\n");
  seenmail = 0; dohelo(arg);
  logpid(3); logstring(3,"remote ehlo ="); logstring(3,arg); logflush(3);
}
void smtp_rset()
{
  seenmail = 0;
  out("250 flushed\r\n");
  logline(3,"remote rset");
}

void smtp_mail(arg) char *arg;
{
  int i,j;
  char *why;
  logpid(3); logstring(3,"remote sent 'mail from' ="); logstring(3,arg); logflush(3);
  if (!addrparse(arg))
  {
    err_syntax(); 
    logpid(2); logstring(2,"RFC821 syntax error in mail from ="); logstring(2,arg); logflush(2);
    return;
  }
  logpid(3); logstring(3,"mail from ="); logstring(3,addr.s); logflush(3);
  flagbarf = bmfcheck();
  if (flagbarf)
  {
    err_bmf();
    logpid(2); logstring(2,"bad mail from ="); logstring(2,arg); logflush(2);
    return;
  }

  /************
   DENYMAIL is set for this session from this client, 
             so heavy checking of mailfrom
   SPAM     -> refuse all mail
   NOBOUNCE -> refuse null mailfrom
   DNSCHECK -> validate Mailfrom domain
  ************/

  if (denymail)
  {
    if (!str_diff("SPAM", denymail)) {
       flagbarf=1;
       spamflag=1;
       why = "refused to accept SPAM";
    }
    else
      if (!addr.s[0] || !str_diff("#@[]", addr.s)) /*mjr*/
      /* if (!addr.s[0]) */
      {  
         if (!str_diff("NOBOUNCE", denymail)) {
            why = "refused to accept RFC821 bounce from remote";
            flagbarf=1;
         }
      }
      else
      {
        /*why = "Invalid.Mailfrom";*/
        if ((i=byte_rchr(addr.s,addr.len,'@')) >= addr.len) {
           why = "refused 'mail from' without @";
           flagbarf=1; }      /* no '@' in from */
        else
        {
          /* money!@domain.TLD */
          if (addr.s[i-1] == '!') {
             why = "refused 'mail from' with !@";
             flagbarf=1; }
             
          /* check syntax, visual */
          if ((j = byte_rchr(addr.s+i, addr.len-i, '.')) >= addr.len-i) {
             why = "refused 'mail from' without . in domain";
             flagbarf=1; } /* curious no '.' in domain.TLD */
         
          j = addr.len-(i+1+j+1);
          if (j < 2 || j > 3) {
             why = "refused 'mail from' without country or top level domain";
             flagbarf=1; } /* root domain, not a country (2), nor TLD (3)*/

         if (!flagbarf)
          if (!str_diff("DNSCHECK", denymail)) 
          {
             /* check syntax, via DNS */
             switch (badmxcheck(&addr.s[i+1]))
             {
               case 0:                 break; /*valid*/
               case DNS_SOFT:  flagbarf=2; /*fail tmp*/
                               why = "refused 'mail from' because return MX lookup failed temporarly";
                               break;
               case DNS_HARD:  flagbarf=1; 
                               why = "refused 'mail from' because return MX does not exist";
                               break;
             }
          }
        }
      }
    if (flagbarf)    
    {
      logpid(2); logstring(2,why); logstring(2,"for ="); logstring(2,addr.s); logflush(2);
      if (2==flagbarf)
        err_dns(); 
      else if (1==spamflag)
        err_spam();
      else
        err_bmf();
      return;
    }
  } /* denymail */
  seenmail = 1;
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();
  rcptcount = 0;
  out("250 ok\r\n");
}

void smtp_rcpt(arg) char *arg; {
  if (!seenmail) { err_wantmail(); return; }
  logpid(3); logstring(3,"remote sent 'rcpt to' ="); logstring(3,arg); logflush(3);
  if (!addrparse(arg))
  {
    err_syntax();
    logpid(2); logstring(2,"syntax error in 'rcpt to' ="); logstring(2,arg); logflush(2);
    return;
  }
  logpid(3); logstring(3,"rcpt to ="); logstring(3,addr.s); logflush(3);
  if (relayclient) {
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  }
  else {
    if (addrallowed()==2)
    {
      err_badrcptto();
      logpid(2); logstring(2,"'rcpt to' not allowed ="); logstring(2,arg); logflush(2);
      return;
    }
    if (!addrallowed()) 
    { 
       err_nogateway(); 
       logpid(2); logstring(2,"no mail relay for 'rcpt to' ="); logstring(2,arg); logflush(2);
       return; 
    }
  }
  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();
  if (tarpitcount && ++rcptcount >= tarpitcount)
  {
    logline(2,"tarpitting");
    while (sleep(tarpitdelay)); 
  }
  out("250 ok\r\n");
}


int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  flush();
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

struct qmail qqt;
unsigned int bytestooverflow = 0;

void put(ch)
char *ch;
{
  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
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
  logpid(2); logstring(2,"message queued ="); logstring(2,accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out("\r\n");
  logstring(2,"qp"); logstring(2,accept_buf); logflush(2);
}

void smtp_data() {
  int hops;
  unsigned long qp;
  char *qqx;
  char buf[FMT_ULONG];
 
  logline(3,"smtp data");
  if (!seenmail) { err_wantmail(); return; }
  if (!rcptto.len) { err_wantrcpt(); return; }
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;
  if (qmail_open(&qqt) == -1) { err_qqt(); logline(1,"failed to start qmail-queue"); return; }
  qp = qmail_qp(&qqt);
  out("354 go ahead\r\n"); logline(3,"go ahead");
 
  received(&qqt,"SMTP",local,remoteip,remotehost,remoteinfo,fakehelo,mailfrom.s,&rcptto.s[1]);
  blast(&hops);
  hops = (hops >= MAXHOPS);
  if (hops) { logline(2,"hop count exceeded"); qmail_fail(&qqt); }
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);
 
  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) { out("554 too many hops, this message is looping (#5.4.6)\r\n"); return; }
  if (databytes) if (!bytestooverflow)
  {
    out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n");
    logline(2,"datasize limit exceeded");
    return;
  }
  logpid(1);
  if (*qqx == 'D') { out("554 "); logstring(1,"message not accepted because ="); }
    else { out("451 "); logstring(1,"message not accepted because ="); }
  out(qqx + 1);
  logstring(1,qqx+1); logflush(1);
  out("\r\n");
}

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { 0, err_unimpl, flush }
} ;

void main()
{
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  if (ipme_init() != 1) die_ipme();
  smtp_greet("220 ");
  out(" ESMTP\r\n");
  if (commands(&ssin,&smtpcommands) == 0) die_read();
  die_nomem();
}
