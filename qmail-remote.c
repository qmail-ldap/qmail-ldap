#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sig.h"
#include "stralloc.h"
#include "substdio.h"
#include "subfd.h"
#include "scan.h"
#include "case.h"
#include "error.h"
#include "auto_qmail.h"
#include "control.h"
#include "dns.h"
#include "alloc.h"
#include "quote.h"
#include "fmt.h"
#include "ip.h"
#include "ipalloc.h"
#include "ipme.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "str.h"
#include "now.h"
#include "exit.h"
#include "constmap.h"
#include "tcpto.h"
#include "readwrite.h"
#include "timeoutconn.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "base64.h"
#include "xtext.h"
#ifdef TLS
#include <tls.h>
#include "ndelay.h"
#include "tlsreadwrite.h"
#endif
#ifdef DATA_COMPRESS
#include <zlib.h>
#endif

#ifdef TLS
struct tls *tls = NULL;
#endif

#define HUGESMTPTEXT 5000

#ifndef PORT_SMTP /* this is for testing purposes, so you can overwrite it */
#define PORT_SMTP 25 /* silly rabbit, /etc/services is for users */
#endif
#ifndef PORT_QMTP /* this is for testing purposes, so you can overwrite it */
#define PORT_QMTP 209 /* silly rabbit, /etc/services is for users */
#endif
unsigned long smtp_port = PORT_SMTP;
unsigned long qmtp_port = PORT_QMTP;

GEN_ALLOC_typedef(saa,stralloc,sa,len,a)
GEN_ALLOC_readyplus(saa,stralloc,sa,len,a,i,n,x,10,saa_readyplus)
static stralloc sauninit = {0};

stralloc helohost = {0};
stralloc outgoingip = {0};
stralloc routes = {0};
struct constmap maproutes;
stralloc host = {0};
stralloc sender = {0};
stralloc auth_login = {0};
stralloc auth_passwd = {0};

saa reciplist = {0};

struct ip_address partner;
struct ip_address outip;

void out(const char *s) { if (substdio_puts(subfdoutsmall,s) == -1) _exit(0); }
void zero(void) { if (substdio_put(subfdoutsmall,"\0",1) == -1) _exit(0); }
void zerodie(void) { zero(); substdio_flush(subfdoutsmall); _exit(0); }
void outsafe(stralloc *sa) { unsigned int i; char ch;
for (i = 0;i < sa->len;++i) {
ch = sa->s[i]; if (ch < 33) ch = '?'; if (ch > 126) ch = '?';
if (substdio_put(subfdoutsmall,&ch,1) == -1) _exit(0); } }

void temp_noip(void) { out("Zinvalid ipaddr in control/outgoingip (#4.3.0)\n"); zerodie(); }
void temp_nomem(void) { out("ZOut of memory. (#4.3.0)\n"); zerodie(); }
void temp_oserr(void) { out("Z\
System resources temporarily unavailable. (#4.3.0)\n"); zerodie(); }
void temp_noconn(void) { out("Z\
Sorry, I wasn't able to establish an SMTP connection. (#4.4.1)\n"); zerodie(); }
void temp_read(void) { out("ZUnable to read message. (#4.3.0)\n"); zerodie(); }
void temp_dnscanon(void) { out("Z\
CNAME lookup failed temporarily. (#4.4.3)\n"); zerodie(); }
void temp_dns(void) { out("Z\
Sorry, I couldn't find any host by that name. (#4.1.2)\n"); zerodie(); }
void temp_chdir(void) { out("Z\
Unable to switch to home directory. (#4.3.0)\n"); zerodie(); }
void temp_control(void) { out("Z\
Unable to read control files. (#4.3.0)\n"); zerodie(); }
void temp_proto(void) { out("Z\
recipient did not talk proper QMTP (#4.3.0)\n"); zerodie(); }
void perm_partialline(void) { out("D\
SMTP cannot transfer messages with partial final lines. (#5.6.2)\n"); zerodie(); }
void perm_usage(void) { out("D\
I (qmail-remote) was invoked improperly. (#5.3.5)\n"); zerodie(); }
void perm_dns(void) { out("D\
Sorry, I couldn't find any host named ");
outsafe(&host);
out(". (#5.1.2)\n"); zerodie(); }
void perm_nomx(void) { out("D\
Sorry, I couldn't find a mail exchanger or IP address. (#5.4.4)\n");
zerodie(); }
void perm_ambigmx(void) { out("D\
Sorry. Although I'm listed as a best-preference MX or A for that host,\n\
it isn't in my control/locals file, so I don't treat it as local. (#5.4.6)\n");
zerodie(); }
void perm_looping(void) { out("D\
Sorry. Message is looping within cluster, giving up. (#5.4.6)\n");
zerodie(); }

void outhost(void)
{
  char x[IPFMT];
  if (substdio_put(subfdoutsmall,x,ip_fmt(x,&partner)) == -1) _exit(0);
}

int flagcritical = 0;

#ifdef TLS
void dropped_tls(void)
{
  out("ZConnected to ");
  outhost();
  out(" but TLS connection died: ");
  if (errno == error_timeout)
    out("timeout ");
  else {
    out(tls_error(tls));
    out(" ");
  }
  if (flagcritical) out("Possible duplicate! ");
  out("(#4.4.2)\n");
  zerodie();
}
#endif

void dropped(void) {
  out("ZConnected to ");
  outhost();
  out(" but connection died. ");
  if (flagcritical) out("Possible duplicate! ");
  out("(#4.4.2)\n");
  zerodie();
}

int timeoutconnect = 60;
int smtpfd;
int timeout = 120;

#ifdef DATA_COMPRESS
z_stream stream;
char zbuf[4096];
int compdata = 0;
int wantcomp = 0;

void compression_init(void)
{
  compdata = 1;
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_out = sizeof(zbuf);
  stream.next_out = zbuf;
  if (deflateInit(&stream,Z_DEFAULT_COMPRESSION) != Z_OK) {
    out("ZInitalizing data compression failed: ");
    out(stream.msg); out(" #(4.3.0)\n");
    zerodie();
  }
}
void compression_done(void)
{
  int r;

  compdata = 0;
  do {
    r = deflate(&stream,Z_FINISH);
    switch (r) {
    case Z_OK:
      if (stream.avail_out == 0) {
#ifdef TLS
	if (tls) {
	  r = tlstimeoutwrite(timeout,smtpfd,tls,zbuf,sizeof(zbuf));
	  if (r == -1)
	    dropped_tls();
	} else
#endif
	r = timeoutwrite(timeout,smtpfd,zbuf,sizeof(zbuf));
	if (r <= 0) dropped();
	stream.avail_out = sizeof(zbuf);
	stream.next_out = zbuf;
	r = Z_OK;
      }
      break;
    case Z_STREAM_END:
      break;
    default:
      out("ZSending compressed data to "); outhost();
      out("but compression failed: ");
      out(stream.msg); out(" (#4.4.2)\n");
      zerodie();
    }
  } while (r!=Z_STREAM_END);
  if (stream.avail_out != sizeof(zbuf)) {
    /* write left data */
#ifdef TLS
    if (tls) {
      r = tlstimeoutwrite(timeout,smtpfd,tls,zbuf,
	  sizeof(zbuf)-stream.avail_out);
      if (r == -1)
        dropped_tls();
    } else
#endif
    r = timeoutwrite(timeout,smtpfd,zbuf,sizeof(zbuf)-stream.avail_out);
    if (r <= 0) dropped();
  }
  if (deflateEnd(&stream) != Z_OK) {
    out("ZFinishing data compression failed: ");
    if (stream.msg) out(stream.msg); else out("unknown error");
    if (flagcritical) out(". Possible duplicate!");
    out(" #(4.3.0)\n");
    zerodie();
  }
}
#endif

int saferead(int fd, void *buf, int len)
{
  int r;
#ifdef TLS
  if (tls) {
    r = tlstimeoutread(timeout,smtpfd,tls,buf,len);
    if (r == -1)
      dropped_tls();
  } else
#endif
  r = timeoutread(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}
int safewrite(int fd, void *buf, int len)
{
  int r;
#ifdef DATA_COMPRESS
  if (compdata == 1) {
    stream.avail_in = len;
    stream.next_in = buf;
    do {
      r = deflate(&stream, 0);
      switch (r) {
      case Z_OK:
	if (stream.avail_out == 0) {
#ifdef TLS
	  if (tls) {
	    r = tlstimeoutwrite(timeout,smtpfd,tls,zbuf,sizeof(zbuf));
	    if (r == -1)
	      dropped_tls();
	  } else
#endif
	  r = timeoutwrite(timeout,smtpfd,zbuf,sizeof(zbuf));
	  if (r <= 0) dropped();
	  stream.avail_out = sizeof(zbuf);
	  stream.next_out = zbuf;
	}
	break;
      default:
	out("ZSending compressed data to "); outhost();
	out("but compression failed: ");
	out(stream.msg); out(" (#4.4.2)\n");
	zerodie();
      }
    } while (stream.avail_in != 0);
    return len;
  }
#endif
#ifdef TLS
  if (tls) {
    r = tlstimeoutwrite(timeout,smtpfd,tls,buf,len);
    if (r == -1)
      dropped_tls();
  } else
#endif
  r = timeoutwrite(timeout,smtpfd,buf,len);
  if (r <= 0) dropped();
  return r;
}

char inbuf[1500];
substdio ssin = SUBSTDIO_FDBUF(subread,0,inbuf,sizeof inbuf);
char smtptobuf[1500];
substdio smtpto = SUBSTDIO_FDBUF(safewrite,-1,smtptobuf,sizeof smtptobuf);
char smtpfrombuf[128];
substdio smtpfrom = SUBSTDIO_FDBUF(saferead,-1,smtpfrombuf,sizeof smtpfrombuf);

stralloc smtptext = {0};

void get(char *ch)
{
  substdio_get(&smtpfrom,ch,1);
  if (*ch != '\r')
    if (smtptext.len < HUGESMTPTEXT)
     if (!stralloc_append(&smtptext,ch)) temp_nomem();
}

unsigned long smtpcode(void)
{
  unsigned char ch;
  unsigned long code;

  if (!stralloc_copys(&smtptext,"")) temp_nomem();

  get(&ch); code = ch - '0';
  get(&ch); code = code * 10 + (ch - '0');
  get(&ch); code = code * 10 + (ch - '0');
  for (;;) {
    get(&ch);
    if (ch != '-') break;
    while (ch != '\n') get(&ch);
    get(&ch);
    get(&ch);
    get(&ch);
  }
  while (ch != '\n') get(&ch);

  return code;
}

void outsmtptext(void)
{
  unsigned int i; 
  if (smtptext.s) if (smtptext.len) {
    out("Remote host said: ");
    for (i = 0;i < smtptext.len;++i)
      if (!smtptext.s[i]) smtptext.s[i] = '?';
    if (substdio_put(subfdoutsmall,smtptext.s,smtptext.len) == -1) _exit(0);
    smtptext.len = 0;
  }
}

void quit(const char *prepend, const char *append)
{
#ifdef DATA_COMPRESS
  int r;
  char num[FMT_ULONG];
#endif
  substdio_putsflush(&smtpto,"QUIT\r\n");
  /* waiting for remote side is just too ridiculous */
  out(prepend);
  outhost();
  out(append);
  out(".\n");
#ifdef DATA_COMPRESS
  if (wantcomp == 2) {
	  r = 100 - (int)(100.0*stream.total_out/stream.total_in);
	  if (r < 0) {
	    num[0] = '-'; r*= -1;
	  } else
	    num[0] = ' ';
	  num[fmt_uint(num+1,r) + 1] = 0;
	  out("DDC saved ");
	  out(num); out(" percent.\n");
  }
#endif

#ifdef TLS
 if (tls) {
  int ret;

  out("STARTTLS proto=");
  out(tls_conn_version(tls));
  out("; cipher=");
  out(tls_conn_cipher(tls));

  /* we want certificate details */
  if (tls_peer_cert_provided(tls)) {
    out("; fingerprint=");
    out(tls_peer_cert_hash(tls));
  }
  out(";\n");

  do {
    ret = tls_close(tls);
  } while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);
 }
#endif

  outsmtptext();
  zerodie();
}

void blast(void)
{
  int r;
  char ch;

  for (;;) {
    r = substdio_get(&ssin,&ch,1);
    if (r == 0) break;
    if (r == -1) temp_read();
    if (ch == '.')
      substdio_put(&smtpto,".",1);
    while (ch != '\n') {
      substdio_put(&smtpto,&ch,1);
      r = substdio_get(&ssin,&ch,1);
      if (r == 0) perm_partialline();
      if (r == -1) temp_read();
    }
    substdio_put(&smtpto,"\r\n",2);
  }
 
  flagcritical = 1;
  substdio_put(&smtpto,".\r\n",3);
  substdio_flush(&smtpto);
}

stralloc cookie = {0};
stralloc recip = {0};
#ifdef TLS
stralloc tlscert = {0};
stralloc tlsciphers = {0};
stralloc tlsdheparams = {0};
stralloc tlshost = {0};
#endif
stralloc xtext = {0};

void smtp(void)
{
  struct stat st;
  unsigned long len;
  unsigned long code;
  int flagbother;
  int flagsize;
  int flagauth;
  unsigned int i, j;
  char num[FMT_ULONG];
#ifdef TLS
  int flagtls = 0;
  int r;
  struct tls_config *tls_config;
#endif

  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but greeting failed");
  if (code >= 400) return;
  if (code != 220) quit("ZConnected to "," but greeting failed");

  if (cookie.len > 0)
    if (smtptext.len > cookie.len + 1)
      if (!str_diffn(smtptext.s + smtptext.len - cookie.len - 1,
		  cookie.s, cookie.len))
        perm_looping();
  
  flagsize = 0;
  flagauth = 0;
  substdio_puts(&smtpto,"EHLO ");
  substdio_put(&smtpto,helohost.s,helohost.len);
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);

  code = smtpcode();
  if (code != 250) {
   substdio_puts(&smtpto,"HELO ");
   substdio_put(&smtpto,helohost.s,helohost.len);
   substdio_puts(&smtpto,"\r\n");
   substdio_flush(&smtpto);
   code = smtpcode();
   if (code >= 500) quit("DConnected to "," but my name was rejected");
   if (code >= 400) return;
   if (code != 250) quit("ZConnected to "," but my name was rejected");
  }

  /* extension handling */
  for (i = 0; i < smtptext.len; i += str_chr(smtptext.s+i,'\n') + 1) {
    if (i+8 < smtptext.len && !case_diffb("SIZE", 4, smtptext.s+i+4) )
      flagsize = 1;
#ifdef DATA_COMPRESS
    else if (i+9 < smtptext.len && !case_diffb("DATAZ", 5, smtptext.s+i+4))
            wantcomp = 1;
#endif
#ifdef TLS
    else if (i+12 < smtptext.len && !case_diffb("STARTTLS", 8, smtptext.s+i+4))
      flagtls = 1;
#endif
    else if (i+9 < smtptext.len && !case_diffb("AUTH ", 5, smtptext.s+i+4)) {
      for (j = i+4; j < smtptext.len; j++)
	if (smtptext.s[j] == ' ')
	  if (j + 6 < smtptext.len && !case_diffb("LOGIN", 5, smtptext.s+j+1))
	    flagauth = 1;
    }
  }

#ifdef TLS
  if (flagtls) {
    substdio_puts(&smtpto,"STARTTLS\r\n");
    substdio_flush(&smtpto);
    if (smtpcode() == 220) {
      tls_config = tls_config_new();
      if (tls_config == NULL)
        temp_nomem();

      if (tls_config_set_protocols(tls_config, TLS_PROTOCOLS_ALL) != 0 ||
          tls_config_set_ciphers(tls_config, tlsciphers.s) != 0 ||
          tls_config_set_dheparams(tls_config, tlsdheparams.s) != 0) {
fail:
        out("ZTLS not available: error initializing ssl: ");
        out(tls_config_error(tls_config));
        out("\n");
        zerodie();
      }

      if (tls_config_set_ca_file(tls_config, tls_default_ca_cert_file()) != 0)
        goto fail;

      if (tlscert.s && *tlscert.s) {
	if (tls_config_set_cert_file(tls_config, tlscert.s) != 0)
	  goto fail;
	if (tls_config_set_key_file(tls_config, tlscert.s) != 0)
	  goto fail;
      }

      tls_config_insecure_noverifycert(tls_config);
      tls_config_insecure_noverifyname(tls_config);
      tls_config_insecure_noverifytime(tls_config);

      if (!(tls = tls_client()))
	temp_nomem();
      if (tls_configure(tls, tls_config) == -1) {
        out("ZTLS not available: error initializing ssl: ");
        out(tls_error(tls));
        out("\n");
        zerodie();
      }

      if (!stralloc_copy(&tlshost,&host)) temp_nomem();
      if (!stralloc_0(&tlshost)) temp_nomem();

      if (ndelay_on(smtpfd) == -1) {
        out("ZTLS not available: failed to set no delay\n");
        zerodie();
      }
      if (tls_connect_socket(tls, smtpfd, tlshost.s) == -1) {
        out("ZTLS not available: connect failed: ");
        out(tls_error(tls));
        out("\n");
        zerodie();
      }

      /* re-EHLO as per RFC */
      substdio_puts(&smtpto,"EHLO ");
      substdio_put(&smtpto,helohost.s,helohost.len);
      substdio_puts(&smtpto,"\r\n");
      substdio_flush(&smtpto);

      if (smtpcode() != 250) {
	quit("ZTLS connected to "," but my name was rejected");
      }

      /* extension handling */
      for (i = 0; i < smtptext.len; i += str_chr(smtptext.s+i,'\n') + 1) {
	if (i+8 < smtptext.len && !case_diffb("SIZE", 4, smtptext.s+i+4) )
	  flagsize = 1;
#ifdef DATA_COMPRESS
	else if (i+9 < smtptext.len && !case_diffb("DATAZ", 5, smtptext.s+i+4))
	  wantcomp = 1;
#endif
        else if (i+9 < smtptext.len &&
	    !case_diffb("AUTH ", 5, smtptext.s+i+4)) {
	  for (j = i+4; j < smtptext.len; j++)
	    if (smtptext.s[j] == ' ')
	      if (j + 6 < smtptext.len &&
	          !case_diffb("LOGIN", 5, smtptext.s+j+1))
		flagauth = 1;
	}
      }
    } 
  }
#endif

  if (flagauth && auth_login.len && auth_passwd.len) {
    substdio_putsflush(&smtpto,"AUTH LOGIN\r\n");
    code = smtpcode();
    if (code >= 500)
      quit("DConnected to "," but authentication was rejected (AUTH LOGIN)");
    if (code >= 400)
      quit("ZConnected to "," but authentication was rejected (AUTH LOGIN)");

    substdio_put(&smtpto,auth_login.s,auth_login.len);
    substdio_putsflush(&smtpto,"\r\n");
    code = smtpcode();
    if (code >= 500)
      quit("DConnected to "," but authentication was rejected (username)");
    if (code >= 400)
      quit("ZConnected to "," but authentication was rejected (username)");

    substdio_put(&smtpto,auth_passwd.s,auth_passwd.len);
    substdio_putsflush(&smtpto,"\r\n");
    code = smtpcode();
    if (code >= 500)
      quit("DConnected to "," but authentication was rejected (password)");
    if (code >= 400)
      quit("ZConnected to "," but authentication was rejected (password)");
  } else if (auth_login.len && auth_passwd.len) {
    quit("ZConnected to "," but no SMTP AUTH support detected but needed.");
  }

  substdio_puts(&smtpto,"MAIL FROM:<");
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_puts(&smtpto,">");
  if (flagsize) {
    substdio_puts(&smtpto," SIZE=");
    if (fstat(0,&st) == -1) quit("Z", " unable to fstat stdin");
    len = st.st_size;
    len += len>>5; /* add some size for the \r chars see rcf 1870 */
    substdio_put(&smtpto,num,fmt_ulong(num,len+1));
  }
  if (flagauth && auth_login.len && auth_passwd.len) {
    substdio_puts(&smtpto, " AUTH=<");
    if (!xtext_quote(&xtext, &sender))
	    temp_nomem();
    substdio_put(&smtpto,xtext.s,xtext.len);
    substdio_puts(&smtpto,">");
  }
  substdio_puts(&smtpto,"\r\n");
  substdio_flush(&smtpto);
  code = smtpcode();
  if (code >= 500) quit("DConnected to "," but sender was rejected");
  if (code >= 400) quit("ZConnected to "," but sender was rejected");
 
  flagbother = 0;
  for (i = 0;i < reciplist.len;++i) {
    substdio_puts(&smtpto,"RCPT TO:<");
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_puts(&smtpto,">\r\n");
    substdio_flush(&smtpto);
    code = smtpcode();
    if (code >= 500) {
      out("h"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else if (code >= 400) {
      out("s"); outhost(); out(" does not like recipient.\n");
      outsmtptext(); zero();
    }
    else {
      out("r"); zero();
      flagbother = 1;
    }
  }
  if (!flagbother) quit("DGiving up on ","");
 
#ifdef DATA_COMPRESS
  if (wantcomp == 1) {
    substdio_putsflush(&smtpto,"DATAZ\r\n");
    compression_init();
  } else
#endif
  substdio_putsflush(&smtpto,"DATA\r\n");
  code = smtpcode();
#ifdef DATA_COMPRESS
  if (wantcomp == 1) {
    if (code >= 500) quit("D"," failed on DATAZ command");
    if (code >= 400) quit("Z"," failed on DATAZ command");
  } else {
#endif
  if (code >= 500) quit("D"," failed on DATA command");
  if (code >= 400) quit("Z"," failed on DATA command");
#ifdef DATA_COMPRESS
  }
#endif
 
  blast();
#ifdef DATA_COMPRESS
  if (wantcomp == 1)
    compression_done();
#endif
  code = smtpcode();
  flagcritical = 0;
  if (code >= 500) quit("D"," failed after I sent the message");
  if (code >= 400) quit("Z"," failed after I sent the message");
#ifdef DATA_COMPRESS
  wantcomp++;
#endif
  quit("K"," accepted message");
}

int qmtp_priority(int pref)
{
  if (pref < 12800) return 0;
  if (pref > 13055) return 0;
  if (pref % 16 == 1) return 1;
  return 0;
}

void qmtp(void)
{
  struct stat st;
  unsigned long len;
  char *x;
  unsigned int i;
  int n;
  unsigned char ch;
  unsigned char rv;
  char num[FMT_ULONG];
  int flagbother;

  if (fstat(0,&st) == -1) quit("Z", " unable to fstat stdin");
  len = st.st_size;

  /* the following code was substantially taken from serialmail's serialqmtp.c */
  substdio_put(&smtpto,num,fmt_ulong(num,len+1));
  substdio_put(&smtpto,":\n",2);
  while (len > 0) {
    n = substdio_feed(&ssin);
    if (n <= 0) temp_read(); /* wise guy again */
    x = substdio_PEEK(&ssin);
    substdio_put(&smtpto,x,n);
    substdio_SEEK(&ssin,n);
    len -= n;
  }
  substdio_put(&smtpto,",",1);

  len = sender.len;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  substdio_put(&smtpto,sender.s,sender.len);
  substdio_put(&smtpto,",",1);

  len = 0;
  for (i = 0;i < reciplist.len;++i)
    len += fmt_ulong(num,reciplist.sa[i].len) + 1 + reciplist.sa[i].len + 1;
  substdio_put(&smtpto,num,fmt_ulong(num,len));
  substdio_put(&smtpto,":",1);
  for (i = 0;i < reciplist.len;++i) {
    substdio_put(&smtpto,num,fmt_ulong(num,reciplist.sa[i].len));
    substdio_put(&smtpto,":",1);
    substdio_put(&smtpto,reciplist.sa[i].s,reciplist.sa[i].len);
    substdio_put(&smtpto,",",1);
  }
  substdio_put(&smtpto,",",1);
  substdio_flush(&smtpto);

  flagbother = 0;

  for (i = 0;i < reciplist.len;++i) {
    len = 0;
    for (;;) {
      get(&ch);
      if (ch == ':') break;
      if (len > 200000000) temp_proto();
      if (ch - '0' > 9) temp_proto();
      len = 10 * len + (ch - '0');
    }
    if (!len) temp_proto();
    get(&ch); --len;
    if ((ch != 'Z') && (ch != 'D') && (ch != 'K')) temp_proto();

    rv = ch;
    if (!stralloc_copys(&smtptext,"qmtp: ")) temp_nomem();

    /* read message */
    while (len > 0) {
      get(&ch);
      --len;
    }
    get(&ch);
    if (ch != ',') temp_proto();
    smtptext.s[smtptext.len-1] = '\n';

    switch (rv) {
      case 'K':
        out("r"); zero();
	flagbother = 1;
	break;
      case 'D':
        out("h"); outhost(); out("  does not like recipient.\n");
	outsmtptext(); zero();
	break;
      case 'Z':
        out("h"); outhost(); out("  does not like recipient.\n");
	outsmtptext(); zero();
	break;
    }
  }
  if (!flagbother) {
    out("DGiving up on "); outhost(); out(".\n"); outsmtptext();
  } else {
    out("K");outhost();out(" accepted message.\n"); outsmtptext();
  }
  zerodie();
}

stralloc canonhost = {0};
stralloc canonbox = {0};

void addrmangle(saout,s,flagalias)
stralloc *saout; /* host has to be canonical, box has to be quoted */
char *s;
int *flagalias;
{
  unsigned int j;
 
  *flagalias = 0;
 
  j = str_rchr(s,'@');
  if (!s[j]) {
    if (!stralloc_copys(saout,s)) temp_nomem();
    return;
  }
  if (!stralloc_copys(&canonbox,s)) temp_nomem();
  canonbox.len = j;
  if (!quote(saout,&canonbox)) temp_nomem();
  if (!stralloc_cats(saout,"@")) temp_nomem();
 
  if (!stralloc_copys(&canonhost,s + j + 1)) temp_nomem();
  if (!stralloc_cat(saout,&canonhost)) temp_nomem();
}

void getcontrols(void)
{
  if (control_init() == -1) temp_control();
  if (control_rldef(&cookie,"control/smtpclustercookie",0,"") == -1)
    temp_control();
  if (cookie.len > 32) cookie.len = 32;
  if (control_readint(&timeout,"control/timeoutremote") == -1) temp_control();
  if (control_readint(&timeoutconnect,"control/timeoutconnect") == -1)
    temp_control();
  if (control_rldef(&helohost,"control/helohost",1,(char *) 0) != 1)
    temp_control();
  switch(control_readfile(&routes,"control/smtproutes",0)) {
    case -1:
      temp_control();
    case 0:
      if (!constmap_init(&maproutes,"",0,1)) temp_nomem(); break;
    case 1:
      if (!constmap_init(&maproutes,routes.s,routes.len,1)) temp_nomem(); break;
  }
  if (control_rldef(&outgoingip, "control/outgoingip", 0, "0.0.0.0") == -1)
    temp_control();
  if (!stralloc_0(&outgoingip)) temp_nomem();
  if (!ip_scan(outgoingip.s, &outip)) temp_noip();

#ifdef TLS
  if (control_readline(&tlscert, "control/remotecert") == -1)
    temp_control();
  if (!stralloc_0(&tlscert)) temp_nomem();
  if (control_rldef(&tlsciphers, "control/tlsremoteciphers", 0, "compat") == -1)
    temp_control();
  if (!stralloc_0(&tlsciphers)) temp_nomem();
  if (control_rldef(&tlsdheparams, "control/tlsdheparams", 0, "none") == -1)
    temp_control();
  if (!stralloc_0(&tlsdheparams)) temp_nomem();
#endif

}

int main(int argc, char **argv)
{
  static ipalloc ip = {0};
  unsigned int i, j;
  unsigned long randm;
  char **recips;
  int prefme;
  int flagallaliases;
  int flagalias;
  const char *relayhost;

  sig_pipeignore();
  if (argc < 4) perm_usage();
  if (chdir(auto_qmail) == -1) temp_chdir();
  getcontrols();
 
 
  if (!stralloc_copys(&host,argv[1])) temp_nomem();
  if (!stralloc_copys(&auth_login, "")) temp_nomem();
  if (!stralloc_copys(&auth_passwd, "")) temp_nomem();
 
  relayhost = 0;
  for (i = 0;i <= host.len;++i)
    if ((i == 0) || (i == host.len) || (host.s[i] == '.'))
      if ((relayhost = constmap(&maproutes,host.s + i,host.len - i)))
        break;
  if (relayhost && !*relayhost) relayhost = 0;
 
  if (relayhost) {
    j = str_chr(relayhost,' ');
    if (relayhost[j]) {
      i = str_chr(relayhost + j + 1,' ');
      if (relayhost[i]) {
	if (b64_ntops(relayhost + j + 1, i, &auth_login) == -1)
	  temp_nomem();
	if (b64_ntops(relayhost + j + i + 2, str_len(relayhost + j + i + 2),
	    &auth_passwd))
	  temp_nomem();
      }
    }
    i = str_chr(relayhost,':');
    if (relayhost[i])
      scan_ulong(relayhost + i + 1,&smtp_port);
    if (i > j) i = j;
    if (!stralloc_copyb(&host,relayhost, i)) temp_nomem();
  }


  addrmangle(&sender,argv[2],&flagalias);
 
  if (!saa_readyplus(&reciplist,0)) temp_nomem();
  if (ipme_init() != 1) temp_oserr();
 
  flagallaliases = 1;
  recips = argv + 3;
  while (*recips) {
    if (!saa_readyplus(&reciplist,1)) temp_nomem();
    reciplist.sa[reciplist.len] = sauninit;
    addrmangle(reciplist.sa + reciplist.len,*recips,&flagalias);
    if (!flagalias) flagallaliases = 0;
    ++reciplist.len;
    ++recips;
  }

 
  randm = now() + (getpid() << 16);
  switch (relayhost ? dns_ip(&ip,&host) : dns_mxip(&ip,&host,randm)) {
    case DNS_MEM: temp_nomem();
    case DNS_SOFT: temp_dns();
    case DNS_HARD: perm_dns();
    case 1:
      if (ip.len <= 0) temp_dns();
  }
 
  if (ip.len <= 0) perm_nomx();
 
  prefme = 100000;
  for (i = 0;i < ip.len;++i)
    if (ipme_is(&ip.ix[i].ip))
      if (ip.ix[i].pref < prefme)
        prefme = ip.ix[i].pref;
 
  if (relayhost) prefme = 300000;
  if (flagallaliases) prefme = 500000;
 
  for (i = 0;i < ip.len;++i)
    if (ip.ix[i].pref < prefme)
      break;
 
  if (i >= ip.len)
    perm_ambigmx();
 
  for (i = 0;i < ip.len;++i) if (ip.ix[i].pref < prefme) {
    if (tcpto(&ip.ix[i].ip)) continue;
 
    smtpfd = socket(AF_INET,SOCK_STREAM,0);
    if (smtpfd == -1) temp_oserr();

    if (qmtp_priority(ip.ix[i].pref)) {
      if (timeoutconn(smtpfd,&ip.ix[i].ip,&outip,(unsigned int) qmtp_port,timeoutconnect) == 0) {
	tcpto_err(&ip.ix[i].ip,0);
	partner = ip.ix[i].ip;
	qmtp(); /* does not return */
      }
      close(smtpfd);
      smtpfd = socket(AF_INET,SOCK_STREAM,0);
      if (smtpfd == -1) temp_oserr();
    }
    if (timeoutconn(smtpfd,&ip.ix[i].ip,&outip,(unsigned int) smtp_port,timeoutconnect) == 0) {
      tcpto_err(&ip.ix[i].ip,0);
      partner = ip.ix[i].ip;
      smtp(); /* should not return unless the start code or the HELO code
	         returns a temporary failure. */
    }
    tcpto_err(&ip.ix[i].ip,errno == error_timeout);
    close(smtpfd);
  }
  
  temp_noconn();
  /* NOTREACHED */
  return 0;
}
