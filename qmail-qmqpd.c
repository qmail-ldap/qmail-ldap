#include "auto_qmail.h"
#include "byte.h"
#include "qmail.h"
#include "received.h"
#include "sig.h"
#include "subfd.h"
#include "substdio.h"
#include "readwrite.h"
#include "exit.h"
#include "now.h"
#include "fmt.h"
#include "env.h"
#include "str.h"
#ifdef QMQP_COMPRESS
#include <zlib.h>

z_stream stream;
char zbuf[4096];
int percent;
extern substdio ssout;

void out(const char *s1, const char *s2, const char *s3)
{
  char strnum[FMT_ULONG];
  unsigned long len;

  len = str_len(s1);
  if (s2) len += str_len(s2);
  if (s3) len += str_len(s3);
  substdio_put(&ssout,strnum,fmt_ulong(strnum,(unsigned long)len));
  substdio_puts(&ssout,":");
  substdio_puts(&ssout,s1);
  substdio_puts(subfderr,s1);
  if (s2) { substdio_puts(&ssout,s2); substdio_puts(subfderr,s2); }
  if (s3) { substdio_puts(&ssout,s3); substdio_puts(subfderr,s3); }
  substdio_puts(subfderr, "\n");
  substdio_puts(&ssout,",");
  substdio_flush(&ssout);
}
void compression_init(void)
{
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_in = 0;
  stream.next_in = zbuf;
  if (inflateInit(&stream) != Z_OK) {
    out("ZInitalizing data compression failed: ", stream.msg, " #(4.3.0)");
    _exit(111);
  }
}
void compression_done(void)
{
  if (stream.avail_out != sizeof(zbuf)) {
    /* there is some data left, ignore */
  }
  if (inflateEnd(&stream) != Z_OK) {
    out("ZFinishing data compression failed: ", stream.msg, " #(4.3.0)");
    _exit(111);
  }
  percent = 100 - (int)(100.0*stream.total_in/stream.total_out);
}
#endif

void resources() { _exit(111); }

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  r = write(fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}
int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef QMQP_COMPRESS
  static int done = -1;
  if (done == -1) {
    compression_init();
    done = 0;
  }
  if (done == 1) _exit(0);
  stream.avail_out = len;
  stream.next_out = buf;
  do {
    if (stream.avail_in == 0) {
      r = read(fd,zbuf,sizeof(zbuf));
      if (r <= 0) _exit(0); /* XXX ??? */
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
      compression_done();
      done = 1;
      return len - stream.avail_out;
    default:
      out("ZReceiving compressed data failed: ", stream.msg, " #(4.3.0)");
      return -1;
    }
    return len;
  } while (1);
#endif 
  r = read(fd,buf,len);
  if (r <= 0) _exit(0);
  return r;
}

char ssinbuf[512];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);
char ssoutbuf[256];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

unsigned long bytesleft = 100;

void getbyte(ch)
char *ch;
{
  if (!bytesleft--) _exit(100);
  substdio_get(&ssin,ch,1);
}

unsigned long getlen()
{
  unsigned long len = 0;
  char ch;

  for (;;) {
    getbyte(&ch);
    if (ch == ':') return len;
    if (len > 200000000) resources();
    len = 10 * len + (ch - '0');
  }
}

void getcomma()
{
  char ch;
  getbyte(&ch);
  if (ch != ',') _exit(100);
}

struct qmail qq;

void identify()
{
  char *remotehost;
  char *remoteinfo;
  char *remoteip;
  char *local;

  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
 
  received(&qq,"QMQP",local,remoteip,remotehost,remoteinfo,(char *) 0,(char *) 0,(char *) 0);
}

char buf[1000 + 20 + FMT_ULONG];
char strnum[FMT_ULONG];

int getbuf()
{
  unsigned long len;
  int i;

  len = getlen();
  if (len >= 1000) {
    for (i = 0;i < len;++i) getbyte(buf);
    getcomma();
    buf[0] = 0;
    return 0;
  }

  for (i = 0;i < len;++i) getbyte(buf + i);
  getcomma();
  buf[len] = 0;
  return byte_chr(buf,len,'\0') == len;
}

int flagok = 1;

main()
{
  char *result;
  unsigned long qp;
  unsigned long len;
  char ch;

  sig_pipeignore();
  sig_alarmcatch(resources);
  alarm(3600);

  bytesleft = getlen();

  len = getlen();

  if (chdir(auto_qmail) == -1) resources();
  if (qmail_open(&qq) == -1) resources();
  qp = qmail_qp(&qq);
  identify();

  while (len > 0) { /* XXX: could speed this up */
    getbyte(&ch);
    --len;
    qmail_put(&qq,&ch,1);
  }
  getcomma();

  if (getbuf())
    qmail_from(&qq,buf);
  else {
    qmail_from(&qq,"");
    qmail_fail(&qq);
    flagok = 0;
  }

  while (bytesleft)
    if (getbuf())
      qmail_to(&qq,buf);
    else {
      qmail_fail(&qq);
      flagok = 0;
    }

  bytesleft = 1;
  getcomma();

  result = qmail_close(&qq);

  if (!*result) {
    len = fmt_str(buf,"Kok ");
    len += fmt_ulong(buf + len,(unsigned long) now());
    len += fmt_str(buf + len," qp ");
    len += fmt_ulong(buf + len,qp);
#ifdef QMQP_COMPRESS
    len += fmt_str(buf + len, " ddc saved ");
    if (percent < 0) {
      len += fmt_str(buf + len, "-");
      percent *= -1;
    }
    len += fmt_ulong(buf + len, percent);
    len += fmt_str(buf + len, " percent");
#endif
    buf[len] = 0;
    result = buf;
  }

  if (!flagok)
    result = "Dsorry, I can't accept addresses like that (#5.1.3)";

  substdio_put(&ssout,strnum,fmt_ulong(strnum,(unsigned long) str_len(result)));
  substdio_puts(&ssout,":");
  substdio_puts(&ssout,result);
  substdio_puts(subfderr,result + 1);
  substdio_puts(subfderr, "\n");
  substdio_puts(&ssout,",");
  substdio_flush(&ssout);
  _exit(0);
}
