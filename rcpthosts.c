#include "cdb.h"
#include "byte.h"
#include "case.h"
#include "open.h"
#include "error.h"
#include "control.h"
#include "constmap.h"
#include "stralloc.h"
#include "rcpthosts.h"

static int flagrh = -1;
static stralloc rh = {0};
static struct constmap maprh;
static int fdmrh;
static stralloc locals = {0};
static struct constmap maplocals;

int rcpthosts_init(void)
{
  if (control_readfile(&locals,"control/locals",1) != 1) return -1;
  if (control_readfile(&rh,"control/rcpthosts",0) == -1) return -1;
  if (!constmap_init(&maplocals,locals.s,locals.len,0)) return -1;
  if (!constmap_init(&maprh,rh.s,rh.len,0)) return -1;
  fdmrh = open_read("control/morercpthosts.cdb");
  if (fdmrh == -1) if (errno != error_noent) return -1;
  flagrh = 0;
  return 0;
}

int addrlocals(char *buf, int len)
{
  int j;
 
   if (flagrh != 0) return 0;
  j = byte_rchr(buf,len,'@');
  if (j < len)
    if (constmap(&maplocals, buf + j + 1, len - j - 2))
      return 1;
  return 0;
}

static stralloc host = {0};

int rcpthosts(buf,len)
char *buf;
int len;
{
  int j;

  if (flagrh != 0) return 0;	/* uh-oh init failed so fail too,
				 * never be a open relay!
				 */

  j = byte_rchr(buf,len,'@');
  if (j >= len) return 1; /* presumably envnoathost is acceptable */

  ++j; buf += j; len -= j;

  if (!stralloc_copyb(&host,buf,len)) return -1;
  buf = host.s;
  case_lowerb(buf,len);

  /* first locals */
  if (constmap(&maplocals,buf,len)) return 1;
  
  /* then rcpthost */
  for (j = 0;j < len;++j)
    if (!j || (buf[j] == '.'))
      if (constmap(&maprh,buf + j,len - j)) return 1;

  /* finaly morercpthosts.cdb */
  if (fdmrh != -1) {
    uint32 dlen;
    int r;

    for (j = 0;j < len;++j)
      if (!j || (buf[j] == '.')) {
	r = cdb_seek(fdmrh,buf + j,len - j,&dlen);
	if (r) return r;
      }
  }

  return 0;
}
