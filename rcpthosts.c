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
static int fdlo;
static int fdrh;
static int fdmrh;
static stralloc locals = {0};
static struct constmap maplocals;

int rcpthosts_init(void)
{
  fdlo = open_read("control/locals.cdb");
  if (fdlo == -1) {
    if (errno != error_noent) return -1;
    if (control_readfile(&locals,"control/locals",1) != 1) return -1;
    if (!constmap_init(&maplocals,locals.s,locals.len,0)) return -1;
  }
  fdrh = open_read("control/rcpthosts.cdb");
  if (fdrh == -1) {
    if (errno != error_noent) return -1;

    if (control_readfile(&rh,"control/rcpthosts",0) == -1) return -1;
    if (!constmap_init(&maprh,rh.s,rh.len,0)) return -1;
    fdmrh = open_read("control/morercpthosts.cdb");
    if (fdmrh == -1) if (errno != error_noent) return -1;
  }
  flagrh = 1;
  return 0;
}

static stralloc host = {0};

int localhosts(char *buf, int len)
{
  int j;
  uint32 dlen;
 
  if (flagrh < 0) return 0;

  j = byte_rchr(buf,len,'@');
  if (j >= len) return 0; /* envnoathost is not acceptable */
  ++j; buf += j; len -= j;
  
  if (!stralloc_copyb(&host,buf,len)) return -1;
  buf = host.s;
  case_lowerb(buf,len);

  /* if local.cdb available use this as source */
  if (fdlo != -1) 
    return cdb_seek(fdlo, buf, len, &dlen);
  else   
    if (constmap(&maplocals, buf, len)) return 1;
  return 0;
}

int rcpthosts(buf,len)
char *buf;
int len;
{
  int j;
  int r;
  uint32 dlen;

  if (flagrh < 0) return 0;	/* uh-oh init failed so fail too,
				 * never be a open relay!
				 */

  j = byte_rchr(buf,len,'@');
  if (j >= len) return 1; /* presumably envnoathost is acceptable */

  ++j; buf += j; len -= j;

  if (!stralloc_copyb(&host,buf,len)) return -1;
  buf = host.s;
  case_lowerb(buf,len);

  /* first locals */
  /* if local.cdb available use this as source */
  if (fdlo != -1) {
    r = cdb_seek(fdlo, buf, len, &dlen);
    if (r) return r;
  } else   
    if (constmap(&maplocals,buf,len)) return 1;
  
  /* then rcpthosts */
  for (j = 0;j < len;++j)
    if (!j || (buf[j] == '.')) {
      /* if rcpthosts.cdb available use this as source */
      if (fdrh != -1) {
	r = cdb_seek(fdrh, buf + j, len - j, &dlen);
	if (r) return r;
      } else
	if (constmap(&maprh,buf + j,len - j)) return 1;
  }
  /* finaly morercpthosts.cdb but only if not rcpthosts.cdb avail */
  if (fdmrh != -1 && fdrh == -1) {
    for (j = 0;j < len;++j)
      if (!j || (buf[j] == '.')) {
	r = cdb_seek(fdmrh,buf + j,len - j,&dlen);
	if (r) return r;
      }
  }

  return 0;
}

