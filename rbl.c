#include "dns.h"
#include "env.h"
#include "ipalloc.h"
#include "qmail.h"
#include "rbl.h"
#include "stralloc.h"

static stralloc rblmessage = {0};
int rblprintheader;
char *rblonlyheader;
char *rblenabled;

extern void safeput();

void rblheader(struct qmail *qqt)
{
  if (!rblenabled) return;
  if (!rblprintheader) return;
  /* rblmessage is safe because it does not contain any remote info */
  if (rblmessage.s) qmail_put(qqt,rblmessage.s,rblmessage.len);
}

struct rbl {
  char *baseaddr;
  char *action;
  char *matchon;
  char *message;
} *rbl;

int numrbl;

static stralloc ip_reverse = {0};
static stralloc rbl_tmp = {0};

static void rbl_start(char *remoteip)
{
  unsigned int i;
  unsigned int j;
  char *ip_env;

  ip_env = remoteip;
  if (!ip_env) ip_env = "";

  if (!stralloc_copys(&ip_reverse,"")) die_nomem();

  i = str_len(ip_env);
  while (i) {
    for (j = i;j > 0;--j) if (ip_env[j - 1] == '.') break;
    if (!stralloc_catb(&ip_reverse,ip_env + j,i - j)) die_nomem();
    if (!stralloc_cats(&ip_reverse,".")) die_nomem();
    if (!j) break;
    i = j - 1;
  }
}

static char ipstr[IPFMT];

static int rbl_lookup(char *base, char *matchon)
{
  ipalloc rblsa = {0};
  int i;

  if (!*base) return 2;

  if (!stralloc_copy(&rbl_tmp,&ip_reverse)) die_nomem();
  if (!stralloc_cats(&rbl_tmp,base)) die_nomem();

  switch (dns_ip(&rblsa,&rbl_tmp)) {
    case DNS_MEM:
    case DNS_SOFT:
      return 2; /* soft error */
    case DNS_HARD:
      return 0; /* found no match */
    default: /* found match */
      if (!str_diff("any", matchon))
        return 1;
      for (i = 0;i < rblsa.len;++i)
      {
	ipstr[ip_fmt(ipstr,&rblsa.ix[0].ip)]=0;
	if (!str_diff(ipstr, matchon)) return 1;
      }
      return 0; /* found match but ignored */
  }
  return 1; /* should never get here */
}

void rbladdheader(char *base, char *matchon, char *message)
{
  /* all of base, matchon and message can be trusted because these
     are under our control */
  rblprintheader = 1;
  if(!stralloc_cats(&rblmessage, "X-RBL: (")) die_nomem();
  if(!stralloc_cats(&rblmessage, base)) die_nomem();
  if(!stralloc_cats(&rblmessage, ") ")) die_nomem();
  if (str_diff("any", matchon)) {
    if(!stralloc_cats(&rblmessage, "matches with ")) die_nomem();
    if(!stralloc_cats(&rblmessage, matchon)) die_nomem();
    if(!stralloc_cats(&rblmessage, " and ")) die_nomem();
  }
  if(!stralloc_cats(&rblmessage, "tells us ")) die_nomem();
  if(!stralloc_cats(&rblmessage, message)) die_nomem();
  if(!stralloc_cats(&rblmessage, "\n")) die_nomem();
}

int rblcheck(char *remoteip, char** rblname)
{
  int r=1;
  int i;

  if (!rblenabled) return 0;

  if(!stralloc_copys(&rblmessage, "")) die_nomem();
  rbl_start(remoteip);

  for (i=0; i < numrbl; i++) {
    logpid(2); logstring(2,"RBL check with '"); logstring(2,rbl[i].baseaddr); logstring(2,"':");

    r = rbl_lookup(rbl[i].baseaddr, rbl[i].matchon);
    if (r == 2) {
      logstring(2,"temporary DNS error, ignored."); logflush(2);
    } else if (r == 1) {
      logstring(2,"found match,");
      *rblname = rbl[i].message;
      if (rblonlyheader) {
	logstring(2,"only tagging header."); logflush(2);
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      }
      if (!str_diff("addheader", rbl[i].action)) {
	logstring(2,"would tag header."); logflush(2);
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      } else {
	/* default reject */
	logstring(2,"sender is rejected."); logflush(2);
	rblprintheader = 0;
	return 1;
      }
    }
    /* continue */
    logstring(2,"no match found, continue."); logflush(2);
  }
  return 0; /* either tagged, soft error or allowed */
}

stralloc rbldata = {0};

int rblinit(void)
{
  char** x;
  int on;
  int i;
  int j;
  int k;

  rblonlyheader = 0;
  rblenabled = 0;

  on = control_readfile(&rbldata,"control/rbllist",0);
  if (on == -1) return on;
  if (!on) return on;

  rblenabled = env_get("RBL");
  if (!rblenabled) return 0;

  for(i=0, numrbl=0; i < rbldata.len; ++i) {
    if (rbldata.s[i] == '\0') ++numrbl;
  }
  rbl = (struct rbl*)alloc(numrbl*sizeof(struct rbl));
  if (!rbl) return -1;

  x = (char **)&rbl[0]; x[0] = rbldata.s;
  for(i=0, j=0, k=0; i < rbldata.len; ++i) {
    if (rbldata.s[i] == '\t') {
      rbldata.s[i] = '\0';
      x[++j] = rbldata.s + i + 1;
    } else if (rbldata.s[i] == '\0')
    if (j == 3) {
      if (++k >= numrbl) break;
      x = (char**)&rbl[k];
      x[0] = rbldata.s + i + 1;
      j = 0;
    } else {
      logline(2,"parse error in rbllist");
      return -1;
    }
  }
  if (k != numrbl) {
    logline(2,"parse error in rbllist");
    return -1;
  }

  on = control_readint(&rblonlyheader,"control/rblonlyheader",0);
  if (on == -1) return on;
  rblonlyheader = env_get("RBLONLYHEADER");
  if (rblonlyheader) logline(2,"Note RBL match only in header, will not reject message");

  return 1;
}
