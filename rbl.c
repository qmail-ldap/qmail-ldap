#include "alloc.h"
#include "control.h"
#include "dns.h"
#include "env.h"
#include "ipalloc.h"
#include "qmail.h"
#include "str.h"
#include "stralloc.h"

#include "rbl.h"

static stralloc rblmessage = {0};
int rblprintheader;
char *rblonlyheader;
char *rblenabled;

/* functions borrowed from qmail-smtpd.c */
extern void safeput();
extern void die_nomem();

extern void logpid();
extern void logline();
extern void logstring();
extern void logflush();

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

static int rbl_start(char *remoteip)
{
  unsigned int i;
  unsigned int j;
  char *ip_env;

  ip_env = remoteip;
  if (!ip_env) ip_env = "";

  if (!stralloc_copys(&ip_reverse,"")) die_nomem();

  i = str_len(ip_env);
  while (i) {
    for (j = i;j > 0;--j) {
      if (ip_env[j - 1] == '.') break;
      if (ip_env[j - 1] == ':') return 0; /* no IPv6 */
    }
    if (!stralloc_catb(&ip_reverse,ip_env + j,i - j)) die_nomem();
    if (!stralloc_cats(&ip_reverse,".")) die_nomem();
    if (!j) break;
    i = j - 1;
  }
  return 1;
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
	ipstr[ip_fmt(ipstr,&rblsa.ix[i].ip)]=0;
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
  if(!rbl_start(remoteip)) return 0;

  for (i=0; i < numrbl; i++) {
    logpid(2); logstring(2,"RBL check with '");
    logstring(2,rbl[i].baseaddr); logstring(2,"': ");

    r = rbl_lookup(rbl[i].baseaddr, rbl[i].matchon);
    if (r == 2) {
      logstring(2,"temporary DNS error, ignored"); logflush(2);
    } else if (r == 1) {
      logstring(2,"found match, ");
      *rblname = rbl[i].message;
      if (rblonlyheader) {
	logstring(2,"tag header"); logflush(2);
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      }
      if (!str_diff("addheader", rbl[i].action)) {
	logstring(2,"tag header"); logflush(2);
	rbladdheader(rbl[i].baseaddr, rbl[i].matchon, rbl[i].message);
	continue;
      } else {
	/* default reject */
	logstring(2,"reject sender"); logflush(2);
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
  int n;

  rblonlyheader = 0;
  rblenabled = 0;

  rblenabled = env_get("RBL");
  if (!rblenabled) return 0;

  on = control_readfile(&rbldata,"control/rbllist",0);
  if (on == -1) return on;
  if (!on) return on;

  for(i=0, numrbl=0; i < rbldata.len; ++i)
    if (rbldata.s[i] == '\0')
	++numrbl;

  rbl = (struct rbl*)alloc(numrbl*sizeof(struct rbl));
  if (!rbl) return -1;

  /* line format is "basedomain action matchon message"
     message may have spaces */
  x = (char **)&rbl[0];
  for (i=0, j=0, k=0, n=0; i < rbldata.len; ++i) {
    while (1) {
      /* hop over spaces */
      if (rbldata.s[i] != ' ' && rbldata.s[i] != '\t') break;
      if (rbldata.s[i] == '\0') {
	logline(1, "parse error in rbllist, unexpected end of line");
	return -1;
      }
      i++;
    }
    j = i;
    if (n == 3) {
      /* message */
      x[n] = rbldata.s + j;
      n = 0;
      x = (char **)&rbl[++k];
      while (rbldata.s[i] != '\0') i++;
    } else {
      while (1) {
        /* hop over argument */
        if (rbldata.s[i] == ' ' || rbldata.s[i] == '\t') break;
        if (rbldata.s[i] == '\0') {
	  logline(1, "parse error in rbllist, unexpected end of line");
	  return -1;
        }
        i++;
      }
      rbldata.s[i] = '\0';
      x[n++] = rbldata.s + j;
    }
  }
  if (k != numrbl) {
    logline(1,"parse error in rbllist, unexpected end of file");
    return -1;
  }

  on = control_readint(&rblonlyheader,"control/rblonlyheader",0);
  if (on == -1) return on;
  rblonlyheader = env_get("RBLONLYHEADER");

  return 1;
}

