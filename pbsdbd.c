#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "alloc.h"
#include "auto_qmail.h"
#include "byte.h"
#include "control.h"
#include "ip.h"
#include "ndelay.h"
#include "now.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"
#include "uint32.h"

#include <stdio.h>

struct ip_address ip;
unsigned int port = 2821;
stralloc addr = {0};
stralloc secret = {0};
int timeout = 600; /* 10 Min */

unsigned long cachesize = 1048576; /* 1 MB */
unsigned char *cache;
unsigned long hashsize;
unsigned int hashbits;
unsigned long writer;
unsigned long oldest;
unsigned long unused;


static unsigned char buf[512];
static int len;

#define fatal "pbsdbd: fatal: "
#define warning "pbsdbd: warning: "
#define info "pbsdbd: info: "

static void die_control(void) { strerr_die2x(111, fatal, "unable to read controls"); }
static void die_nomem(void) { strerr_die2x(111, fatal, "out of memory"); }

static void init(void)
{
  int l;
  
  if (chdir(auto_qmail) == -1) die_control();
  
  if (control_rldef(&addr,"control/pbsip",0, "0.0.0.0") == -1) die_control();
  if (!stralloc_0(&addr)) die_nomem();

  l = ip_scan(addr.s, &ip);
  if ( l == 0 && l > 15 ) die_control();
  
  if (control_rldef(&secret,"control/pbssecret",0, 0) != 1) die_control();

  if (control_readint(&port,"control/pbsport") == -1) die_control();
  if (port > 65000) die_control();

  /* if a luser sets bad values it's his fault */
  if (control_readint(&cachesize,"control/pbscachesize") == -1) die_control();
  if (control_readint(&timeout,"control/pbstimeout") == -1) die_control();

  cache = alloc(cachesize);
  if (!cache) die_nomem();
  
  hashsize = 4;
  while (hashsize <= (cachesize >> 5)) hashsize <<= 1;
  
  writer = hashsize;
  oldest = cachesize;
  unused = cachesize;

}

static int socket_bind(int s)
{
  int opt = 1;
  struct sockaddr_in sin;
  char *x;
  
  setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof opt);
  
  byte_zero(&sin,sizeof(sin));
  byte_copy(&sin.sin_addr,4,&ip);
  x = (char *) &sin.sin_port;
  x[1] = port; port >>= 8; x[0] = port;
  sin.sin_family = AF_INET;
  
  return bind(s,(struct sockaddr *) &sin,sizeof sin);
}

static void cache_impossible(void)
{
  strerr_die2x(111, fatal, "cache corrupted");
}

static void set4(unsigned long pos,uint32 u)
{
  unsigned char *s;
  
  if (pos > cachesize - 4) cache_impossible();
  
  s = cache + pos;
  s[3] = u & 255;
  u >>= 8;
  s[2] = u & 255;
  u >>= 8;
  s[1] = u & 255;
  s[0] = u >> 8;  
}

static uint32 get4(unsigned long pos)
{
  unsigned char *s;
  uint32 result;  
  
  if (pos > cachesize - 4) cache_impossible();
  s = cache + pos;
  result = s[0];
  result <<= 8;
  result += s[1];
  result <<= 8;
  result += s[2];
  result <<= 8;
  result += s[3];
   
  return result;
}

unsigned long hash(const unsigned char *key,unsigned int keylen)
{
  unsigned long result = 5381;

  while (keylen) {
    result = (result << 5) + result;
    result ^= *key;
    ++key;
    --keylen;
  }
  result <<= 2;
  result &= hashsize - 4;
  printf("hash: result %li %#lx hashsize %li %#lx\n", 
      result, result, hashsize, hashsize);
  return result;
}

/* to be stored: 4-byte link, 4-byte timestamp, 1-byte size and size-byte Address */
/* see also dnscache */
void setaddr(const unsigned char *key,unsigned int keylen, unsigned long timenow)
{
  unsigned int entrylen;
  unsigned int keyhash;
  unsigned long pos;

  printf("setaddr:\ttimeout %lu, keylen %i, key %#lx\n", timenow, keylen, *(unsigned long*)key);

  if (!cache) return;
  if ( keylen > 255 ) return;
  
  entrylen = 9 + keylen;
  
  while (writer + entrylen > oldest) {
    if (oldest == unused) {
      if (writer <= hashsize) return;
      unused = writer;
      oldest = hashsize;
      writer = hashsize;
    }

    pos = get4(oldest);
    set4(pos,get4(pos) ^ oldest);
  
    if (oldest + 9 > cachesize ) cache_impossible();
    oldest += 9 + *(cache + oldest + 8);
    if (oldest > unused) cache_impossible();
    if (oldest == unused) {
      unused = cachesize;
      oldest = cachesize;
    }
  }

  keyhash = hash(key,keylen);

  pos = get4(keyhash);
  if (pos)
    set4(pos,get4(pos) ^ keyhash ^ writer);
  set4(writer,pos ^ keyhash);
  set4(writer + 4,timenow + timeout);
  if (writer + 9 > cachesize ) cache_impossible();
  *(cache + writer + 8) = keylen;
  byte_copy(cache + writer + 9,keylen,key);

  set4(keyhash,writer);

  printf("setaddr: writer %li: %#lx %#lx %i %#lx\n", writer, 
      get4(writer), get4(writer + 4), *(cache + writer + 8), get4(writer + 9) );

  writer += entrylen;
}

int checkaddr(const unsigned char *key,unsigned int keylen,unsigned long timenow)
{
  unsigned long pos;
  unsigned long prevpos;
  unsigned long nextpos;
  unsigned long u;
  unsigned int loop;

  printf("checkaddr:\ttimeout %lu, keylen %i, key %#lx\n", timenow, keylen, *(unsigned long*)key);

  if (!cache) return 0;

  prevpos = hash(key,keylen);
  pos = get4(prevpos);
  loop = 0;

  while (pos) {
    if (pos + 9 > cachesize ) cache_impossible();
    if (*(cache + pos + 8) == keylen) {
      if (pos + 9 + keylen > cachesize) cache_impossible();
      if (byte_equal(key,keylen,cache + pos + 9)) {
        u = get4(pos + 4);
	if (u < timenow) {
	  strerr_warn2(info, "cache hit but timed out", 0);
	  return 0;
        }
	return 1;
      }
    }
    nextpos = prevpos ^ get4(pos);
    prevpos = pos;
    pos = nextpos;
    if (++loop > 100) {
      strerr_warn2(warning, "hash flooding", 0);
      return 0; /* to protect against hash flooding */
    }
  }

  strerr_warn2(info, "not in cache", 0);
  return 0;
}


static int doit(void)
{
  unsigned char *sec;
  unsigned int sec_len;
  unsigned long timenow;

  if ( buf[1] + 2 >= len ) {
    strerr_warn2(warning, "bad packet", 0);
    return 0;
  }
    
  timenow = now();
  
  switch(buf[0]) {
    case 'Q':
      strerr_warn2(info, "query packet", 0);
      if ( checkaddr(&buf[2], buf[1], timenow) ) {
	*(buf + 2 + buf[1]) = 'R';
      } else {
	*(buf + 2 + buf[1]) = 'N';
      }
      buf[0] = 'R';
      return 1;
    case 'A':
      strerr_warn2(info, "add packet", 0);
      sec_len = *(buf + 2 + buf[1]);
      sec = buf + 2 + buf[1] + 1;
      if ( buf + len < sec + sec_len ) {
	strerr_warn2(warning, "bad packet", 0);
	return 0;
      }
      if ( secret.len != sec_len || byte_diff(secret.s, sec_len, sec) ) {
	strerr_warn2(warning, "no authorized add packet", 0);
	return 0;
      }
      setaddr(&buf[2], buf[1], timenow);
      return 0;
    case 'R':
      strerr_warn2(warning, "response recived", 0);
      return 0;
    default:
      strerr_warn2(warning, "bad packet", 0);
      return 0;
  }
}

int main(int argc, char** argv)
{
  struct sockaddr_in sa;
  int dummy;
  int udp;

  init();

  udp = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp == -1)
    strerr_die2sys(111,fatal,"unable to create UDP socket: ");
  if (socket_bind(udp) == -1)
    strerr_die2sys(111,fatal,"unable to bind UDP socket: ");
  
  ndelay_off(udp);

  for (;;) {
    dummy = sizeof(sa);
    len = recvfrom(udp, buf, sizeof(buf), 0, (struct sockaddr*) &sa, &dummy);
    if (len < 0) continue;
    if (!doit()) continue;
    sendto(udp, buf, len, 0, (struct sockaddr*) &sa, sizeof(sa));
    /* may block for buffer space; if it fails, too bad */
  }
}