#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include "auto_qmail.h"
#include "case.h"
#include "cdbmss.h"
#include "exit.h"
#include "getln.h"
#include "open.h"
#include "readwrite.h"
#include "stralloc.h"
#include "strerr.h"
#include "substdio.h"

#define FATAL "qmail-cdb: fatal: "

void die_read(void)
{
  strerr_die2sys(111,FATAL,"unable to read from stdin: ");
}
void die_write(const char *f)
{
  strerr_die4sys(111,FATAL,"unable to write to ", f, ": ");
}

char inbuf[1024];
substdio ssin;

int fd;
int fdtemp;

struct cdbmss cdbmss;
stralloc line = {0};
int match;

int main(int argc, char **argv)
{
  umask(033);

  if (argc != 3)
    strerr_die1sys(111,"qmail-cdb: usage: qmail-cdb rules.cdb rules.tmp");

  substdio_fdbuf(&ssin,subread,0,inbuf,sizeof inbuf);

  fdtemp = open_trunc(argv[2]);
  if (fdtemp == -1) die_write(argv[2]);

  if (cdbmss_start(&cdbmss,fdtemp) == -1) die_write(argv[2]);

  for (;;) {
    if (getln(&ssin,&line,&match,'\n') != 0) die_read();
    case_lowerb(line.s,line.len);
    while (line.len) {
      if (line.s[line.len - 1] == ' ') { --line.len; continue; }
      if (line.s[line.len - 1] == '\n') { --line.len; continue; }
      if (line.s[line.len - 1] == '\t') { --line.len; continue; }
      if (line.s[0] != '#')
	if (cdbmss_add(&cdbmss,line.s,line.len,"",0) == -1)
	  die_write(argv[2]);
      break;
    }
    if (!match) break;
  }

  if (cdbmss_finish(&cdbmss) == -1) die_write(argv[2]);
  if (fsync(fdtemp) == -1) die_write(argv[2]);
  if (close(fdtemp) == -1) die_write(argv[2]); /* NFS stupidity */
  if (rename(argv[2],argv[1]) == -1)
    strerr_die5sys(111, FATAL, "unable to move ", argv[2], " to ", argv[1]);

  return 0;
}
