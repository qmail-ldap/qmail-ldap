#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include "readwrite.h"
#include "sig.h"
#include "byte.h"
#include "case.h"
#include "datetime.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "newfield.h"
#include "open.h"
#include "seek.h"
#include "str.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "wait.h"

/* global vars */
stralloc warning={0};
stralloc to={0};
stralloc from={0};
stralloc host={0};
stralloc dtline={0};
stralloc ufline={0};
stralloc rpline={0};
stralloc temp={0};

char buf[1024];

void temp_nomem() { strerr_die1x(111,"Out of memory. (LDAP-ERR #5.5.0)"); }
void temp_qmail(fn) char *fn;
{ strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (LDAP-ERR #5.5.1)"); }
void temp_rewind() { strerr_die1x(111,"Unable to rewind message. (LDAP-ERR #5.5.2)"); }
void temp_slowlock()
{ strerr_die1x(111,"File has been locked for 30 seconds straight. (#4.3.0)"); }

void check_maildir(void);
void write_maildir(char* fn);
void check_mailfile(char* fn);
void write_mailfile(char* fn);

int main (int argc, char **argv) 
{
   char *s;
   char *fn;
   
   if (!env_init()) temp_nomem();
   
   if( !argv[1] || argv[2] ) 
      strerr_die3x(111,"Usage: ", argv[0], " mailbox (LDAP-ERR #5.0.1)");
   
   fn = argv[1];
   
   if (! (s = env_get("QMAILQUOTAWARNING") ) )
      strerr_die1x(111,"ARRG: QMAILQUOTAWARNING not present (LDAP-ERR #5.1.1)");
   if (!stralloc_copys(&warning,s)) temp_nomem();
   
   if (! (s = env_get("HOST") ) )
      strerr_die1x(111,"ARRG: HOST not present (LDAP-ERR #5.1.3)");  
   if (!stralloc_copys(&host,s)) temp_nomem();
   
   if ( fn[str_len(fn)-1] == '/' ) {
      write_maildir(fn);
   } else {
      check_mailfile(fn);
      write_mailfile(fn);
   }
   /* should never get here */
   return 7;
}


/* a match function */
static int wild_matchb(register char* pattern, register unsigned int pat_len, \
                       register char* string, unsigned int len)
{
   register unsigned int i;
   register unsigned int t;
   
   t = len-pat_len;
   for(i=0; i < t; i++) {
      if (!str_diffn( pattern, string+i, pat_len) )
         return 0;
   }
   return 1;
}


void check_maildir(void)
{
   char *(dirs[3]);
   DIR *folder;
   struct dirent *entry;
   int i;

   dirs[0]="new"; dirs[1]="cur"; dirs[2]="tmp";
   for (i=0; i<3; i++ ) {
      /* checking for old mail */
      if ( (folder = opendir(dirs[i])) == 0 )
         strerr_die1x(111,"Error while checking for QUOTA_WARNING file (LDAP-ERR #5.2.2)");
      while ((entry = readdir(folder)) != 0) {
         if (!str_diffn("QUOTA_WARNING", entry->d_name, str_len( "QUOTA_WARNING")))
            _exit(0);
      }
      closedir(folder);
   }

}

char fntmptph[30];
char fnnewtph[30];
void tryunlinktmp() { unlink(fntmptph); }
void sigalrm()
   { tryunlinktmp(); strerr_die1x(111,"Timeout on quota-warning delivery. (LDAP-ERR #5.2.9)"); }

void write_maildir(char* fn)
{
   char *s;
   char *t;
   int loop;
   struct stat st;
   int fd;
   datetime_sec starttime;
   substdio ssout;
 
   sig_alarmcatch(sigalrm);
   if (chdir(fn) == -1) {
      if (error_temp(errno)) 
         strerr_die1x(111,"Temporary error on qmail-warning delivery. (LDAP_ERR #5.2.8)");
      strerr_die1x(111,"Unable to chdir to maildir. (LDAP-ERR #5.2.1)");
   }
   
   check_maildir();
   
   /* set To: From: Delivered-to: Return-Path: UFLINE Date: Message-ID: */
   if (! (t = env_get("RECIPIENT") ) )
      strerr_die1x(111,"ARRG: RECIPIENT not present (LDAP-ERR #5.1.2)");
   if (!stralloc_copys(&to,"To: ")) temp_nomem();
   if (!stralloc_cats(&to,t)) temp_nomem();
   if (!stralloc_cats(&to,"\n")) temp_nomem();

   if (!stralloc_copys(&from,"From: Qmail-QUOTAGUARD <MAILER-DAEMON@")) temp_nomem();
   if (!stralloc_cat(&from,&host)) temp_nomem();
   if (!stralloc_cats(&from,">\n")) temp_nomem();

   if (! (t = env_get("DTLINE") ) )
      strerr_die1x(111,"ARRG: DTLINE not present (LDAP-ERR #5.1.4)");
   if (!stralloc_copys(&dtline,t)) temp_nomem();
   
   if (!stralloc_copys(&rpline,"Return-Path: <>\n")) temp_nomem();

   starttime = now();
   if (!newfield_datemake(starttime)) temp_nomem();
   if (!newfield_msgidmake(host.s,host.len,starttime)) temp_nomem();


   for (loop = 0;;++loop) {
      s = fntmptph;
      s += fmt_str(s,"tmp/");
      s += fmt_strn(s,"QUOTA_WARNING",sizeof("QUOTA_WARNING")); *s++ = 0;
      if (stat(fntmptph,&st) == -1) if (errno == error_noent) break;
      /* really should never get to this point */
      if (loop == 2) strerr_die1x(111,"Temporary error on qmail-warning delivery. (LDAP_ERR #5.2.8)");
      sleep(2);
   }
   str_copy(fnnewtph,fntmptph);
   byte_copy(fnnewtph,3,"new");

   alarm(86400);
   fd = open_excl(fntmptph);
   if (fd == -1) strerr_die1x(111,"Temporary error on qmail-warning delivery. (LDAP_ERR #5.2.8)");
   
   substdio_fdbuf(&ssout,write,fd,buf,sizeof(buf));
   if (substdio_put(&ssout,rpline.s,rpline.len) == -1) goto fail;
   if (substdio_put(&ssout,dtline.s,dtline.len) == -1) goto fail;
   /* Received: line */
   if (substdio_puts(&ssout,"Received: (directly through the qmail-quota-warning program);\n\t"))
      goto fail;
   if (substdio_puts(&ssout,myctime(starttime))) goto fail;
   /* message-id and date line */
   if (substdio_put(&ssout,newfield_msgid.s,newfield_msgid.len)) goto fail;   
   if (substdio_put(&ssout,newfield_date.s,newfield_date.len)) goto fail;
   /* To: From: and Subject: */
   if (substdio_put(&ssout,to.s,to.len)) goto fail;
   if (substdio_put(&ssout,from.s,from.len)) goto fail;
   if (substdio_puts(&ssout,"Subject: QUOTA-WARNING !\n")) goto fail;
   /* don't forget the single \n */
   if (substdio_puts(&ssout,"\n")) goto fail;
   /* the Warning */
   if (substdio_put(&ssout,warning.s,warning.len)) goto fail;
   if (warning.s[warning.len-1] == '\n')
      if (substdio_bputs(&ssout,"\n")) goto fail;


   if (substdio_flush(&ssout) == -1) goto fail;
   if (fsync(fd) == -1) goto fail;
   if (close(fd) == -1) goto fail; /* NFS dorks */

   if (link(fntmptph,fnnewtph) == -1) /* if error_exist unlink and exit(0), strange things can happen */
      if ( errno != error_exist) goto fail;
   tryunlinktmp(); _exit(0);

   fail:
      tryunlinktmp();
      strerr_die1x(111,"Temporary error on qmail-warning delivery. (LDAP_ERR #5.2.8)");
   
}

void check_mailfile(char* fn)
{
   int fd;
   int len;
   int match;
   substdio ss;
   
   fd = open_read(fn);
   if (seek_begin(fd) == -1) temp_rewind();
   
   substdio_fdbuf(&ss, read, fd, buf, sizeof(buf) );
   do {
      if( getln(&ss, &temp, &match, '\n') != 0 ) {
         strerr_warn3("Unable to read message: ",error_str(errno),". (LDAP-ERR #5.3.1)",0);
         break; /* something bad happend, but we ignore it :-( */
      }
      case_lowerb(temp.s, (len = byte_chr(temp.s,temp.len,':') ) );
      if( !str_diffn("qmail-quotawarning:", temp.s, len+1) ) {
         if (!wild_matchb(host.s, host.len, temp.s+len+1, temp.len-len-2) ) {
            /* quota warning allredy in mailbox */
            close(fd);
            _exit(0);
         }
      }
   } while (match);
   /* no quota warning found */
   close(fd);
   return;
}
   

void write_mailfile(char* fn)
{
   int fd;
   substdio ssout;
   int match;
   seek_pos pos;
   int flaglocked;
   char *t;
   datetime_sec starttime;

   /* set To: From: Delivered-to: Return-Path: UFLINE Date: Message-ID: */
   if (! (t = env_get("RECIPIENT") ) )
      strerr_die1x(111,"ARRG: RECIPIENT not present (LDAP-ERR #5.1.2)");
   if (!stralloc_copys(&to,"To: ")) temp_nomem();
   if (!stralloc_cats(&to,t)) temp_nomem();
   if (!stralloc_cats(&to,"\n")) temp_nomem();

   if (!stralloc_copys(&from,"From: Qmail-QUOTAGUARD <MAILER-DAEMON@")) temp_nomem();
   if (!stralloc_cat(&from,&host)) temp_nomem();
   if (!stralloc_cats(&from,">\n")) temp_nomem();

   if (! (t = env_get("DTLINE") ) )
      strerr_die1x(111,"ARRG: DTLINE not present (LDAP-ERR #5.1.4)");
   if (!stralloc_copys(&dtline,t)) temp_nomem();
   
   if (!stralloc_copys(&rpline,"Return-Path: <>\n")) temp_nomem();

   if (!stralloc_copys(&ufline,"From ")) temp_nomem();
   if (!stralloc_cats(&ufline,"MAILER-DAEMON")) temp_nomem();
   if (!stralloc_cats(&ufline," ")) temp_nomem();
   starttime = now();
   if (!stralloc_cats(&ufline,myctime(starttime))) temp_nomem();

   if (!newfield_datemake(starttime)) temp_nomem();
   if (!newfield_msgidmake(host.s,host.len,starttime)) temp_nomem();

   fd = open_append(fn);
   if (fd == -1)
      strerr_die5x(111,"Unable to open ",fn,": ",error_str(errno),". (LDAP-ERR #5.3.5)");

   sig_alarmcatch(temp_slowlock);
   alarm(30);
   flaglocked = (lock_ex(fd) != -1);
   alarm(0);
   sig_alarmdefault();

   seek_end(fd);
   pos = seek_cur(fd);

   substdio_fdbuf(&ssout,write,fd,buf,sizeof(buf));
   if (substdio_put(&ssout,ufline.s,ufline.len)) goto writeerrs;
   if (substdio_put(&ssout,rpline.s,rpline.len)) goto writeerrs;
   if (substdio_put(&ssout,dtline.s,dtline.len)) goto writeerrs;
   /* Received: line */
   if (substdio_puts(&ssout,"Received: (directly through the qmail-quota-warning program);\n\t"))
      goto writeerrs;
   if (substdio_puts(&ssout,myctime(starttime))) goto writeerrs;
   /* Qmail-QUOTAWARNING: line */
   if (substdio_puts(&ssout,"Qmail-QuotaWarning: ")) goto writeerrs;
   if (substdio_put(&ssout,host.s,host.len)) goto writeerrs;
   if (substdio_puts(&ssout,"\n")) goto writeerrs;
   /* message-id and date line */
   if (substdio_put(&ssout,newfield_msgid.s,newfield_msgid.len)) goto writeerrs;   
   if (substdio_put(&ssout,newfield_date.s,newfield_date.len)) goto writeerrs;
   /* To: From: and Subject: */
   if (substdio_put(&ssout,to.s,to.len)) goto writeerrs;
   if (substdio_put(&ssout,from.s,from.len)) goto writeerrs;
   if (substdio_puts(&ssout,"Subject: QUOTA-WARNING !\n")) goto writeerrs;
   /* don't forget the single \n */
   if (substdio_puts(&ssout,"\n")) goto writeerrs;
   /* the Warning */
   if (substdio_put(&ssout,warning.s,warning.len)) goto writeerrs;
   if (warning.s[warning.len-1] == '\n')
      if (substdio_bputs(&ssout,"\n")) goto writeerrs;
   if (substdio_bputs(&ssout,"\n")) goto writeerrs;
   if (substdio_flush(&ssout)) goto writeerrs;
   if (fsync(fd) == -1) goto writeerrs;
   close(fd);
   _exit(0);

   writeerrs:
   strerr_warn5("Unable to write ",fn,": ",error_str(errno),". (LDAP-ERR #5.3.6)",0);
   if (flaglocked) seek_trunc(fd,pos);
   close(fd);
   _exit(111);
}
