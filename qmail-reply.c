#include "auto_qmail.h"
#include "case.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "getln.h"
#include "qlx.h"
#include "readwrite.h"
#include "seek.h"
#include "sig.h"
#include "str.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"
#include "wait.h"
#include "byte.h"
#include "fd.h"
#include "qmail-ldap.h"

/* some error-handling funktions */
void temp_nomem() { strerr_die1x(111,"Out of memory. (LDAP-ERR #4.5.0)"); }
void temp_rewind() { strerr_die1x(111,"Unable to rewind message. (LDAP-ERR #4.5.0)"); }
void temp_childcrashed() { strerr_die1x(111,"Aack, child crashed. (LDAP-ERR #4.5.0)"); }
void temp_fork() { strerr_die3x(111,"Unable to fork: ",error_str(errno),". (LDAP-ERR #4.5.0)"); }
void temp_read() { strerr_die3x(111,"Unable to read message: ",error_str(errno),". (LDAP-ERR #4.5.0)"); }

/* function prototypes */
void get_env(stralloc *dtl, stralloc *to, stralloc *from, stralloc *replytext);
void check_header_and_get_subject(stralloc *subject);
void send_reply(stralloc *dtl, stralloc *to, stralloc *from, stralloc *subject, stralloc *replytext);

/* global vars */
char buf[1024];
char *(ignore[7]);

stralloc subj={0};
stralloc replytext={0};
stralloc to={0};
stralloc from={0};
stralloc dtline={0};
stralloc prog={0};

int main()
{

   ignore[0] = "root";
   ignore[1] = "-request@";
   ignore[2] = "daemon";
   ignore[3] = "postmaster";
   ignore[4] = "mailer-daemon";
   ignore[5] = "mailer";
   ignore[6] = 0;
   
   if (!env_init()) temp_nomem();
   
   get_env(&dtline, &to, &from, &replytext);
   
   check_header_and_get_subject(&subj);
      
   send_reply(&dtline, &to, &from, &subj, &replytext);
   
   return 0;
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

/* check and get the environment */
void get_env(stralloc *dtl, stralloc *to, stralloc *from, stralloc *replytext)
{
   char *s;
   unsigned int i;

   if ( s = env_get("DTLINE") ) {
      if (!stralloc_copys(dtl,s)) temp_nomem();
   } else {
      strerr_die1x(111,"DTLINE not present (LDAP-ERR #4.1.1)");
   }
   if ( s = env_get(ENV_REPLYTEXT) ) {
      if (!stralloc_copys(replytext,s)) temp_nomem();
   } else { /* paranoia */
      strerr_die2x(111,ENV_REPLYTEXT, " not present (LDAP-ERR #4.1.2)");
   }
   if ( s = env_get("SENDER") ) {
      if (!stralloc_copys(to,s)) temp_nomem();
      case_lowers(s);
      i=0;
      while ( ignore[i] ) {
         if (!wild_matchb(ignore[i], str_len( ignore[i] ), s, str_len(s) ) ) {
            exit(0);
         }
         i++;
      }
   } else { /* paranoia */
      strerr_die1x(111,"SENDER not present (LDAP-ERR #4.1.3)");
   }
   if ( s = env_get("RECIPIENT") ) {
      if (!stralloc_copys(from,s)) temp_nomem();
   } else { /* paranoia */
      strerr_die1x(111,"RECIPIENT not present (LDAP-ERR #4.1.4)");
   }
      
   
}


/* get the subject, for replymode */
void check_header_and_get_subject(stralloc *subject)
{
   substdio ss;
   int match;
   int len;
   int subj_set;
   stralloc temp = {0};
   stralloc line = {0};

   subj_set = 0;
   if (seek_begin(0) == -1) temp_rewind();
   substdio_fdbuf(&ss, read, 0, buf, sizeof(buf) );
   do {
      if( getln(&ss, &line, &match, '\n') != 0 ) {
         strerr_warn3("Unable to read message: ",error_str(errno),". (LDAP-ERR #4.3.0)",0);
         break; /* something bad happend, but we ignore it :-( */
      }
      if( !str_diffn("\n", line.s, 1) ) {
         if ( subj_set == 0 ) {
            if (!stralloc_copys(subject, "Re: Your mail")) temp_nomem();
         } 
         return;
      }
      case_lowerb(line.s, (len = byte_chr(line.s,line.len,':') ) );
      if( !str_diffn("subject:", line.s, len+1) ) {
         temp.s = line.s+len+1; /* cut away "subject:" without ' ' */
         temp.len = line.len-len-1; /* reducing lenght: amount lenght of "subject:" */
         if (temp.len > 1 ) { /* subject has to be more than 1 char (normaly a \n) */
            if (!stralloc_copys(subject, "Re:")) temp_nomem();
            if (!stralloc_cat(subject, &temp)) temp_nomem();
            temp.s = 0; temp.len = 0;
            subj_set=1;
         }
      }
      if( !str_diffn("mailing-list:", line.s, len+1) ) exit(0); /* don't send to mailing-lists */
      if( !str_diffn("precedence:", line.s, len+1) ) { /* exit if bulk, junk, list */
         temp.s = line.s+len+1;      /* cut away the header tag and the nasty \n ...  */
         temp.len = line.len-len-2;  /* by reducing lenght (quite a nasty hack ;-) ) */
         if ( wild_matchb("list", 4, temp.s, temp.len) ) {
            exit(0);
         }
         if ( wild_matchb("bulk", 4, temp.s, temp.len) ) {
            exit(0);
         }
         if ( wild_matchb("junk", 4, temp.s, temp.len) ) {
            exit(0);
         }
      }   
   } while (match);
   strerr_warn1("Premature end of header AARRG, giving up. (LDAP-ERR #4.5.0)");
   if ( subj_set == 0 ) {
      if (!stralloc_copys(subject, "Re: Your mail")) temp_nomem();
   } 
}

/* reply function */
void send_reply(stralloc *dtl, stralloc *to, stralloc *from, stralloc *subject, stralloc *replytext)
{
 char *(args[3]);
 int child;
 int pi[2];
 int wstat;
 
 if (!stralloc_copys(&prog, auto_qmail)) temp_nomem();
 if (!stralloc_cats(&prog, "/bin/datemail")) temp_nomem();
 if (!stralloc_0(&prog)) temp_nomem();
 
 if (pipe(pi) == -1) _exit(QLX_SYS);
 switch( child = fork() )
 {
  case -1:
    temp_fork();
  case 0:
    close(pi[1]);
    if(fd_move(0,pi[0]) == -1) _exit(QLX_SYS);
    args[0]=prog.s; args[1]="-t"; args[2]=0;
    sig_pipedefault();
    execv(*args,args);
    strerr_die5x(111,"Unable to run ",prog.s,": ",error_str(errno),". (LDAP-ERR #4.4.0)");
 }

 close(pi[0]);
 write(pi[1],dtl->s,dtl->len);
 write(pi[1],"Precedence: junk\n", 17); 
 write(pi[1],"To: ", 4);
 write(pi[1],to->s, to->len);
 write(pi[1], "\nFrom: ", 7);
 write(pi[1], from->s, from->len);
 write(pi[1], "\nSubject: ", 10);
 write(pi[1], subject->s, subject->len);
 write(pi[1], "\n", 1);
 write(pi[1],replytext->s,replytext->len);
 close(pi[1]);
 wait_pid(&wstat,child);
 if(wait_crashed(wstat))
    temp_childcrashed();
 switch(wait_exitcode(wstat))
 {
   case 100:
   case 64: case 65: case 70: case 76: case 77: case 78: case 112: _exit(100);
   case 0: break;
   default: _exit(111);
 }
   
}
