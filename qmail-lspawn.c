#include "fd.h"
#include "wait.h"
#include "prot.h"
#include "substdio.h"
#include "stralloc.h"
#include "scan.h"
#include "exit.h"
#include "fork.h"
#include "error.h"
#include "cdb.h"
#include "case.h"
#include "slurpclose.h"
#include "auto_qmail.h"
#include "auto_uids.h"
#include "qlx.h"

#include "qmail-ldap.h"
#include "qldap-ldaplib.h"
#include "qldap-errno.h"
#include "qldap-debug.h"
#include "alloc.h"
#include "env.h"
#include "fmt.h"
#include "check.h"
#include "sig.h"
#include "auto_usera.h"
#include "auto_uids.h"
#include <pwd.h>
#include <sys/types.h>

char *aliasempty;

/* initialize the string arrays, this uses DJB's libs */
extern stralloc qldap_me;
stralloc    qldap_defdotmode = {0};
stralloc    qldap_defaultquota = {0};
stralloc    qldap_quotawarning = {0};
stralloc    qldap_dirmaker = {0};
int         qldap_localdelivery;
int         qldap_cluster;

stralloc    foo = {0};

/* init done */

#ifdef QLDAP_CLUSTER
static int allwrite(op,fd,buf,len)
register int (*op)();
register int fd;
register char *buf;
register int len;
{
  register int w;

  while (len) {
    w = op(fd,buf,len);
    if (w == -1) {
      if (errno == error_intr) continue;
      return -1; /* note that some data may have been written */
    }
    if (w == 0) ; /* luser's fault */
    buf += w;
    len -= w;
  }
  return 0;
}

/* declaration of the mail forwarder function */
void forward_mail(char *host, stralloc *to, char *from, int fdmess);
#endif

/* this is a simple wrapper for the signal handler */
void get_qldap_controls()
{
   if ( init_ldap( &qldap_localdelivery, &qldap_cluster, 0, &qldap_dirmaker,
                   &qldap_defdotmode, &qldap_defaultquota, &qldap_quotawarning ) == -1 ) 
      _exit(1);
   
   if ( qldap_dirmaker.len != 0 ) {
      if ( !env_put2(ENV_HOMEDIRMAKE, qldap_dirmaker.s )) _exit(QLX_NOMEM);
   } else {
      if ( !env_unset(ENV_HOMEDIRMAKE) ) _exit(QLX_NOMEM);
   }
   
   if ( qldap_quotawarning.len != 0 ) {
      if ( !env_put2(ENV_QUOTAWARNING, qldap_quotawarning.s )) _exit(QLX_NOMEM);
   } else {
      if ( !env_unset(ENV_QUOTAWARNING) ) _exit(QLX_NOMEM);
   }
}

/* here it is not possible to log something */
void initialize(argc,argv)
int argc;
char **argv;
{
   aliasempty = argv[1];
   if (!aliasempty) {
      _exit(100);
   }
   
   /* read the control files */
   get_qldap_controls();
   sig_hangupcatch(get_qldap_controls);
   sig_hangupunblock();
}

int truncreport = 3000;

void report(ss,wstat,s,len)
substdio *ss;
int wstat;
char *s;
int len;
{
#ifdef DEBUG
#define REPORT_RETURN for (i = 0;i < len;++i) if (!s[i]) break; substdio_put(ss,s,i); return
#else
#define REPORT_RETURN return
#endif
 int i;
   if (wait_crashed(wstat)) {
      substdio_puts(ss,"Zqmail-local crashed.\n");
      REPORT_RETURN;
   }
   switch(wait_exitcode(wstat)) {
   case QLX_CDB:
         substdio_puts(ss,"ZTrouble reading users/cdb in qmail-lspawn.\n");
      REPORT_RETURN;
      
   case QLX_NOMEM:
         substdio_puts(ss,"ZOut of memory in qmail-lspawn.\n");
      REPORT_RETURN;
      
   case QLX_SYS:
         substdio_puts(ss,"ZTemporary failure in qmail-lspawn.\n");
      REPORT_RETURN;
      
   case QLX_NOALIAS:
         substdio_puts(ss,"ZUnable to find alias user!\n");
      REPORT_RETURN;
      
   case QLX_ROOT:
         substdio_puts(ss,"ZNot allowed to perform deliveries as root.\n");
      REPORT_RETURN;
      
   case QLX_USAGE:
         substdio_puts(ss,"ZInternal qmail-lspawn bug.\n");
      REPORT_RETURN;

   case QLX_NFS:
         substdio_puts(ss,"ZNFS failure in qmail-local.\n");
      REPORT_RETURN;
      
   case QLX_EXECHARD:
         substdio_puts(ss,"DUnable to run qmail-local.\n");
      REPORT_RETURN;
      
   case QLX_EXECSOFT:
         substdio_puts(ss,"ZUnable to run qmail-local.\n");
      REPORT_RETURN;
      
   case QLX_EXECPW:
         substdio_puts(ss,"ZUnable to run qmail-getpw.\n");
      REPORT_RETURN;
      
   case 111: case 71: case 74: case 75:
         substdio_put(ss,"Z",1);
      break;
      
   case 0:
         substdio_put(ss,"K",1);
      break;
      
   /* report LDAP errors */
   case 198:
         substdio_puts(ss, "DInternal qmail-ldap-lspawn bug. (LDAP-ERR #198)\n");
      REPORT_RETURN;

   case 199:
         substdio_puts(ss, "DMissing ~control/ldapserver. (LDAP-ERR #199)\n");
      REPORT_RETURN;

   case 200:
         substdio_puts(ss, "DReceipient email address is not a valid email address. (LDAP-ERR #200)\n");
      REPORT_RETURN;

   case 201:
         substdio_puts(ss, "ZUnable to initialize LDAP connection (bad server address or server down?) (LDAP-ERR #201).\n");
      REPORT_RETURN;
      
   case 202:
         substdio_puts(ss, "ZInternal error in ldap_set_option. (LDAP-ERR #202)\n");
      REPORT_RETURN;

   case 203:
         substdio_puts(ss, "ZUnable to login into LDAP server (bad username/password?). (LDAP-ERR #203)\n");
      REPORT_RETURN;

   case 204:
         substdio_puts(ss, "ZInternal error in ldap_search_ext_s. (LDAP-ERR #204)\n");
      REPORT_RETURN;

   case 210:
         substdio_puts(ss, "DLDAP attribute qmailUser contains illegal characters. (LDAP-ERR #210)\n");
      REPORT_RETURN;

   case 211:
         substdio_puts(ss, "DLDAP attribute qmailUID is too high/low or not numeric. (LDAP-ERR #211)\n");
      REPORT_RETURN;

   case 212:
         substdio_puts(ss, "DLDAP attribute qmailGID is too high/low or not numeric. (LDAP-ERR #212)\n");
      REPORT_RETURN;

   case 213:
         substdio_puts(ss, "DLDAP attribute mailMessageStore contains illegal characters. (LDAP-ERR #213)\n");
      REPORT_RETURN;

   case 214:
         substdio_puts(ss, "DLDAP attribute mailMessageStore with ~control/ldapmessagestore contains illegal characters. (LDAP-ERR #214)\n");
      REPORT_RETURN;

   case 215:
         substdio_puts(ss, "DLDAP attribute mailMessageStore is not given but mandatory. (LDAP-ERR #215)\n");
      REPORT_RETURN;

   case 220:
         substdio_puts(ss, "DLDAP attribute mailForwardingAddress contains illegal characters. (LDAP-ERR #220)\n");
      REPORT_RETURN;

   case 221:
         substdio_puts(ss, "DLDAP attribute deliveryProgramPath contains illegal characters. (LDAP-ERR #221)\n");
      REPORT_RETURN;

   case 222:
         substdio_puts(ss, "DError while reading ~control files. (LDAP-ERR #222)\n");
      REPORT_RETURN;

   case 225:
         substdio_puts(ss, "DMailaddress is administrativley disabled. (LDAP-ERR #220)\n");
      REPORT_RETURN;

   case 230:
         substdio_puts(ss, "ZConfiguration file ~control/ldapusername is missing/empty and LDAP qmailUser is not given. (LDAP-ERR #230)\n");
      REPORT_RETURN;

   case 231:
         substdio_puts(ss, "DConfiguration file ~control/ldapusername contains illegal characters. (LDAP-ERR #231)\n");
      REPORT_RETURN;

   case 232:
         substdio_puts(ss, "ZConfiguration file ~control/ldapuid is missing/empty and LDAP qmailUID is not given. (LDAP-ERR #232)\n");
      REPORT_RETURN;

   case 233:
         substdio_puts(ss, "DConfiguration file ~control/ldapuid is too high/low or not numeric. (LDAP-ERR #233)\n");
      REPORT_RETURN;

   case 234:
         substdio_puts(ss, "ZConfiguration file ~control/ldapgid is missing/empty and LDAP qmailGID is not given. (LDAP-ERR #234)\n");
      REPORT_RETURN;

   case 235:
         substdio_puts(ss, "DConfiguration file ~control/ldapgid is too high/low or not numeric. (LDAP-ERR #235)\n");
      REPORT_RETURN;

   case 236:
         substdio_puts(ss, "ZConfiguration file ~control/ldapmessagestore does not begin with an / or is emtpy. (LDAP-ERR #236)\n");
      REPORT_RETURN;

   case 237:
         substdio_puts(ss, "ZConfiguration file ~control/ldapmessagestore does not end with an / or is empty. (LDAP-ERR #237)\n");
      REPORT_RETURN;
      
   case 238:
         substdio_puts(ss, "ZAACK: qmail-qmqpc (as mail forwarder) crashed (LDAP-ERR #238)\n");
      REPORT_RETURN;

#ifdef QLDAP_CLUSTER
   case 239:
         substdio_puts(ss, "ZTemporary error in qmail-qmqpc (as mail forwarder) (LDAP-ERR #239)\n");
      REPORT_RETURN;
      
   case 240:
         substdio_puts(ss, "DPermanet error in qmail-qmqpc (as mail forwarder) (LDAP-ERR #240)\n");
      REPORT_RETURN;
#endif /* QLDAP_CLUSTER */
/* end -- report LDAP errors */

   case 100:
   default:
         substdio_put(ss,"D",1);
      break;
  }

   for (i = 0;i < len;++i)
      if (!s[i])
         break;
   
   substdio_put(ss,s,i);
}


stralloc nughde = {0};

/* LDAP server query routines */

int qldap_get( stralloc *mail, char *from, int fdmess)
{
   userinfo   info;
   extrainfo  extra[7];
   searchinfo search;
   char *attrs[] = {  /* LDAP_MAIL, */ /* not needed, we search for those values */
                      /* LDAP_MAILALTERNATE, */
                      LDAP_UID, /* the first 5 attrs are the default ones */
                      LDAP_QMAILUID,
                      LDAP_QMAILGID,
                      LDAP_ISACTIVE,
                      LDAP_MAILHOST,
                      LDAP_MAILSTORE,
                      LDAP_QUOTA, /* the last 6 are extra infos */
                      LDAP_FORWARDS,
                      LDAP_PROGRAM,
                      LDAP_MODE,
                      LDAP_REPLYTEXT,
                      LDAP_DOTMODE, 0 };
   int  ret;
   int  reply;
   int  at;
   int  i;
   char *r;
   stralloc filter = {0};
   unsigned long tid;

   /* check the mailaddress for illegal characters       *
    * escape '*', ,'\', '(' and ')' with a preceding '\' */
   /* XXX: also '\0' should be escaped but this is not done. */
   if (!escape_forldap(mail)) _exit(QLX_NOMEM);

   /* build the search string for the email address */
   if (!stralloc_copys(&filter,"(|(mail=" ) ) _exit(QLX_NOMEM);
   if (!stralloc_cat(&filter,mail)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,")(mailalternateaddress=")) _exit(QLX_NOMEM);
   if (!stralloc_cat(&filter,mail)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,"))")) _exit(QLX_NOMEM);
   if (!stralloc_0(&filter)) _exit(QLX_NOMEM);
   
   debug(16, "ldapfilter: '%s'\n", filter.s);
   search.filter = filter.s;
   search.bindpw = 0;    /* rebind off */

   /* initalize the different objects */
   extra[0].what = LDAP_QUOTA;
   extra[1].what = LDAP_FORWARDS;
   extra[2].what = LDAP_PROGRAM;
   extra[3].what = LDAP_MODE;
   extra[4].what = LDAP_REPLYTEXT;
   extra[5].what = LDAP_DOTMODE;
   extra[6].what = 0;

   /* do the search for the email address */
   ret = ldap_lookup(&search, attrs, &info, extra);
   if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
   if ( ret != 0 && qldap_errno == LDAP_NOSUCH ) {
      /* this handles the "catch all" extension */
      at = 0;
      r = mail->s;
      i = mail->len;
      for (at = i - 1; r[at] != '@' && at >= 0 ; at--) ; /* handels also mailwith 2 @ */
      /* build the search string for the email address */
      if (!stralloc_copys(&filter,"(|(mail=" ) ) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) _exit(QLX_NOMEM);
      if (!stralloc_catb(&filter,r+at, i-at)) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,")(mailalternateaddress=")) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) _exit(QLX_NOMEM);
      if (!stralloc_catb(&filter,r+at, i-at)) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,"))")) _exit(QLX_NOMEM);
      if (!stralloc_0(&filter)) _exit(QLX_NOMEM);
      
      debug(16, "retry with filter '%s'\n", filter.s);
      /* do the search for the email address */
      ret = ldap_lookup(&search, attrs, &info, extra);
      if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
      /* count the results, we must have exactly one */
   }
   if ( ret != 0 ) {
      return 1;
   }

   /* go through the attributes and set the proper args for qmail-local  *
    * this can probably done with some sort of loop, but hey, how cares? */
   debug(32, "found: user='%s', uid=%s, gid=%s, mms='%s', host='%s', status=%i\n",
              info.user, info.uid, info.gid, info.mms, info.host, info.status);

   /* check if the ldap entry is active */
   if ( info.status == STATUS_BOUNCE ) {
      debug(2, "warning: %s's accountsatus is bounce\n", info.user);
      _exit(225); 
   }

#ifdef QLDAP_CLUSTER
   /* check if the I'm the right host */
   if ( qldap_cluster && info.host && str_diff(qldap_me.s, info.host) ) {
      /* hostname is different, so I reconnect */
      forward_mail(info.host, mail, from, fdmess);
      forward_session(info.host, login->s, authdata->s);
      /* that's it. Function does not return */
   }
#endif

   if (!chck_users(info.user) ) return 20;
   /* set the value for qmail-local... */
   if (!stralloc_copys(&nughde, info.user) ) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   alloc_free(info.user);

   /* get the UID for delivery on the local system */
   scan_ulong(info.uid, &tid);
   if (UID_MIN > tid || tid > UID_MAX ) return 21;
   if (!stralloc_cats(&nughde, info.uid)) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   alloc_free(info.uid);

   /* get the GID for delivery on the local system */
   scan_ulong(info.gid, &tid);
   if (GID_MIN > tid || tid > GID_MAX ) return 21;
   if (!stralloc_cats(&nughde, info.gid)) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   alloc_free(info.gid);

   /* get the path of the maildir or mbox */
   if (!chck_paths(info.mms) ) return 23;
   if (!stralloc_cats(&nughde, info.mms)) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   alloc_free(info.mms);

   /* At the moment we ignore the dash-field and the extension field *
    * so we fill up the nughde structure with '\0'                   */
   
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* get the quota for the user of that maildir mbox */
   if ( extra[0].vals != 0 ) {
      debug(32, "%s: %s\n", ENV_QUOTA, extra[0].vals[0]);
      if ( !env_put2(ENV_QUOTA, extra[0].vals[0] ) ) _exit(QLX_NOMEM);
   } else {
      debug(32, "%s: %s\n", ENV_QUOTA, qldap_defaultquota.s);
      if ( !env_put2(ENV_QUOTA, qldap_defaultquota.s )) _exit(QLX_NOMEM);
   }
   ldap_value_free(extra[0].vals);

   /* get the forwarding addresses and build a list *
    * equals to &jdoe@heaven.af.mil in .qmail       */
   if ( extra[1].vals != 0 ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; extra[1].vals[i] != 0; i++ ) {
         if (!stralloc_cats(&foo, extra[1].vals[i])) _exit(QLX_NOMEM);
         if (extra[1].vals[i+1] == 0 ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      debug(32, "%s: %s\n", ENV_FORWARDS, foo.s );
      if ( !env_put2(ENV_FORWARDS, foo.s) ) _exit(QLX_NOMEM);
   } else {
      /* default */
      if ( !env_unset(ENV_FORWARDS) ) _exit(QLX_NOMEM);
   }
   ldap_value_free(extra[1].vals);

   /* get the path of the local delivery program *
    * equals to |/usr/bin/program in .qmail      */
   if ( extra[2].vals != 0 ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; extra[2].vals[i] != 0; i++ ) {
         /* append */
         if (!chck_paths(extra[2].vals[i]) ) return 31;
         if (!stralloc_cats(&foo, extra[2].vals[i])) _exit(QLX_NOMEM);
         if (extra[2].vals[i+1] == 0 ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      debug(32, "%s: %s\n", ENV_PROGRAM, foo.s );
      if ( !env_put2(ENV_PROGRAM, foo.s) ) _exit(QLX_NOMEM);
   } else {
      /* default */
      if ( !env_unset(ENV_PROGRAM) ) _exit(QLX_NOMEM);
   }
   ldap_value_free(extra[2].vals);

   /* get the deliverymode of the mailbox:                    *
    * reply, echo, forwardonly, normal, nombox, localdelivery */
   reply = 0;
   if ( extra[3].vals != 0 ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; extra[3].vals[i] != 0; i++ ) {
         /* append */
         case_lowers(extra[3].vals[i]);
         if ( !str_diff(MODE_REPLY, extra[3].vals[i]) ) reply = 1;
         if (!stralloc_cats(&foo, extra[3].vals[i])) _exit(QLX_NOMEM);
         if (extra[3].vals[i+1] == 0 ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      debug(32, "%s: %s\n", ENV_MODE, foo.s );
      if ( !env_put2(ENV_MODE, foo.s) ) _exit(QLX_NOMEM);
   } else {
      /* default */
      if ( !env_unset(ENV_MODE) ) _exit(QLX_NOMEM);
      if ( !env_unset(ENV_REPLYTEXT) ) _exit(QLX_NOMEM);
   }
   ldap_value_free(extra[3].vals);
   
   if ( reply ) {
      if ( extra[4].vals != 0 ) {
         debug(32, "%s: %s\n", ENV_REPLYTEXT, extra[4].vals[0] );
         if ( !env_put2(ENV_REPLYTEXT, extra[4].vals[0]) ) _exit(QLX_NOMEM);
      }
      ldap_value_free(extra[4].vals);
   }

   /* get the mode of the .qmail interpretion: ldaponly, dotonly, both, none */
   if ( extra[5].vals != 0 ) {
      case_lowers(extra[5].vals[0]);
      if ( !str_diff(DOTMODE_LDAPONLY, extra[5].vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_LDAPONLY) ) _exit(QLX_NOMEM);
      } else if ( !str_diff(DOTMODE_LDAPWITHPROG, extra[5].vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_LDAPWITHPROG) ) _exit(QLX_NOMEM);
      } else if ( !str_diff(DOTMODE_DOTONLY, extra[5].vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_DOTONLY) ) _exit(QLX_NOMEM);
      } else if ( !str_diff(DOTMODE_BOTH, extra[5].vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_BOTH) ) _exit(QLX_NOMEM);
      } else if ( !str_diff(DOTMODE_NONE, extra[5].vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_NONE) ) _exit(QLX_NOMEM);
      } else {
         if ( !env_put2(ENV_DOTMODE, qldap_defdotmode.s) ) _exit(QLX_NOMEM);
      }
   } else {
      /* default */
      if ( !env_put2(ENV_DOTMODE, qldap_defdotmode.s) ) _exit(QLX_NOMEM);
   }
   debug(32, "%s: %s\n", ENV_DOTMODE, env_get(ENV_DOTMODE) );
   ldap_value_free(extra[5].vals);

   /* ok, we finished, lets clean up and disconnect from the LDAP server */
   return 0;
}
/* end -- LDAP server query routines */

stralloc lower = {0};
stralloc wildchars = {0};

void nughde_get(local)
char *local;
{
 char *(args[3]);
   int   pi[2],
         gpwpid,
         gpwstat,
         r,
         fd,
         flagwild;

 if (!stralloc_copys(&lower,"!")) _exit(QLX_NOMEM);
 if (!stralloc_cats(&lower,local)) _exit(QLX_NOMEM);
 if (!stralloc_0(&lower)) _exit(QLX_NOMEM);
 case_lowerb(lower.s,lower.len);

 if (!stralloc_copys(&nughde,"")) _exit(QLX_NOMEM);

 fd = open_read("users/cdb");
 if (fd == -1)
   if (errno != error_noent)
     _exit(QLX_CDB);

   if (fd != -1) {
   uint32 dlen;
   unsigned int i;

   r = cdb_seek(fd,"",0,&dlen);
   if (r != 1) _exit(QLX_CDB);
   if (!stralloc_ready(&wildchars,(unsigned int) dlen)) _exit(QLX_NOMEM);
   wildchars.len = dlen;
   if (cdb_bread(fd,wildchars.s,wildchars.len) == -1) _exit(QLX_CDB);

   i = lower.len;
   flagwild = 0;

      do {
     /* i > 0 */
         if (!flagwild || (i == 1) || (byte_chr(wildchars.s,wildchars.len,lower.s[i - 1]) < wildchars.len)) {
       r = cdb_seek(fd,lower.s,i,&dlen);
       if (r == -1) _exit(QLX_CDB);
            if (r == 1) {
         if (!stralloc_ready(&nughde,(unsigned int) dlen)) _exit(QLX_NOMEM);
         nughde.len = dlen;
         if (cdb_bread(fd,nughde.s,nughde.len) == -1) _exit(QLX_CDB);
         if (flagwild)
      if (!stralloc_cats(&nughde,local + i - 1)) _exit(QLX_NOMEM);
         if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
         close(fd);
         return;
        }
      }
     --i;
     flagwild = 1;
      } while (i);

   close(fd);
  }

 if (pipe(pi) == -1) _exit(QLX_SYS);
 args[0] = "bin/qmail-getpw";
 args[1] = local;
 args[2] = 0;
   switch(gpwpid = vfork()) {
   case -1:
     _exit(QLX_SYS);

   case 0:
     if (prot_gid(auto_gidn) == -1) _exit(QLX_USAGE);
     if (prot_uid(auto_uidp) == -1) _exit(QLX_USAGE);
     close(pi[0]);
     if (fd_move(1,pi[1]) == -1) _exit(QLX_SYS);
     execv(*args,args);
     _exit(QLX_EXECPW);
  }
 close(pi[1]);

 if (slurpclose(pi[0],&nughde,128) == -1) _exit(QLX_SYS);

   if (wait_pid(&gpwstat,gpwpid) != -1) {
   if (wait_crashed(gpwstat)) _exit(QLX_SYS);
   if (wait_exitcode(gpwstat) != 0) _exit(wait_exitcode(gpwstat));
  }
}

int spawn(fdmess,fdout,s,r,at)
int fdmess; int fdout;
char *s; char *r; int at;
{
 int f;

   if (!(f = fork())) {
   char *(args[11]);
   unsigned long u;
   int           n,
                 uid,
                 gid;
   char *x;
   unsigned int xlen;

   stralloc ra = {0};
   int      rv;
   
     /* XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
        XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX
        XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX */
   init_debug(fdout, -1); /* here are no critical data handled so debuglevel is free */
   
   /* copy the whole email address before the @ gets destroyed */
   sig_hangupdefault(); /* clear the hup sig handler for the child */
   if (!stralloc_copys(&ra,r)) _exit(QLX_NOMEM);
   debug(16, "mailaddr: %S\n", &ra);
   /* end -- save the @ */

   r[at] = 0;
   if (!r[0]) _exit(0); /* <> */

   if (chdir(auto_qmail) == -1) _exit(QLX_USAGE);

   /* do the address lookup */
   rv = qldap_get(&ra, s, fdmess);
   switch( rv ) {
      case 0:
		  debug(16, "LDAP lookup succeded\n");
      break;

      case 1:
         if (!stralloc_copys(&nughde,"")) _exit(QLX_NOMEM);
         if ( qldap_localdelivery == 1 ) {
         /* do the address lookup local */
         /* this is the standart qmail lookup funktion */
         	debug(4, "LDAP lookup faild using local db\n");
            nughde_get(r);

         /* the alias-user handling for LDAP only mode */
         } else {
            struct passwd *pw;
            char num[FMT_ULONG];

            debug(4, "LDAP lookup faild using alias (no local db)\n");
            pw = getpwnam(auto_usera);
            if (!pw) {
               _exit(QLX_NOALIAS);
            }
            
            if (!stralloc_copys(&nughde, pw->pw_name)) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_catb(&nughde,num,fmt_ulong(num, (long) pw->pw_uid))) 
               _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_catb(&nughde,num,fmt_ulong(num, (long) pw->pw_gid))) 
               _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde, pw->pw_dir)) _exit(QLX_NOMEM); 
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde,"-")) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde,r)) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
         }
         /* end -- alias-user handling */
      break;
        
      default:
         debug(2, "warning: ldap lookup faild with %i\n", rv);
         _exit(190 + rv);
      break;
   } /* end switch */

   /* debug(16, "nughde: %S\n", &nughde); */
   x = nughde.s;
   xlen = nughde.len;

   args[0] = "bin/qmail-local";
   args[1] = "--";
   args[2] = x;

   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   scan_ulong(x,&u);
   uid = u;
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   scan_ulong(x,&u);
   gid = u;

   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[3] = x;
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[4] = r;

   args[5] = x;
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[6] = x;
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[7] = r + at + 1;
   args[8] = s;
   args[9] = aliasempty;
   args[10] = 0;

   debug(8, "executing 'qmail-local -- %s %s %s %s %s %s %s %s' under uid=%i, gid=%i\n",
            args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9],
            uid, gid);

   if (fd_move(0,fdmess) == -1) _exit(QLX_SYS);
   if (fd_move(1,fdout) == -1) _exit(QLX_SYS);
   if (fd_copy(2,1) == -1) _exit(QLX_SYS);
   if (prot_gid(gid) == -1) _exit(QLX_USAGE);
   if (prot_uid(uid) == -1) _exit(QLX_USAGE);
   if (!getuid()) _exit(QLX_ROOT);

   execv(*args,args);
   if (error_temp(errno)) _exit(QLX_EXECSOFT);
   _exit(QLX_EXECHARD);
  }
 return f;
}


#ifdef QLDAP_CLUSTER
void forward_mail(char *host, stralloc *to, char* from, int fdmess)
{
   char *(args[3]);
   int pi[2];
   int wstat;
   int child;

   if (pipe(pi) == -1) _exit(QLX_SYS);

   switch( child = fork() ) {
      case -1:
         if (error_temp(errno)) _exit(QLX_EXECSOFT);
         _exit(QLX_EXECHARD);
       case 0:
          close(pi[1]);
          if (fd_move(0,fdmess) == -1) _exit(QLX_SYS);
          if (fd_move(1,pi[0]) == -1) _exit(QLX_SYS);
          args[0]="bin/qmail-qmqpc"; args[1]=host; args[2]=0;
          sig_pipedefault();
          execv(*args,args);
   }
   
   debug(8, "Frowrding to %S at host %s from %s\n", to, host, from);
   close(pi[0]);
   allwrite(write, pi[1], "F", 1);
   allwrite(write, pi[1], from, str_len(from));
   allwrite(write, pi[1], "",1);
   allwrite(write, pi[1], "T",1);
   allwrite(write, pi[1], to->s, to->len);
   allwrite(write, pi[1], "", 1);
   allwrite(write, pi[1], "", 1);
   close(pi[1]);
   wait_pid(&wstat,child);
   if (wait_crashed(wstat)) {
      _exit(238);
   }
      
   switch(wait_exitcode(wstat)) {
      case 0: _exit(0);
      case 31: case 61: 
         _exit(240);
      default:
         _exit(239);
   }
}
#endif

