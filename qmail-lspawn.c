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

/* #define QLDAP        */ /* enable LDAP for qmail, done by the Makefile  */
/* #define QLDAPDEBUG   */ /* We should set this with the -D option of gcc */

#ifdef QLDAP /* Includes needed to make LDAP work */

#include "qmail-ldap.h"
#define QLDAP_PORT LDAP_PORT
#include "control.h"
#include "env.h"
#include <lber.h>
#include <ldap.h>
#include "auto_usera.h"
#include "auto_uids.h"
#include "fmt.h"
#include "check.h"
#include <pwd.h>
#include <sys/types.h>

#ifndef NULL
#define NULL 0L
#endif

#endif /* end -- Includes needed to make LDAP work */
#ifdef QLSPAWN_LOG
#include "readwrite.h"
/* for logging */
/*
 * There are these log levels:  
 *       DEBUG_LEVEL   4 : for debug information
 *       INFO_LEVEL    3 : a lot of generic infos
 *       WARNING_LEVEL 2 : warning (not an error, but not OK)
 *       ERROR_LEVEL   1 : error (no panic nessary)
 */
#define DEBUG_LEVEL   4
#define INFO_LEVEL    3
#define WARNING_LEVEL 2
#define ERROR_LEVEL   1

#if LOG_LEVEL >= DEBUG_LEVEL
#define DEBUG(s1,s2,s3,s4)   log_msg(fdlog, s1,s2,s3,s4)
#else
#define DEBUG(s1,s2,s3,s4)
#endif

#if LOG_LEVEL >= INFO_LEVEL
#define INFO(s1,s2,s3,s4)    log_msg(fdlog, s1,s2,s3,s4)
#else
#define INFO(s1,s2,s3,s4)
#endif

#if LOG_LEVEL >= WARNING_LEVEL
#define WARNING(s1,s2,s3,s4) log_msg(fdlog,s1,s2,s3,s4)
#else
#define WARNING(s1,s2,s3,s4)
#endif

#if LOG_LEVEL >= ERROR_LEVEL
#define ERROR(s1,s2,s3,s4)   log_msg(fdlog,s1,s2,s3,s4)
#else 
#define ERROR(s1,s2,s3,s4)
#endif

int fdlog;

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

void log_msg(logfd, s1, s2 , s3, s4) int logfd; char *s1; char *s2; char *s3; char *s4;
{
  if (s1) allwrite(write,logfd,s1,str_len(s1));
  if (s2) allwrite(write,logfd,s2,str_len(s2));
  if (s3) allwrite(write,logfd,s3,str_len(s3));
  if (s4) allwrite(write,logfd,s4,str_len(s4));
}

/* now some realy ugly hacks, don't even think of using them in non-debug code */
char buf[FMT_ULONG];
char *ulong_2_str(unsigned long i) { buf[fmt_ulong(buf, i)] = '\0'; return buf;}
char *sa2s(stralloc *sa)
{
  if(! stralloc_0(sa) ) return "No memory";
  sa->len--;
  return sa->s;
}

#else /* -- LOGGING_OFF -- */
#define DEBUG(s1,s2,s3,s4)
#define INFO(s1,s2,s3,s4)
#define WARNING(s1,s2,s3,s4)
#define ERROR(s1,s2,s3,s4)

/* ... for those how can't read */
void debug_msg() {exit(100);}
char *ulong_2_str() {return 0L;}
char *sa2s() {return 0L;}

#endif
/* end -- for logging */

char *aliasempty;


#ifdef QLDAP /* routine to read the control files */

/* initialize the string arrays, this uses DJB's libs */
stralloc    qldap_server = {0};
stralloc    qldap_basedn = {0};
stralloc    qldap_user = {0};
stralloc    qldap_password = {0};
stralloc    qldap_defdotmode = {0};
stralloc    qldap_defaultquota = {0};
stralloc    qldap_quotawarning = {0};
#ifdef AUTOHOMEDIRMAKE
stralloc    qldap_dirmaker = {0};
#endif

stralloc    qldap_messagestore = {0};
stralloc    qldap_username = {0};
stralloc    qldap_uid = {0};
stralloc    qldap_gid = {0};

stralloc    foo = {0};

int         qldap_localdelivery = 1;
/* init done */

/* char replacement */
unsigned int replace(s, len, f, r)
char *s;
register unsigned int len;
char f;
char r;
{
   register char *t;
   register int count = 0;

   t=s;
   for(;;) {
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
      if (!len) return count; if (*t == f) { *t=r; count++; } ++t; --len;
   }
}


/* read the various LDAP control files */
void get_qldap_controls()
{
   /* Sorry but in this part of the code no logging is possible */
   if (chdir(auto_qmail) == -1) _exit(111);

   if (control_rldef(&qldap_server,"control/ldapserver",0,(char *) 0) != 1) _exit(199);
   if (!stralloc_0(&qldap_server)) _exit(QLX_NOMEM);

   if (control_rldef(&qldap_basedn,"control/ldapbasedn",0,"") == -1) _exit(222);
   if (!stralloc_0(&qldap_basedn)) _exit(QLX_NOMEM);

   if (control_rldef(&qldap_user,"control/ldaplogin",0,"") == -1) _exit(222);
   if (!stralloc_0(&qldap_user)) _exit(QLX_NOMEM);

   if (control_rldef(&qldap_password,"control/ldappassword",0,"") == -1) _exit(222);
   if (!stralloc_0(&qldap_password)) _exit(QLX_NOMEM);

   if (control_readint(&qldap_localdelivery,"control/ldaplocaldelivery") == -1) _exit(222);

   if (control_rldef(&qldap_defaultquota,"control/ldapdefaultquota",0,"0") == -1) _exit(222);
   if (!stralloc_0(&qldap_defaultquota)) _exit(QLX_NOMEM);

   if (control_rldef(&qldap_defdotmode,"control/ldapdefaultdotmode",0,"ldaponly") == -1) _exit(222);
   if (!stralloc_0(&qldap_defdotmode)) _exit(QLX_NOMEM);

   if (control_rldef(&qldap_messagestore,"control/ldapmessagestore",0,"/home/") == -1) _exit(222);

   if (control_rldef(&qldap_username,"control/ldapusername",0,"") != 1) _exit(222);
   
   if (control_rldef(&qldap_uid,"control/ldapuid",0,"") != 1) _exit(222);
   
   if (control_rldef(&qldap_gid,"control/ldapgid",0,"") != 1) _exit(222);

   if (control_readfile(&qldap_quotawarning,"control/quotawarning",0) == 1 ) {
      replace(qldap_quotawarning.s, qldap_quotawarning.len, '\0', '\n');
      if (!stralloc_0(&qldap_quotawarning)) _exit(QLX_NOMEM);
      if ( !env_put2(ENV_QUOTAWARNING, qldap_quotawarning.s )) _exit(QLX_NOMEM);
   } else {
      if ( !env_unset(ENV_QUOTAWARNING) ) _exit(QLX_NOMEM);
   }

#ifdef AUTOHOMEDIRMAKE
   if (control_readfile(&qldap_dirmaker,"control/dirmaker",0) == 1 ) {
      if (!stralloc_0(&qldap_dirmaker)) _exit(QLX_NOMEM);
      if ( !env_put2(ENV_HOMEDIRMAKE, qldap_dirmaker.s )) _exit(QLX_NOMEM);
   } else {
      if ( !env_unset(ENV_HOMEDIRMAKE) ) _exit(QLX_NOMEM);
   }
#endif

   /* reading of the various LDAP control files done */
   /* chdir back to queue/mess */
   if (chdir(auto_qmail) == -1) _exit(111);
   if (chdir("queue/mess") == -1) _exit(111);

}

#endif /* end -- routine to read the control files */

/* also here it is not possible to log something */
void initialize(argc,argv)
int argc;
char **argv;
{
   aliasempty = argv[1];
   if (!aliasempty) {
      _exit(100);
   }
   
#ifdef QLDAP /* read the control files */
   get_qldap_controls();
#endif
}

int truncreport = 3000;

void report(ss,wstat,s,len)
substdio *ss;
int wstat;
char *s;
int len;
{
#ifdef QLSPAWN_LOG
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
      
#ifdef QLDAP /* report LDAP errors */
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
         substdio_puts(ss, "DInternal error in ldap_set_option. (LDAP-ERR #202)\n");
      REPORT_RETURN;

      case 203:
         substdio_puts(ss, "ZUnable to login into LDAP server (bad username/password?). (LDAP-ERR #203)\n");
      REPORT_RETURN;

      case 204:
         substdio_puts(ss, "DInternal error in ldap_search_ext_s. (LDAP-ERR #204)\n");
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

#endif /* end -- report LDAP errors */

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

#ifdef QLDAP /* LDAP server query routines */

int qldap_get( stralloc *mail )
{
   LDAP           *ld;
   LDAPMessage    *res, *msg;
   char           *dn,
                  **vals,
                  *attrs[] = {  LDAP_MAIL,
                                LDAP_MAILALTERNATE,
                                LDAP_QMAILUSER,
                                LDAP_QMAILUID,
                                LDAP_QMAILGID,
                                LDAP_MAILSTORE,
                                LDAP_QUOTA,
                                LDAP_FORWARDS,
                                LDAP_PROGRAM,
                                LDAP_MODE,
                                LDAP_REPLYTEXT,
                                LDAP_DOTMODE,
                                LDAP_UID,
                                LDAP_PASSWD, NULL };

   int            version, at, ext,
                  rc, i, reply = 0,
                  num_entries = 0;
   char           *r;
   stralloc       filter = {0};

   /* lower case the receipient email address before     *
    * we do the check for illegal chars                  */
   /* case_lowerb(mail->s, mail->len); */ /* XXX: no longer used */

   /* check the mailaddress for illegal characters       *
    * escape '*', ,'\', '(' and ')' with a preceding '\' */
   /* NOTE: also '\0' should be escaped but this is not done. */
   if (!escape_forldap(mail)) _exit(QLX_NOMEM);

   /* initialize the LDAP connection and get a handle */
   if ( (ld = ldap_init(qldap_server.s,QLDAP_PORT)) == NULL ) return 11;

   /* set LDAP connection options (only with Mozilla LDAP SDK) */
#ifdef LDAP_OPT_PROTOCOL_VERSION
   version = LDAP_VERSION2;
   if ( ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&version) != LDAP_SUCCESS ) return 12;
#endif

   /* connect to the LDAP server */
   if ( (rc = ldap_simple_bind_s(ld,qldap_user.s,qldap_password.s)) != LDAP_SUCCESS ) { 
       ERROR("ldap_simple_bind_s: ", ldap_err2string(rc), "\n", 0);
       return 13;
   }

   /* build the search string for the email address */
   if (!stralloc_copys(&filter,"(|(mail=" ) ) _exit(QLX_NOMEM);
   if (!stralloc_cat(&filter,mail)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,")(mailalternateaddress=")) _exit(QLX_NOMEM);
   if (!stralloc_cat(&filter,mail)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,"))")) _exit(QLX_NOMEM);
   if (!stralloc_0(&filter)) _exit(QLX_NOMEM);
   
   DEBUG("filter: ", filter.s, "\n", 0);

   /* do the search for the email address */
   if ( (rc = ldap_search_s(ld,qldap_basedn.s,LDAP_SCOPE_SUBTREE,filter.s,attrs,0,&res)) != LDAP_SUCCESS ) {
      ERROR("ldap_search_ext_s: ", ldap_err2string(rc), "\n", 0);
      if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
      return 14;
   }
   if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
   ext = 0; at = 0;
   r = mail->s;
   /* count the results, we must have exactly one */
   if ( (num_entries = ldap_count_entries(ld,res)) != 1) {
      /* this handles the "catch all" extension */
      i = mail->len;
      for (at = i - 1; r[at] != '@' && at >= 0 ; at--) ;
      /* build the search string for the email address */
      if (!stralloc_copys(&filter,"(|(mail=" ) ) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) _exit(QLX_NOMEM);
      if (!stralloc_catb(&filter,r+at, i-at)) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,")(mailalternateaddress=")) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,LDAP_CATCH_ALL)) _exit(QLX_NOMEM);
      if (!stralloc_catb(&filter,r+at, i-at)) _exit(QLX_NOMEM);
      if (!stralloc_cats(&filter,"))")) _exit(QLX_NOMEM);
      if (!stralloc_0(&filter)) _exit(QLX_NOMEM);
      DEBUG("def-filter: ", filter.s, "\n", 0);
       
      /* do the search for the email address */
      if ( (rc = ldap_search_s(ld,qldap_basedn.s,LDAP_SCOPE_SUBTREE,filter.s,attrs,0,&res)) != LDAP_SUCCESS ) {
         ERROR("ldap_search_ext_s: ", ldap_err2string(rc), "\n", 0);
         if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
         return 14;
      }
      if (!stralloc_copys(&filter, "")) _exit(QLX_NOMEM);
      /* count the results, we must have exactly one */
      if ( (num_entries = ldap_count_entries(ld,res)) != 1) return 1;
   }
   

   /* go to the first entry */
   msg = ldap_first_entry(ld,res);

   /* get the dn and free it (we dont need it, to prevent memory leaks) */
#ifdef LDAP_OPT_PROTOCOL_VERSION /* (only with Mozilla LDAP SDK) */
   if ( (dn = ldap_get_dn(ld,msg)) != NULL ) ldap_memfree(dn);
#else
   if ( (dn = ldap_get_dn(ld,msg)) != NULL ) free(dn);
#endif

   /* go through the attributes and set the proper args for qmail-local  *
    * this can probably done with some sort of loop, but hey, how cares? */

   /* check if the ldap entry is active */
   if ( (vals = ldap_get_values(ld,msg,LDAP_ISACTIVE)) != NULL ) {
      DEBUG("is_active: ", vals[0], "\n", 0);
      if ( !str_diff(ISACTIVE_BOUNCE, vals[0]) ) _exit(225); 
   }

   /* get the username for delivery on the local system */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILUSER)) != NULL ) {
//      DEBUG("qmailUser: ", vals[0], "\n", 0);
      if (!chck_users(vals[0]) ) return 20;
      /* set the value for qmail-local... */
      if (!stralloc_copys(&nughde, vals[0])) _exit(QLX_NOMEM);
   } else {
      /* ...or set the default one (or break) */
      if (!qldap_username.len) return 40;
      if (!chck_userb(qldap_username.s,qldap_username.len)) return 41;
      if (!stralloc_copy(&nughde, &qldap_username)) _exit(QLX_NOMEM);
   }
   ldap_value_free(vals);
   
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* get the UID for delivery on the local system */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILUID)) != NULL ) {
//      DEBUG("qmailUID: ", vals[0], "\n", 0);
      if (100 > chck_ids(vals[0]) ) return 21;
      if (!stralloc_cats(&nughde, vals[0])) _exit(QLX_NOMEM);
   } else {
      if (!qldap_uid.len) return 42;
      if (100 > chck_idb(qldap_uid.s,qldap_uid.len) ) return 43;
      if (!stralloc_cat(&nughde, &qldap_uid)) _exit(QLX_NOMEM);
   }
   ldap_value_free(vals);

   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* get the GID for delivery on the local system */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILGID)) != NULL ) {
//      DEBUG("qmailGID: ", vals[0], "\n", 0);
      if ( 100 > chck_ids(vals[0]) ) return 22; 
      if (!stralloc_cats(&nughde, vals[0])) _exit(QLX_NOMEM);
   } else {
      if (!qldap_gid.len) return 44;
      if ( 100 > chck_idb(qldap_gid.s,qldap_gid.len) ) return 45;
      if (!stralloc_cat(&nughde, &qldap_gid)) _exit(QLX_NOMEM);
   }
   ldap_value_free(vals);
   
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* get the path of the maildir or mbox */
   if ( (vals = ldap_get_values(ld,msg,LDAP_MAILSTORE)) != NULL ) {
//      DEBUG("mailMessageStore: ", vals[0], "\n", 0);
      if (vals[0][0] != '/') {
         if (qldap_messagestore.s[0] != '/') return 46;
         if (qldap_messagestore.s[qldap_messagestore.len -1] != '/') return 47;
         if (!stralloc_cats(&qldap_messagestore, vals[0])) _exit(QLX_NOMEM);
         if (!chck_pathb(qldap_messagestore.s,qldap_messagestore.len) ) return 24;
         if (!stralloc_cat(&nughde, &qldap_messagestore)) _exit(QLX_NOMEM);
      } else {
         if (!chck_paths(vals[0]) ) return 23;
         if (!stralloc_cats(&nughde, vals[0])) _exit(QLX_NOMEM);
      }
   } else {
      return 25;
   }
   ldap_value_free(vals);

   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* At the moment we ignore the dash-field and the extension field *
    * so we fill up the nughde structure with '\0'                   */
   
   if (ext) if (!stralloc_cats(&nughde, "-")) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
   if (ext) if (!stralloc_catb(&nughde, r+ext, at-ext)) _exit(QLX_NOMEM);
   if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);

   /* get the quota for the user of that maildir mbox */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QUOTA)) != NULL ) {
      if ( !env_put2(ENV_QUOTA, vals[0] ) ) _exit(QLX_NOMEM);
   } else {
      if ( !env_put2(ENV_QUOTA, qldap_defaultquota.s )) _exit(QLX_NOMEM);
   }
   ldap_value_free(vals);

   /* get the forwarding addresses and build a list *
    * equals to &jdoe@heaven.af.mil in .qmail       */
   if ( (vals = ldap_get_values(ld,msg,LDAP_FORWARDS)) != NULL ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; vals[i] != NULL; i++ ) {
         /* append */
         /* if (!chck_mails(vals[i]) ) return 30; */ /* XXX: this function will be removed */
         /* no longer needed, its the MTA/users problem to have correct forwarding addresses */
         if (!stralloc_cats(&foo, vals[i])) _exit(QLX_NOMEM);
         if (vals[i+1] == NULL ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      if ( !env_put2(ENV_FORWARDS, foo.s) ) _exit(QLX_NOMEM);
      DEBUG(ENV_FORWARDS,": ", foo.s, "\n");
   } else {
      /* default */
      if ( !env_unset(ENV_FORWARDS) ) _exit(QLX_NOMEM);
      DEBUG("NO ", ENV_FORWARDS, "\n",0);
   }
   ldap_value_free(vals);

   /* get the path of the local delivery program *
    * equals to |/usr/bin/program in .qmail      */
   if ( (vals = ldap_get_values(ld,msg,LDAP_PROGRAM)) != NULL ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; vals[i] != NULL; i++ ) {
         /* append */
         if (!chck_paths(vals[i]) ) return 31;
         if (!stralloc_cats(&foo, vals[i])) _exit(QLX_NOMEM);
         if (vals[i+1] == NULL ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      if ( !env_put2(ENV_PROGRAM, foo.s) ) _exit(QLX_NOMEM);
      DEBUG(ENV_PROGRAM,": ", foo.s, "\n");
   } else {
      /* default */
      if ( !env_unset(ENV_PROGRAM) ) _exit(QLX_NOMEM);
      DEBUG("NO ", ENV_PROGRAM, "\n",0);
   }
   ldap_value_free(vals);

   /* get the deliverymode of the mailbox:                    *
    * reply, echo, forwardonly, normal, nombox, localdelivery */
   if ( (vals = ldap_get_values(ld,msg,LDAP_MODE)) != NULL ) {
      if (!stralloc_copys(&foo, "")) _exit(QLX_NOMEM);
      for ( i = 0; vals[i] != NULL; i++ ) {
         /* append */
         case_lowers(vals[i]);
         if ( !str_diff(MODE_REPLY, vals[i]) ) reply = 1;
         if (!stralloc_cats(&foo, vals[i])) _exit(QLX_NOMEM);
         if (vals[i+1] == NULL ) break;
         if (!stralloc_cats(&foo, ",") ) _exit(QLX_NOMEM);
      }
      if (!stralloc_0(&foo) ) _exit(QLX_NOMEM);
      if ( !env_put2(ENV_MODE, foo.s) ) _exit(QLX_NOMEM);
      DEBUG(ENV_MODE,": ", foo.s, "\n");
   } else {
      /* default */
      if ( !env_unset(ENV_MODE) ) _exit(QLX_NOMEM);
      if ( !env_unset(ENV_REPLYTEXT) ) _exit(QLX_NOMEM);
      DEBUG("NO ", ENV_MODE, "\n",0);
   }
   ldap_value_free(vals);
   
   if ( reply ) {
      if ( (vals = ldap_get_values(ld,msg,LDAP_REPLYTEXT)) != NULL ) {
          if ( !env_put2(ENV_REPLYTEXT, vals[0]) ) _exit(QLX_NOMEM);
          DEBUG(ENV_REPLYTEXT,": ", vals[0], "\n");
      }
      ldap_value_free(vals);
   }

   /* get the mode of the .qmail interpretion: ldaponly, dotonly, both, none */
   if ( (vals = ldap_get_values(ld,msg,LDAP_DOTMODE)) != NULL ) {
      case_lowers(vals[0]);
//      DEBUG(ENV_DOTMODE,"(from server): ", vals[0], "\n");
      if ( !str_diff(DOTMODE_LDAPONLY, vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_LDAPONLY) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,": ",DOTMODE_LDAPONLY, "\n");
      } else if ( !str_diff(DOTMODE_LDAPWITHPROG, vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_LDAPWITHPROG) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,": ",DOTMODE_LDAPWITHPROG, "\n");
      } else if ( !str_diff(DOTMODE_DOTONLY, vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_DOTONLY) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,": ",DOTMODE_DOTONLY, "\n");
      } else if ( !str_diff(DOTMODE_BOTH, vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_BOTH) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,": ",DOTMODE_BOTH, "\n");
      } else if ( !str_diff(DOTMODE_NONE, vals[0]) ) {
         if ( !env_put2(ENV_DOTMODE, DOTMODE_NONE) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,": ",DOTMODE_NONE, "\n");
      } else {
         if ( !env_put2(ENV_DOTMODE, qldap_defdotmode.s) ) _exit(QLX_NOMEM);
         DEBUG(ENV_DOTMODE,"(default): ",qldap_defdotmode.s, "\n");
      }
   } else {
      /* default */
      if ( !env_put2(ENV_DOTMODE, qldap_defdotmode.s) ) _exit(QLX_NOMEM);
      DEBUG("NO ", ENV_DOTMODE, "\n",0);
   }
   ldap_value_free(vals);

   /* ok, we finished, lets clean up and disconnect from the LDAP server */
   ldap_unbind_s(ld);
   return 0;
}
#endif /* end -- LDAP server query routines */

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
      int            n,
                     uid,
                     gid;
   char *x;
   unsigned int xlen;
   
#ifdef QLDAP /* copy the whole email address before the @ gets destroyed */
   stralloc ra = {0};
   int      rv;
#ifdef QLSPAWN_LOG
   fdlog = fdout;
#endif
   if (!stralloc_copys(&ra,r)) _exit(QLX_NOMEM);
   DEBUG("address: ", r, "\n", 0);
#endif /* end -- save the @ */


   r[at] = 0;
   if (!r[0]) _exit(0); /* <> */

   if (chdir(auto_qmail) == -1) _exit(QLX_USAGE);

#ifdef QLDAP /* do the address lookup - part 1 */
   rv = qldap_get(&ra);
   DEBUG("qldap_get return value: ", ulong_2_str(rv), "\n", 0);
   switch( rv ) {
      case 0:
        INFO("LDAP lookup succeded, user found\n",0,0,0);
      break;

      case 1: 
         WARNING("LDAP lookup failed, ",0,0,0);
         if (!stralloc_copys(&nughde,"")) _exit(QLX_NOMEM);
         if ( qldap_localdelivery == 1 ) {
           WARNING("... looking up on local db\n",0,0,0);
#endif /* end -- do the address lookup - part 1 */

   nughde_get(r);

#ifdef QLDAP /* the alias-user handling for LDAP only mode - part 2 */
         } else {
            struct passwd *pw;
            char num[FMT_ULONG];

            WARNING("local delivery not enabled, trying to find alias user in passwd db\n",0,0,0);

            pw = getpwnam(auto_usera);
            if (!pw) {
              WARNING("getpwnam failed, your qmail configuration is probaly screwed\n",0,0,0);
              _exit(QLX_NOALIAS);
            }
            
            if (!stralloc_copys(&nughde, pw->pw_name)) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_catb(&nughde,num,fmt_ulong(num, (long) pw->pw_uid))) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_catb(&nughde,num,fmt_ulong(num, (long) pw->pw_gid))) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde, pw->pw_dir)) _exit(QLX_NOMEM); 
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde,"-")) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            if (!stralloc_cats(&nughde,r)) _exit(QLX_NOMEM);
            if (!stralloc_0(&nughde)) _exit(QLX_NOMEM);
            WARNING("... trying alias\n",0,0,0);
         }
      break;
        
      default:
         _exit(190 + rv);
      break;
   } /* end switch */

#endif /* end -- alias-user handling - part 2 */

#ifdef QLSPAWN_LOG
#if LOG_LEVEL >= DEBUG_LEVEL
   DEBUG("nughde: ", nughde.s,0,0);
   { char *s=nughde.s+1; 
     for (; s<nughde.s+nughde.len; s++ )
        if ( *(s-1) == '\0' )
           DEBUG(" ", s,0,0);
   }
   DEBUG("\n",0,0,0);
#endif
#endif

   x = nughde.s;
   xlen = nughde.len;

   args[0] = "bin/qmail-local";
   args[1] = "--";
   args[2] = x;

   INFO("executing qmail-local with user: ", x, "\n", 0);
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(QLX_USAGE); x += n; xlen -= n;

   scan_ulong(x,&u);
   uid = u;
   INFO("uid: ", x, "\n", 0);
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   scan_ulong(x,&u);
   gid = u;
   INFO("gid: ", x, "\n", 0);

   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[3] = x;
   INFO("homedir: ", x, "\n", 0);
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[4] = r;
   INFO("local: ", r, "\n", 0);

   args[5] = x;
   INFO("dash: ", x, "\n", 0);
   
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[6] = x;
   INFO("ext: ", x, "\n", 0);
   n = byte_chr(x,xlen,0); if (n++ == xlen) _exit(198); x += n; xlen -= n;

   args[7] = r + at + 1;
   args[8] = s;
   args[9] = aliasempty;
   args[10] = 0;

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
