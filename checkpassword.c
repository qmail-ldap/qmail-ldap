#include <errno.h>
#define QLDAP_PORT LDAP_PORT
#include "control.h"
#include "stralloc.h"
#include "env.h"
#include "lber.h"
#include "ldap.h"
#include "auto_usera.h"
#include "auto_uids.h"
#include "auto_qmail.h"
#include "fmt.h"
#include "check.h"
#include "case.h"
#include "qlx.h"
#include <sys/types.h>
#include "compatibility.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "str.h"

#ifndef NULL
 #define NULL 0
#endif

#ifdef QLDAPDEBUG
#warning __checkpassword_DEBUG_version_set_in_Makefile__
#warning __you_need_a_none_debug_version_to_run_with_qmail-pop3d__
#endif

/* Edit the first lines in the Makefile to enable local passwd lookups and debug options.
 * To use shadow passwords under Solaris, uncomment the 'SHADOWOPTS' line in the Makefile.
 * To use shadow passwords under Linux, uncomment the 'SHADOWOPTS' line and
 * the 'SHADOWLIBS=-lshadow' line in the Makefile.
 */
#ifdef LOOK_UP_PASSWD
#include <pwd.h>
#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef AIX
#include <userpw.h>
#endif

#endif /* LOOK_UP_PASSWD */


extern int errno;
extern char *crypt();
extern char *malloc();

char up[513];
int uplen;

char* sa2s(stralloc sa)
{
  if(! stralloc_0(&sa) ) return "No memory";
  return sa.s;
}


/* initialize the string arrays, this uses DJB's libs */
stralloc    qldap_server = {0};
stralloc    qldap_basedn = {0};
stralloc    qldap_user = {0};
stralloc    qldap_password = {0};

stralloc    qldap_uid = {0};
stralloc    qldap_gid = {0};
stralloc    qldap_messagestore = {0};
stralloc    qldap_passwdappend = {0};
/* init done */

/* read the various LDAP control files */

void get_qldap_controls()
{
#ifdef QLDAPDEBUG
      printf("\naction: reading control files\n\n");
#endif

   if (control_rldef(&qldap_server,"control/ldapserver",0,(char *) 0) != 1) {
#ifdef QLDAPDEBUG
      printf(" unable to read \t: control/ldapserver\n exit\n");
#endif
      _exit(1);
   }
   if (!stralloc_0(&qldap_server)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG
   printf(" control/ldapserver \t: %s\n",qldap_server.s);
#endif

   if (control_rldef(&qldap_basedn,"control/ldapbasedn",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_basedn)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG
   printf(" control/ldapbasedn \t: %s\n",qldap_basedn.s);
#endif

   if (control_rldef(&qldap_user,"control/ldaplogin",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_user)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG
   printf(" control/ldaplogin \t: %s\n",qldap_user.s);
#endif

   if (control_rldef(&qldap_password,"control/ldappassword",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_password)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG
   printf(" control/ldappassword \t: %s\n",qldap_password.s);
#endif

   if (control_rldef(&qldap_uid,"control/ldapuid",0,"") == -1) _exit(1);
#ifdef QLDAPDEBUG
   printf(" control/ldapuid \t: %s\n",sa2s(qldap_uid) );
#endif
   if (control_rldef(&qldap_gid,"control/ldapgid",0,"") == -1) _exit(1);
#ifdef QLDAPDEBUG
   printf(" control/ldapgid \t: %s\n",sa2s(qldap_gid) );
#endif

   if (control_rldef(&qldap_messagestore,"control/ldapmessagestore",0,"/home/") == -1) _exit(1);
#ifdef QLDAPDEBUG
   printf(" control/ldapmessagestore: %s\n",sa2s(qldap_messagestore) );
#endif

   if (control_rldef(&qldap_passwdappend,"control/ldappasswdappend",0,"./") == -1) _exit(1);
#ifdef QLDAPDEBUG
   printf(" control/ldappasswdappend: %s\n",sa2s(qldap_passwdappend) );
#endif
#ifdef QLDAPDEBUG
   printf("\naction: reading control files done successful\n");
#endif
}

int qldap_get( char *login, stralloc *passwd, unsigned int *uid, unsigned int *gid, stralloc *homedir )
{
   LDAP           *ld;
   LDAPMessage    *res, *msg;
   char           *dn,
                  **vals,
                  *attrs[] = {  "uid",
                                "userPassword",
                                "qmailUID",
                                "qmailGID",
                                "mailMessagestore", NULL };

   int            rc,
                  version,
                  num_entries = 0;

   stralloc       filter = {0};

#ifdef QLDAPDEBUG
  printf("\naction: doing ldap lookup\n\n");
#endif

   /* lower case the POP user name before we do the      *
    * check for illegal chars                            */
   case_lowers(login);

   /* check the login uid for illegal characters         *
    * only [a-z][0-9][.-_] are allowed                   *
    * because all other stuff would kill the LDAP search */
   if ( !chck_users(login) ) {
#ifdef QLDAPDEBUG
  printf(" check for illegal characters \t: failed, POP username contains illegal characters\n");
#endif
     _exit(1);
   } else {
#ifdef QLDAPDEBUG
  printf(" check for illegal characters \t: succeeded\n");
#endif
   }

   /* initialize the LDAP connection and get a handle */
   if ( (ld = ldap_init(qldap_server.s,QLDAP_PORT)) == NULL ) {
#ifdef QLDAPDEBUG
  printf(" initialize ldap connection \t: failed, problem in ldap library?\n");
#endif
     _exit(1);
   } else {
#ifdef QLDAPDEBUG
  printf(" initialize ldap connection\t: succeeded\n");
#endif
   }

   /* set LDAP connection options (only with Mozilla LDAP SDK) */
#ifdef LDAP_OPT_PROTOCOL_VERSION
   version = LDAP_VERSION2;
   if ( ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&version) != LDAP_SUCCESS ) {
#ifdef QLDAPDEBUG
  printf(" setting ldap connection options\t: failed, are you using Mozilla LDAP SDK?\n");
#endif
     _exit(1);
   } else {
#ifdef QLDAPDEBUG
  printf(" setting ldap connection options: succeeded\n");
#endif
   }
#endif

   /* connect to the LDAP server */
   if ( (rc = ldap_simple_bind_s(ld,qldap_user.s,qldap_password.s)) != LDAP_SUCCESS ) {
#ifdef QLDAPDEBUG
  printf(" connecting to ldap server\t: failed, %s\n",ldap_err2string(rc));
#endif
      _exit(1);
   } else {
#ifdef QLDAPDEBUG
  printf(" connecting to ldap server\t: succeeded\n");
#endif
   }

   /* build the search string for the login uid */
   if (!stralloc_copys(&filter,"(uid=" ) ) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,login)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,")")) _exit(QLX_NOMEM);
   if (!stralloc_0(&filter)) _exit(QLX_NOMEM);

#ifdef QLDAPDEBUG
  printf(" building ldap search string\t: '%s'\n",filter.s);
#endif
   
   /* do the search for the login uid */
   if ( (rc = ldap_search_s(ld,qldap_basedn.s,LDAP_SCOPE_SUBTREE,filter.s,attrs,0,&res)) != LDAP_SUCCESS ) {
#ifdef QLDAPDEBUG
  printf(" ldap search on server\t: failed, %s\n",ldap_err2string(rc));
#endif
      _exit(1);
   } else {
#ifdef QLDAPDEBUG
  printf(" ldap search on server\t: succeeded");
#endif
   }

   /* count the results, we must have exactly one */
   if ( (num_entries = ldap_count_entries(ld,res)) != 1) {
#ifdef QLDAPDEBUG
  printf(", but returned no match\n");
#endif
   return 1;
   } else {
#ifdef QLDAPDEBUG
  printf(", found one match\n");
#endif
   }

   /* go to the first entry */
   msg = ldap_first_entry(ld,res);

   /* get the dn and free it (we dont need it, to prevent memory leaks) */
#ifdef LDAP_OPT_PROTOCOL_VERSION /* (only with Mozilla LDAP SDK) */
   if ( (dn = ldap_get_dn(ld,msg)) != NULL ) ldap_memfree(dn);
#else
   if ( (dn = ldap_get_dn(ld,msg)) != NULL ) free(dn);
#endif

   /* go through the attributes and set the proper args for qmail-pop3d */
   /* get the stored and (hopefully) encrypted password */
   if ( (vals = ldap_get_values(ld,msg,"userPassword")) != NULL ) {
      if (!stralloc_copys(passwd, vals[0])) _exit(QLX_NOMEM);
      if (!stralloc_0(passwd)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG 
      printf(" ldap search results \t: found password '%s'\n", vals[0]);
#endif
   } else {
#ifdef QLDAPDEBUG
     printf(" ldap search results \t: no password\n");
#endif
      _exit(1);
   }
   ldap_value_free(vals);

   /* get the UID for setuid() for POP retrieval */
   if ( (vals = ldap_get_values(ld,msg,"qmailUID")) != NULL ) {
      *uid = chck_ids(vals[0]);
      if (100 > *uid ) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: UID failed for '%s'\n",vals[0]);
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: UID succeeded for '%s'\n",vals[0]);
#endif
         }
   } else { /* default */
      if (!qldap_uid.len) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: no UID found and control/ldapuid empty\n");
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: no UID found, taking control/ldapuid\n");
#endif
         }
      *uid = chck_idb(qldap_uid.s,qldap_uid.len);
      if (100 > *uid ) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: control/ldapuid check failed for '%s'\n",sa2s(qldap_uid) );
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: control/ldapuid check succeeded for '%s'\n",sa2s(qldap_uid) );
#endif
         }
   }
   ldap_value_free(vals);

   /* get the GID for setgid() for POP retrieval */
   if ( (vals = ldap_get_values(ld,msg,"qmailGID")) != NULL ) {
      *gid = chck_ids(vals[0]);
      if ( 100 > *gid ) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: GID failed for '%s'\n",vals[0]);
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: GID succeeded for '%s'\n",vals[0]);
#endif
         }
   } else { /* default */
      if (!qldap_gid.len) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: no GID found, and control/ldapgid empty\n");
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: no GID found, taking control/ldapgid\n");
#endif
         }
      *gid = chck_idb(qldap_gid.s,qldap_gid.len);
      if ( 100 > *gid ) {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: control/ldapgid check failed for '%s'\n",sa2s(qldap_gid) );
#endif
         _exit(1);
         } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: control/ldapgid check succeeded for '%s'\n",sa2s(qldap_gid) );
#endif
         }
   }
   ldap_value_free(vals);

   /* get the path of the maildir for qmail-pop3d */
   if ( (vals = ldap_get_values(ld,msg,"mailMessagestore")) != NULL ) {
      if (vals[0][0] != '/') {   /* relative path */
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: maildir path is relative to messagestore\n");
#endif
         if (qldap_messagestore.s[0] != '/') {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: control/ldapmessagestore path does not begin with /\n");
#endif
            _exit(1);
            }
         if (qldap_messagestore.s[qldap_messagestore.len -1] != '/') {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: control/ldapmessagepath does not end with /\n");
#endif
            _exit(1);
            }
         if (!stralloc_cats(&qldap_messagestore, vals[0])) _exit(QLX_NOMEM);
         if (!chck_pathb(qldap_messagestore.s,qldap_messagestore.len) ) {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: combined maildir path contains illegal constructs\n");
#endif
            _exit(1);
            }
         if (qldap_messagestore.s[qldap_messagestore.len -1] != '/') {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: combined maildir path does not end with /\n");
#endif
            _exit(1);
            }
         if (!stralloc_copy(homedir,&qldap_messagestore)) _exit(QLX_NOMEM);
      } else {                   /* absolute path */
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: maildir path is absolute\n");
#endif
         if (!chck_paths(vals[0]) ) {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: maildir path contains illegal constructs\n");
#endif
            _exit(1);
            }
         if (!stralloc_copys(homedir, vals[0])) _exit(QLX_NOMEM);
         if (homedir->s[homedir->len -1] != '/') {
#ifdef QLDAPDEBUG
            printf(" ldap search results \t: maildir path does not end with /\n");
#endif
            _exit(1);
            }
      }
   if (!stralloc_0(homedir)) _exit(QLX_NOMEM);
#ifdef QLDAPDEBUG
   printf(" ldap search results \t: maildir path is '%s'\n",homedir->s);
#endif
   } else {
#ifdef QLDAPDEBUG
         printf(" ldap search results \t: no maildir path specified\n");
#endif
      _exit(1);
   }
   ldap_value_free(vals);

#ifdef QLDAPDEBUG
   printf("\naction: ldap lookup done successful\n");
#endif
   return 0;
} /* end -- ldap lookup */

void main(argc,argv)
int argc;
char **argv;
{
 char hashed[40] = "0000000000000000000000000000000000000000";
 char *login,
      *encrypted,
      *entredpassword;

#warning __do_not_remove_one_of_this_variables_all_are_somehow_used__
 unsigned int i, r,
              uid,
              gid,
              shift;

 stralloc password={0};
 stralloc homedir={0};

#ifdef LOOK_UP_PASSWD
 struct passwd *pw;
 #ifdef PW_SHADOW
 struct spwd *spw;
 #endif
 #ifdef AIX
 struct userpw *spw;
 #endif
#endif

#ifdef QLDAPDEBUG
 printf("\naction: parsing arguments\n\n");
 if (!argv[1]) {
   printf(" parsing arguments: no username\n");
   printf("\nusage : %s username password\n\n",argv[0]);
   _exit(2);
 }
 printf(" parsing arguments: POP username is '%s'\n",argv[1]);
 if (!argv[2]) {
   printf(" parsing arguments: no password\n");
   printf("\nusage : %s username password\n\n",argv[0]);
   _exit(2);
 }
 printf(" parsing arguments: POP password is '%s'\n",argv[2]);
 printf("\naction: parsing arguments successful\n");
#else
 if (!argv[1]) _exit(2);
#endif

 /* read the ldap control files */
 if (chdir(auto_qmail) == -1) {
#ifdef QLDAPDEBUG
   printf(" ldap checkpassword \t: unable to chdir to control file directory\n");
#endif
   _exit(1);
   }
 get_qldap_controls();

#ifdef QLDAPDEBUG
 login = argv[1];
 entredpassword = argv[2];
#else

 uplen = 0;
 for (;;)
  {
   do r = read(3,up + uplen,sizeof(up) - uplen);
   while ((r == -1) && (errno == EINTR));
   if (r == -1) _exit(111);
   if (r == 0) break;
   uplen += r;
   if (uplen >= sizeof(up)) _exit(1);
  }
 close(3);

 i = 0;
 login = up + i;
 while (up[i++]) if (i == uplen) _exit(2);
 entredpassword = up + i;
 if (i == uplen) _exit(2);
 while (up[i++]) if (i == uplen) _exit(2);

#endif

 /* do the ldap lookup based on the POP username */
 if(qldap_get(login, &password, &uid, &gid, &homedir) ) {

#ifdef LOOK_UP_PASSWD /* check for password and stuff in passwd */
 #ifdef QLDAPDEBUG
    printf("\naction: ldap lookup not successful\n");
    printf("\naction: try to get password from passwd-file\n\n");
 #endif
    pw = getpwnam(login);
    if (!pw) {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' not found\n",login);
  #endif
      _exit(1); /* XXX: unfortunately getpwnam() hides temporary errors */
    } else {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' found\n",login);
  #endif
    }

 #ifdef PW_SHADOW
    spw = getspnam(login);
    if (!spw) {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' not found in shadow file\n",login);
  #endif
      _exit(1); /* XXX: again, temp hidden */
    } else {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' found in shadow file\n",login);
  #endif
    }
    if (!stralloc_copys(&password, spw->sp_pwdp) ) _exit(QLX_NOMEM);
 #else
 #ifdef AIX
    spw = getuserpw(login);
    if (!spw) {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' not found in shadow file\n",login);
  #endif
      _exit(1); /* XXX: and again */
    } else {
  #ifdef QLDAPDEBUG
     printf(" passwd-file lookup \t: login '%s' found in shadow file\n",login);
  #endif
    }
    if (!stralloc_copys(&password, spw->upw_passwd) ) _exit(QLX_NOMEM);
 #else
    if (!stralloc_copys(&password, pw->pw_passwd) ) _exit(QLX_NOMEM);
 #endif
 #endif
    if (!stralloc_0(&password) ) _exit(QLX_NOMEM);
  #ifdef QLDAPDEBUG 
    printf(" passwd-file lookup \t: found password '%s'\n", password.s);
  #endif

    gid = pw->pw_gid;
  #ifdef QLDAPDEBUG
    printf(" passwd-file lookup \t: GID succeeded for '%u'\n",gid );
  #endif
    uid = pw->pw_uid;
  #ifdef QLDAPDEBUG
    printf(" passwd-file lookup \t: UID succeeded for '%u'\n",uid );
  #endif

    if (!stralloc_copys(&homedir, pw->pw_dir) ) _exit(QLX_NOMEM);
    if (homedir.s[homedir.len -1] != '/') 
       if (!stralloc_cats(&homedir, "/") ) _exit(QLX_NOMEM);
    if (!stralloc_cat(&homedir, &qldap_passwdappend) ) _exit(QLX_NOMEM);
    if (!stralloc_0(&homedir) ) _exit(QLX_NOMEM);
  #ifdef QLDAPDEBUG
    printf(" passwd-file lookup \t: homedir path is '%s'\n",homedir.s);
  #endif

 #ifdef QLDAPDEBUG
    printf("\naction: get password from passwd-file succeeded\n");
 #endif

#else /* do not check in passwd file */
   _exit(1);
#endif
 }

 /* compare the password given by user and the stored one */
#ifdef QLDAPDEBUG
   printf("\naction: comparing passwords\n\n");
#endif

 if (password.s[0] == '{') { /* hashed */
#ifdef QLDAPDEBUG
   printf(" comparing passwords \t: password is encrypted with an hash function\n");
   printf(" comparing passwords \t: found value '%s'\n",password.s);
#endif
   /* MD4 */
   if (!str_diffn("{MD4}", password.s, 5) ) {
      shift = 5;
      MD4DataBase64(entredpassword,strlen(entredpassword),hashed,sizeof(hashed));
#ifdef QLDAPDEBUG
      printf(" comparing passwords \t: calculated  '{MD4}%s'\n",hashed);
#endif
   } else if (!str_diffn("{MD5}", password.s, 5) ) {
   /* MD5 */
      shift = 5;
      MD5DataBase64(entredpassword,strlen(entredpassword),hashed,sizeof(hashed));
#ifdef QLDAPDEBUG
      printf(" comparing passwords \t: calculated  '{MD5}%s'\n",hashed);
#endif
   } else if (!str_diffn("{SHA}", password.s, 6) ) {
   /* SHA */
      shift = 6;
      SHA1DataBase64(entredpassword,strlen(entredpassword),hashed,sizeof(hashed));
#ifdef QLDAPDEBUG
      printf(" comparing passwords \t: calculated  '{SHA}%s'\n",hashed);
#endif
   } else  if (!str_diffn("{RMD160}", password.s, 8) ) {
   /* RMD160 */
      shift = 8;
      RMD160DataBase64(entredpassword,strlen(entredpassword),hashed,sizeof(hashed));
#ifdef QLDAPDEBUG
      printf(" comparing passwords \t: calculated  '{RMD160}%s'\n",hashed);
#endif
   } else {
   /* unknown hash function detected */ 
      shift = 0;
#ifdef QLDAPDEBUG
      printf(" comparing passwords \t: unknown hash function\n");
#endif
      _exit(1);
   }
   /* End getting correct hash-func hashed */
   if (!*password.s || str_diff(hashed,password.s+shift) ) {
#ifdef QLDAPDEBUG
     printf(" comparing passwords \t: compare failed, password are not equal\n");
#endif
     _exit(1);
     } else {
#ifdef QLDAPDEBUG
     printf(" comparing passwords \t: compare succeeded, passwords are equal\n");
#endif
     }

 } else { /* crypt or clear text */
#ifdef QLDAPDEBUG
   printf(" comparing passwords \t: password is crypt()ed or clear text\n");
   printf(" comparing passwords \t: found value '%s'\n",password.s);
#endif

 encrypted = crypt(entredpassword,password.s);
#ifdef QLDAPDEBUG
 printf(" comparing passwords \t: crypt()ed '%s'\n",encrypted);
#endif

   if (!*password.s || str_diff(password.s,encrypted) ) {
#ifdef QLDAPDEBUG
     printf(" comparing passwords \t: compare crypt failed, doing clear text compare\n");
#endif
     if (!*password.s || str_diff(password.s,entredpassword) ) {
#ifdef QLDAPDEBUG
       printf(" comparing passwords \t: clear text compare also failed\n");
#endif
       _exit(1);
     } else {
#ifdef QLDAPDEBUG
       printf(" comparing passwords \t: compare clear text succeeded, passwords are equal\n");
#endif
     }
   } else {
#ifdef QLDAPDEBUG
   printf(" comparing passwords \t: compare crypt succeeded, passwords are equal\n");
#endif
   }
 } /* end -- hashed or crypt/clear text */

#ifdef QLDAPDEBUG
   printf("\naction: comparing passwords done successful\n");
#endif

 for(i = 0; i < sizeof(up); i++) up[i] = 0;

#ifdef QLDAPDEBUG
   printf("\naction: doing set{gid|uid} and chdir(homedir)\n\n");
#endif
 /* set uid, gid, chdir to homedir of POP user */
 if (setgid(gid) == -1) {
#ifdef QLDAPDEBUG
   printf(" set{gid|uid} \t: setgid failed with '%i'\n",gid);
#endif
   _exit(1);
   } else {
#ifdef QLDAPDEBUG
   printf(" set{gid|uid} \t: setgid succeeded with '%i'\n",gid);
#endif
   }
 if (setuid(uid) == -1) {
#ifdef QLDAPDEBUG
   printf(" set{gid|uid} \t: setuid failed with '%i'\n",uid);
#endif
   _exit(1);
   } else {
#ifdef QLDAPDEBUG
   printf(" set{gid|uid} \t: setuid succeeded with '%i'\n",uid);
#endif
   }
 if (chdir(homedir.s) == -1) {
#ifdef QLDAPDEBUG
   printf(" chdir(homedir) \t: chdir failed with '%s'\n",homedir.s);
#endif
   _exit(111);
   } else {
#ifdef QLDAPDEBUG
   printf(" chdir(homedir) : chdir succeeded with '%s'\n",homedir.s);
#endif
   }

#ifdef QLDAPDEBUG
   printf("\naction: set{uid|gid} and chdir(homedir) done successful\n");
#endif

#ifndef QLDAPDEBUG
 /* set up the environment for the execution of qmail-pop3d */

 if (!env_put2("USER",login)) _exit(111);
 if (!env_put2("HOME",homedir.s)) _exit(111);

 execvp(argv[1],argv + 1);
#endif

 _exit(111);

}

