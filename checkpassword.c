#include "qmail-ldap.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <lber.h>
#include <ldap.h>
#include "control.h"
#include "stralloc.h"
#include "env.h"
#include "auto_usera.h"
#include "auto_uids.h"
#include "auto_qmail.h"
#include "fmt.h"
#include "check.h"
#include "case.h"
#include "qlx.h"
#include "compatibility.h"
#include "digest_md4.h"
#include "digest_md5.h"
#include "digest_rmd160.h"
#include "digest_sha1.h"
#include "str.h"
#include "select.h"
#include "ipalloc.h"
#include "dns.h"
#include "timeoutconn.h"
#include "byte.h"
#include "readwrite.h"

#ifdef AUTOHOMEDIRMAKE
#include "error.h"
#include "wait.h"
#endif

#define QLDAP_PORT LDAP_PORT

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
#include <pwd.h>
#ifdef PW_SHADOW
#include <shadow.h>
#endif
#ifdef AIX
#include <userpw.h>
#endif


extern int errno;
extern char *crypt();
extern char *malloc();

char up[513];
int uplen;

#ifdef QLDAPDEBUG

#include <stdio.h>
#define OUTPUT stderr
#define debug_msg fprintf

char *sa2s(stralloc *sa)
{
  if(! stralloc_0(sa) ) return "No memory";
  sa->len--;
  return sa->s;
}

#else
#define OUTPUT 0
void debug_msg( ) { ; }

char* sa2s(stralloc *sa) { return 0; }

#endif

static void forward_session(char *host, char *name, char *passwd);

/* initialize the string arrays, this uses DJB's libs */
stralloc    qldap_server = {0};
stralloc    qldap_basedn = {0};
stralloc    qldap_user = {0};
stralloc    qldap_password = {0};

stralloc    qldap_uid = {0};
stralloc    qldap_gid = {0};
stralloc    qldap_messagestore = {0};
stralloc    qldap_passwdappend = {0};
stralloc    qldap_me = {0};
#ifdef AUTOHOMEDIRMAKE
stralloc    qldap_dirmaker = {0};
#endif

int         qldap_localdelivery = 1;

/* init done */

/* read the various LDAP control files */

void get_qldap_controls()
{

   debug_msg(OUTPUT,"\naction: reading control files\n\n");

   if (control_rldef(&qldap_server,"control/ldapserver",0,(char *) 0) != 1) {
      debug_msg(OUTPUT," unable to read \t: control/ldapserver\n exit\n");
      _exit(1);
   }
   if (!stralloc_0(&qldap_server)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/ldapserver \t: %s\n",qldap_server.s);

   if (control_rldef(&qldap_basedn,"control/ldapbasedn",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_basedn)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/ldapbasedn \t: %s\n",qldap_basedn.s);

   if (control_rldef(&qldap_user,"control/ldaplogin",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_user)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/ldaplogin \t: %s\n",qldap_user.s);

   if (control_rldef(&qldap_password,"control/ldappassword",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_password)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/ldappassword \t: %s\n",qldap_password.s);

   if (control_readint(&qldap_localdelivery,"control/ldaplocaldelivery") == -1) _exit(1);
   debug_msg(OUTPUT," control/ldaplocaldelivery \t: %i\n", qldap_localdelivery);
	
   if (control_rldef(&qldap_uid,"control/ldapuid",0,"") == -1) _exit(1);
   debug_msg(OUTPUT," control/ldapuid \t: %s\n",sa2s(&qldap_uid) );
   
   if (control_rldef(&qldap_gid,"control/ldapgid",0,"") == -1) _exit(1);
   debug_msg(OUTPUT," control/ldapgid \t: %s\n",sa2s(&qldap_gid) );

   if (control_rldef(&qldap_messagestore,"control/ldapmessagestore",0,"") == -1) _exit(1);
   debug_msg(OUTPUT," control/ldapmessagestore: %s\n",sa2s(&qldap_messagestore) );

   if (control_rldef(&qldap_passwdappend,"control/ldappasswdappend",0,"./") == -1) 
   debug_msg(OUTPUT," control/ldappasswdappend: %s\n",sa2s(&qldap_passwdappend) );

   if (control_rldef(&qldap_me,"control/me",0,"") == -1) _exit(1);
   if (!stralloc_0(&qldap_me)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/me\t\t: %s\n",qldap_me.s);

#ifdef AUTOHOMEDIRMAKE
   if (control_rldef(&qldap_dirmaker,"control/dirmaker",0,(char *) 0) == -1) _exit(1);
   if (!stralloc_0(&qldap_dirmaker)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," control/dirmaker \t: %s\n",sa2s(&qldap_dirmaker) );
#endif

   debug_msg(OUTPUT,"\naction: reading control files done successful\n");
}

stralloc password={0};
stralloc homedir={0};

int qldap_get( char *login, char *passwd, unsigned int *uid, unsigned int *gid )
{
   LDAP           *ld;
   LDAPMessage    *res, *msg;
   char           *dn,
                  **vals,
                  *attrs[] = {  LDAP_UID,
                                LDAP_PASSWD,
                                LDAP_QMAILUID,
                                LDAP_QMAILGID,
										  LDAP_ISACTIVE,
										  LDAP_MAILHOST,
                                LDAP_MAILSTORE, NULL };

   int            rc,
                  version,
                  num_entries = 0;

   stralloc       filter = {0};


   debug_msg(OUTPUT,"\naction: doing ldap lookup\n\n");
   /* lower case the POP user name before we do the      *
    * check for illegal chars                            */
   case_lowers(login);

   /* check the login uid for illegal characters         *
    * only [a-z][0-9][.-_] are allowed                   *
    * because all other stuff would kill the LDAP search */
   if ( !chck_users(login) ) {
     debug_msg(OUTPUT," check for illegal characters \t: failed, POP username contains illegal characters\n");
     _exit(1);
   } else {
     debug_msg(OUTPUT," check for illegal characters \t: succeeded\n");
   }

   /* initialize the LDAP connection and get a handle */
   if ( (ld = ldap_init(qldap_server.s,QLDAP_PORT)) == NULL ) {
     debug_msg(OUTPUT," initialize ldap connection \t: failed, problem in ldap library?\n");
     _exit(1);
   } else {
     debug_msg(OUTPUT," initialize ldap connection\t: succeeded\n");
   }

   /* set LDAP connection options (only with Mozilla LDAP SDK) */
#ifdef LDAP_OPT_PROTOCOL_VERSION
   version = LDAP_VERSION2;
   if ( ldap_set_option(ld,LDAP_OPT_PROTOCOL_VERSION,&version) != LDAP_SUCCESS ) {
     debug_msg(OUTPUT," setting ldap connection options\t: failed, are you using Mozilla LDAP SDK?\n");
     _exit(1);
   } else {
     debug_msg(OUTPUT," setting ldap connection options: succeeded\n");
   }
#endif

   /* connect to the LDAP server */
   if ( (rc = ldap_simple_bind_s(ld,qldap_user.s,qldap_password.s)) != LDAP_SUCCESS ) {
     debug_msg(OUTPUT," connecting to ldap server\t: failed, %s\n",ldap_err2string(rc));
     _exit(1);
   } else {
     debug_msg(OUTPUT," connecting to ldap server\t: succeeded\n");
   }

   /* build the search string for the login uid */
   if (!stralloc_copys(&filter,"(uid=" ) ) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,login)) _exit(QLX_NOMEM);
   if (!stralloc_cats(&filter,")")) _exit(QLX_NOMEM);
   if (!stralloc_0(&filter)) _exit(QLX_NOMEM);

   debug_msg(OUTPUT," building ldap search string\t: '%s'\n",filter.s);
   
   /* do the search for the login uid */
   if ( (rc = ldap_search_s(ld,qldap_basedn.s,LDAP_SCOPE_SUBTREE,filter.s,attrs,0,&res)) != LDAP_SUCCESS ) {
      debug_msg(OUTPUT," ldap search on server\t: failed, %s\n",ldap_err2string(rc));
      _exit(1);
   } else {
      debug_msg(OUTPUT," ldap search on server\t: succeeded");
   }

   /* count the results, we must have exactly one */
   if ( (num_entries = ldap_count_entries(ld,res)) != 1) {
     debug_msg(OUTPUT,", but returned no match\n");
     return 1;
   } else {
     debug_msg(OUTPUT,", found one match\n");
   }

   /* go to the first entry */
   msg = ldap_first_entry(ld,res);

   /* check if the ldap entry is active */
   if ( (vals = ldap_get_values(ld,msg,LDAP_ISACTIVE)) != NULL ) {
      debug_msg(OUTPUT," accountStatus is\t: %s\n", vals[0]);
      if ( !str_diff(ISACTIVE_BOUNCE, vals[0]) ) _exit(1);
      if ( !str_diff(ISACTIVE_NOPOP, vals[0]) ) _exit(1);
   }
#ifdef QLDAP_CLUSTER
   /* check if the I'm the right host */
   if ( (vals = ldap_get_values(ld,msg,LDAP_MAILHOST)) != NULL ) {
      debug_msg(OUTPUT," mailHost is\t\t: %s (I'm %s)\n", vals[0], qldap_me.s);
      if ( str_diff(qldap_me.s, vals[0]) ) {
		  	/* hostname is different, so I reconnect */
#ifdef QLDAPDEBUG
         debug_msg(OUTPUT, "\t\t\t  would connect to new host %s\n", vals[0]);
#else
			forward_session(vals[0], login, passwd);
#endif
			/* that's it */
		}
   }
#endif
   /* get the dn and free it (we dont need it, to prevent memory leaks) *
    * but first try to rebind with the password (only if compiled with  *
    * QLDAP_BIND.                                                       */
   dn = ldap_get_dn(ld,msg);
#ifdef QLDAP_BIND
   if ( dn == NULL ) _exit(1);
   /* add re-bind here */
   if ( (rc = ldap_simple_bind_s(ld,dn,passwd)) != LDAP_SUCCESS) {
      debug_msg(OUTPUT," rebinding with dn %s \t: failed, %s\n",dn,ldap_err2string(rc));
#ifdef LDAP_OPT_PROTOCOL_VERSION /* (only with Mozilla LDAP SDK) */
      ldap_memfree(dn);
#else
      free(dn);
#endif
      return 1;
   }
   debug_msg(OUTPUT," rebinding with dn %s \t: succeeded\n", dn);
#endif
#ifdef LDAP_OPT_PROTOCOL_VERSION /* (only with Mozilla LDAP SDK) */
   if ( dn != NULL ) ldap_memfree(dn);
#else
   if ( dn != NULL ) free(dn);
#endif

#ifndef QLDAP_BIND
   /* go through the attributes and set the proper args for qmail-pop3d */
   /* get the stored and (hopefully) encrypted password */
   if ( (vals = ldap_get_values(ld,msg,LDAP_PASSWD)) != NULL ) {
      if (!stralloc_copys(&password, vals[0])) _exit(QLX_NOMEM);
      if (!stralloc_0(&password)) _exit(QLX_NOMEM);
      debug_msg(OUTPUT," ldap search results \t: found password '%s'\n", vals[0]);
   } else {
      debug_msg(OUTPUT," ldap search results \t: no password\n");
      _exit(1);
   }
   ldap_value_free(vals);
#endif

   /* get the UID for setuid() for POP retrieval */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILUID)) != NULL ) {
      *uid = chck_ids(vals[0]);
      if (PW_MIN > *uid ) {
         debug_msg(OUTPUT," ldap search results \t: UID failed for '%s'\n",vals[0]);
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: UID succeeded for '%s'\n",vals[0]);
      }
   } else { /* default */
      if (!qldap_uid.len) {
         debug_msg(OUTPUT," ldap search results \t: no UID found and control/ldapuid empty\n");
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: no UID found, taking control/ldapuid\n");
      }
      *uid = chck_idb(qldap_uid.s,qldap_uid.len);
      if (PW_MIN > *uid ) {
         debug_msg(OUTPUT," ldap search results \t: control/ldapuid check failed for '%s'\n",sa2s(&qldap_uid) );
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: control/ldapuid check succeeded for '%s'\n",sa2s(&qldap_uid) );
      }
   }
   ldap_value_free(vals);

   /* get the GID for setgid() for POP retrieval */
   if ( (vals = ldap_get_values(ld,msg,LDAP_QMAILGID)) != NULL ) {
      *gid = chck_ids(vals[0]);
      if ( PW_MIN > *gid ) {
         debug_msg(OUTPUT," ldap search results \t: GID failed for '%s'\n",vals[0]);
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: GID succeeded for '%s'\n",vals[0]);
      }
   } else { /* default */
      if (!qldap_gid.len) {
         debug_msg(OUTPUT," ldap search results \t: no GID found, and control/ldapgid empty\n");
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: no GID found, taking control/ldapgid\n");
      }
      *gid = chck_idb(qldap_gid.s,qldap_gid.len);
      if ( PW_MIN > *gid ) {
         debug_msg(OUTPUT," ldap search results \t: control/ldapgid check failed for '%s'\n",sa2s(&qldap_gid) );
         _exit(1);
      } else {
         debug_msg(OUTPUT," ldap search results \t: control/ldapgid check succeeded for '%s'\n",sa2s(&qldap_gid) );
      }
   }
   ldap_value_free(vals);

   /* get the path of the maildir for qmail-pop3d */
   if ( (vals = ldap_get_values(ld,msg,LDAP_MAILSTORE)) != NULL ) {
      if (vals[0][0] != '/') {   /* relative path */
            debug_msg(OUTPUT," ldap search results \t: maildir path is relative to messagestore\n");
         if (qldap_messagestore.s[0] != '/') {
            debug_msg(OUTPUT," ldap search results \t: control/ldapmessagestore path does not begin with /\n");
            _exit(1);
         }
         if (qldap_messagestore.s[qldap_messagestore.len -1] != '/') {
            debug_msg(OUTPUT," ldap search results \t: control/ldapmessagepath does not end with /\n");
            _exit(1);
         }
         if (!stralloc_cats(&qldap_messagestore, vals[0])) _exit(QLX_NOMEM);
         if (!chck_pathb(qldap_messagestore.s,qldap_messagestore.len) ) {
            debug_msg(OUTPUT," ldap search results \t: combined maildir path contains illegal constructs\n");
            _exit(1);
         }
         if (qldap_messagestore.s[qldap_messagestore.len -1] != '/') {
            debug_msg(OUTPUT," ldap search results \t: combined maildir path does not end with /\n");
            _exit(1);
         }
         if (!stralloc_copy(&homedir,&qldap_messagestore)) _exit(QLX_NOMEM);
      } else {                   /* absolute path */
         debug_msg(OUTPUT," ldap search results \t: maildir path is absolute\n");
         if (!chck_paths(vals[0]) ) {
            debug_msg(OUTPUT," ldap search results \t: maildir path contains illegal constructs\n");
            _exit(1);
         }
         if (!stralloc_copys(&homedir, vals[0])) _exit(QLX_NOMEM);
         if (homedir.s[homedir.len -1] != '/') {
            debug_msg(OUTPUT," ldap search results \t: maildir path does not end with /\n");
            _exit(1);
         }
      }
   if (!stralloc_0(&homedir)) _exit(QLX_NOMEM);
   debug_msg(OUTPUT," ldap search results \t: maildir path is '%s'\n",homedir.s);

   } else {
      debug_msg(OUTPUT," ldap search results \t: no maildir path specified\n");
      _exit(1);
   }
   ldap_value_free(vals);

   debug_msg(OUTPUT,"\naction: ldap lookup done successful\n");
   return 0;
} /* end -- ldap lookup */

void main(argc,argv)
int argc;
char **argv;
{
 char hashed[100];
 char salt[33];
 char *login,
      *enteredpasswd,
      *encrypted;

#warning __do_not_remove_one_of_this_variables_all_are_somehow_used__
 unsigned int i, r,
              uid,
              gid,
              shift;


 struct passwd *pw;
#ifdef PW_SHADOW
 struct spwd *spw;
#endif
#ifdef AIX
 struct userpw *spw;
#endif

#ifdef QLDAPDEBUG
 debug_msg(OUTPUT,"\naction: parsing arguments\n\n");
 if (!argv[1]) {
   debug_msg(OUTPUT," parsing arguments: no username\n");
   debug_msg(OUTPUT,"\nusage : %s username password\n\n",argv[0]);
   _exit(2);
 }
 debug_msg(OUTPUT," parsing arguments: POP username is '%s'\n",argv[1]);
 if (!argv[2]) {
   debug_msg(OUTPUT," parsing arguments: no password\n");
   debug_msg(OUTPUT,"\nusage : %s username password\n\n",argv[0]);
   _exit(2);
 }
 debug_msg(OUTPUT," parsing arguments: POP password is '%s'\n",argv[2]);
 debug_msg(OUTPUT,"\naction: parsing arguments successful\n");
#else
 if (!argv[1]) _exit(2);
#endif

 /* read the ldap control files */
 if (chdir(auto_qmail) == -1) {
   debug_msg(OUTPUT," ldap checkpassword \t: unable to chdir to control file directory\n");
   _exit(1);
 }
 get_qldap_controls();

#ifdef QLDAPDEBUG
 login = argv[1];
 enteredpasswd = argv[2];
 if ( argc == 4 ) {
   stralloc_copys(&qldap_me, argv[3]);
   stralloc_0(&qldap_me);
 }
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
 enteredpasswd = up + i;
 if (i == uplen) _exit(2);
 while (up[i++]) if (i == uplen) _exit(2);

#endif

 /* do the ldap lookup based on the POP username */
 if(qldap_get(login, enteredpasswd, &uid, &gid) ) {
   if (qldap_localdelivery == 1 ) {

 /* check for password and stuff in passwd */
    debug_msg(OUTPUT,"\naction: ldap lookup not successful\n");
    debug_msg(OUTPUT,"\naction: try to get password from passwd-file\n\n");
    pw = getpwnam(login);
    if (!pw) {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' not found\n",login);
      _exit(1); /* XXX: unfortunately getpwnam() hides temporary errors */
    } else {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' found\n",login);
    }

#ifdef PW_SHADOW
    spw = getspnam(login);
    if (!spw) {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' not found in shadow file\n",login);
      _exit(1); /* XXX: again, temp hidden */
    } else {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' found in shadow file\n",login);
    }
    if (!stralloc_copys(&password, spw->sp_pwdp) ) _exit(QLX_NOMEM);
#else
#ifdef AIX
    spw = getuserpw(login);
    if (!spw) {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' not found in shadow file\n",login);
      _exit(1); /* XXX: and again */
    } else {
      debug_msg(OUTPUT," passwd-file lookup \t: login '%s' found in shadow file\n",login);
    }
    if (!stralloc_copys(&password, spw->upw_passwd) ) _exit(QLX_NOMEM);
#else
    if (!stralloc_copys(&password, pw->pw_passwd) ) _exit(QLX_NOMEM);
#endif /* AIX */
#endif /* PW_SHADOW */
    if (!stralloc_0(&password) ) _exit(QLX_NOMEM);
    debug_msg(OUTPUT," passwd-file lookup \t: found password '%s'\n", password.s);

    gid = pw->pw_gid;
    debug_msg(OUTPUT," passwd-file lookup \t: GID succeeded for '%u'\n",gid );
  
    uid = pw->pw_uid;
    debug_msg(OUTPUT," passwd-file lookup \t: UID succeeded for '%u'\n",uid );
  
    if (!stralloc_copys(&homedir, pw->pw_dir) ) _exit(QLX_NOMEM);
    if (homedir.s[homedir.len -1] != '/') 
       if (!stralloc_cats(&homedir, "/") ) _exit(QLX_NOMEM);
    if (!stralloc_cat(&homedir, &qldap_passwdappend) ) _exit(QLX_NOMEM);
    if (!stralloc_0(&homedir) ) _exit(QLX_NOMEM);
    debug_msg(OUTPUT," passwd-file lookup \t: homedir path is '%s'\n",homedir.s);
  
    debug_msg(OUTPUT,"\naction: get password from passwd-file succeeded\n");
#ifdef QLDAP_BIND
    encrypted = crypt(enteredpasswd,password.s);
    debug_msg(OUTPUT," comparing passwords \t: crypt()ed '%s'\n",encrypted);
    if (!*password.s || str_diff(password.s,encrypted) ) {
      debug_msg(OUTPUT," comparing passwords \t: compare crypt failed\n");
      _exit(1);
    }
    debug_msg(OUTPUT," comparing passwords \t: compare crypt succeeded\n");
#endif

  } else { /* do not check in passwd file */
    debug_msg(OUTPUT," nothing found, giving up\n");
    _exit(1);
  }
 }
#ifndef QLDAP_BIND
 /* compare the password given by user and the stored one */
   debug_msg(OUTPUT,"\naction: comparing passwords\n\n");

 if (password.s[0] == '{') { /* hashed */
   debug_msg(OUTPUT," comparing passwords \t: password is encrypted with an hash function\n");
   debug_msg(OUTPUT," comparing passwords \t: found value '%s'\n",password.s);
   if (!str_diffn("{crypt}", password.s, 7) ) {
   /* CRYPT */
      shift = 7;
      encrypted=crypt(enteredpasswd,password.s+shift);
      str_copy(hashed,encrypted);
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{crypt}%s'\n",hashed);
   } else if (!str_diffn("{MD4}", password.s, 5) ) {
   /* MD4 */
      shift = 5;
      MD4DataBase64(enteredpasswd,strlen(enteredpasswd),hashed,sizeof(hashed));
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{MD4}%s'\n",hashed);
   } else if (!str_diffn("{MD5}", password.s, 5) ) {
   /* MD5 */
      shift = 5;
      MD5DataBase64(enteredpasswd,strlen(enteredpasswd),hashed,sizeof(hashed));
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{MD5}%s'\n",hashed);
   } else if (!str_diffn("{NS-MTA-MD5}", password.s, 12) ) {
   /* NS-MTA-MD5 */
      shift = 12;
      if (!strlen(password.s) == 76) {
      debug_msg(OUTPUT," comparing passwords \t: NS-MTA-MD5 password string length mismatch\n");
      _exit(1); } /* boom */
      strncpy(salt,&password.s[44],32);
      salt[32] = 0;
      ns_mta_hash_alg(hashed,salt,enteredpasswd);
      strncpy(&hashed[32],salt,33);
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{NS-MTA-MD5}%s'\n",hashed);
   } else if (!str_diffn("{SHA}", password.s, 5) ) {
   /* SHA */
      shift = 5;
      SHA1DataBase64(enteredpasswd,strlen(enteredpasswd),hashed,sizeof(hashed));
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{SHA}%s'\n",hashed);
   } else  if (!str_diffn("{RMD160}", password.s, 8) ) {
   /* RMD160 */
      shift = 8;
      RMD160DataBase64(enteredpasswd,strlen(enteredpasswd),hashed,sizeof(hashed));
      debug_msg(OUTPUT," comparing passwords \t: calculated  '{RMD160}%s'\n",hashed);
   } else {
   /* unknown hash function detected */ 
      shift = 0;
      debug_msg(OUTPUT," comparing passwords \t: unknown hash function\n");
      _exit(1);
   }
   /* End getting correct hash-func hashed */
   if (!*password.s || str_diff(hashed,password.s+shift) ) {
     debug_msg(OUTPUT," comparing passwords \t: compare failed, password are not equal\n");
     _exit(1);
   } else {
     debug_msg(OUTPUT," comparing passwords \t: compare succeeded, passwords are equal\n");
   }
 } else { /* crypt or clear text */
   debug_msg(OUTPUT," comparing passwords \t: password is crypt()ed or clear text\n");
   debug_msg(OUTPUT," comparing passwords \t: found value '%s'\n",password.s);

#warning ___remove_crypt_code_@_clear_text_compare___
   encrypted = crypt(enteredpasswd,password.s);
   debug_msg(OUTPUT," comparing passwords \t: crypt()ed '%s'\n",encrypted);
   if (!*password.s || str_diff(password.s,encrypted) ) {
     debug_msg(OUTPUT," comparing passwords \t: compare crypt failed, doing clear text compare\n");
     if (!*password.s || str_diff(password.s,enteredpasswd) ) {
       debug_msg(OUTPUT," comparing passwords \t: clear text compare also failed\n");
       _exit(1);
     } else {
       debug_msg(OUTPUT," comparing passwords \t: compare clear text succeeded, passwords are equal\n");
     }
   } else {
     debug_msg(OUTPUT," comparing passwords \t: compare crypt succeeded, passwords are equal\n");
   }
 } /* end -- hashed or crypt/clear text */
 debug_msg(OUTPUT,"\naction: comparing passwords done successful\n");
#endif /* QLDAP_BIND */

 for(i = 0; i < sizeof(up); i++) up[i] = 0;

 debug_msg(OUTPUT,"\naction: doing set{gid|uid} and chdir(homedir)\n\n");

 /* set uid, gid, chdir to homedir of POP user */
 if (setgid(gid) == -1) {
   debug_msg(OUTPUT," set{gid|uid} \t: setgid failed with '%i'\n",gid);
   _exit(1);
 } else {
   debug_msg(OUTPUT," set{gid|uid} \t: setgid succeeded with '%i'\n",gid);
 }
 if (setuid(uid) == -1) {
   debug_msg(OUTPUT," set{gid|uid} \t: setuid failed with '%i'\n",uid);
   _exit(1);
 } else {
   debug_msg(OUTPUT," set{gid|uid} \t: setuid succeeded with '%i'\n",uid);
 }
 if (!getuid()) {
   debug_msg(OUTPUT," ABORTING, ROOT IS NOT ALLOWED!!!!\n");
   _exit(1);
 }

 if (chdir(homedir.s) == -1) {
#ifdef AUTOHOMEDIRMAKE
   if (errno == error_noent && qldap_dirmaker.len > 1) {
     /* do the auto homedir creation */
     int child;
     char *(dirargs[4]);
     int wstat;

     if (!stralloc_0(&qldap_dirmaker)) _exit(QLX_NOMEM);

     switch(child = fork()) {
     case -1:
       debug_msg(OUTPUT," create homedir : fork failed\n");
       _exit(11);
     case 0:
       dirargs[0] = qldap_dirmaker.s; dirargs[1] = homedir.s;
       dirargs[2] = argv[2]; dirargs[3] = 0;
       execv(*dirargs,dirargs);
       debug_msg(OUTPUT," create homedir : exec '%s' failed with %s\n", dirargs[0],error_str(errno));
       _exit(11);
     }

     wait_pid(&wstat,child);
     if (wait_crashed(wstat)) {
       debug_msg(OUTPUT," create homedir : %s crashed\n", qldap_dirmaker.s);
       _exit(11);
     }
     switch(wait_exitcode(wstat)) {
     case 0: break;
     default:
       debug_msg(OUTPUT," create homedir : %s's exitcode is not zero\n", qldap_dirmaker.s);
       _exit(11);
     }
     debug_msg(OUTPUT," create homedir : so far everything went fine\n");
     if (chdir(homedir.s) == -1)
       debug_msg(OUTPUT," chdir(homedir) : chdir failed with '%s'; %s\n",homedir.s,error_str(errno));
     else
       debug_msg(OUTPUT," chdir(homedir) : chdir succeeded with '%s'\n",homedir.s);
   } else {
#endif
   debug_msg(OUTPUT," chdir(homedir) : chdir failed with '%s'; %s\n",homedir.s,error_str(errno));
   _exit(111);
#ifdef AUTOHOMEDIRMAKE
   }
#endif
 } else {
   debug_msg(OUTPUT," chdir(homedir) : chdir succeeded with '%s'\n",homedir.s);
 }
 debug_msg(OUTPUT,"\naction: set{uid|gid} and chdir(homedir) done successful\n");

#ifndef QLDAPDEBUG
 /* set up the environment for the execution of qmail-pop3d */

 if (!env_put2("USER",login)) _exit(111);
 if (!env_put2("HOME",homedir.s)) _exit(111);

 execvp(argv[1],argv + 1);
#endif

 _exit(111);

}

static void copyloop(int infd, int outfd, int timeout)
{
	fd_set iofds;
	fd_set savedfds;
	int maxfd;			/* Maximum numbered fd used */
	struct timeval tv;
	unsigned long bytes;
	char buf[4096];

	/* Set up timeout */
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	/* file descriptor bits */
	FD_ZERO(&savedfds);
	FD_SET(infd, &savedfds);
	FD_SET(outfd, &savedfds);

	if (infd > outfd) {
		maxfd = infd;
	} else {
		maxfd = outfd;
	}

	debug_msg(OUTPUT, "Entering copyloop() - timeout is %d\n", timeout);
	while(1) {
		//memcpy(&iofds, &savedfds, sizeof(iofds));
		byte_copy(&iofds, sizeof(iofds), &savedfds);
		
		if ( select( maxfd + 1, &iofds, (fd_set *)0, (fd_set *)0, &tv)
			  <= 0 ) {
			break;
		}

		if(FD_ISSET(infd, &iofds)) {
			if((bytes = read(infd, buf, sizeof(buf))) <= 0)
				break;
			if(write(outfd, buf, bytes) != bytes)
				break;
		}
		if(FD_ISSET(outfd, &iofds)) {
			if((bytes = read(outfd, buf, sizeof(buf))) <= 0)
				break;
			if(write(infd, buf, bytes) != bytes)
				break;
		}
	}
	debug_msg(OUTPUT, "Leaving main copyloop\n");

	shutdown(infd,0);
	shutdown(outfd,0);
	close(infd);
	close(outfd);
	return;
}

static void forward_session(char *host, char *name, char *passwd)
{
	ipalloc ip = {0};
	stralloc host_stralloc = {0};
	int ffd;
	int timeout = 60;
	int ctimeout = 20;
	
	if (!stralloc_copys(&host_stralloc, host)) _exit(QLX_NOMEM);

	switch (dns_ip(&ip,&host_stralloc)) {
		case DNS_MEM:
			debug_msg(OUTPUT, "Out of memory\n");
			_exit(QLX_NOMEM);
		case DNS_SOFT:
			debug_msg(OUTPUT, "Sorry, I couldn't find any host by that name.\n");
			_exit(33);
		case DNS_HARD:
			debug_msg(OUTPUT, "There is no host named '%s'\n", host);
			_exit(30);
		case 1:
			if (ip.len <= 0) {
				debug_msg(OUTPUT, "Sorry, I couldn't find any host by that name.\n");
				_exit(33);
			}
	}
	if ( ip.len != 1 ) {
		debug_msg(OUTPUT, "Too many hosts found ???\n");
		_exit(35);
	}
	
	ffd = socket(AF_INET,SOCK_STREAM,0);
	if (ffd == -1) {
		debug_msg(OUTPUT, "socket made a booboo\n");
		_exit(36);
	}
	
	if (timeoutconn(ffd,&ip.ix[0].ip,110,ctimeout) != 0) {
		debug_msg(OUTPUT, "timeoutconn made a booboo\n");
		_exit(37);
	}
	
	/* We have a connection, first send user and pass */
	write(ffd, "user ", 5); write(ffd, name, str_len(name) ); write(ffd, "\n", 1);
	write(ffd, "pass ", 5); write(ffd, passwd, str_len(passwd) ); write(ffd, "\n",1);
	/* Now the other server can handle this */
	copyloop(0, ffd, timeout);
	
	_exit(0);
}
	
