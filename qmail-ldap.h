#ifndef _QMAIL_LDAP_H_
#define _QMAIL_LDAP_H_

/* this is the "catch all" string
 * ATTN: escape the string correctly, remember
 * '(', ')', '\', and '*' have to be escaped with '\'
 */
#define LDAP_CATCH_ALL "catchall"

/* triger level for quotawarning (0-100) */
#define QUOTA_WARNING_LEVEL 70

/* reply subject for mails without subjects. */
#define REPLY_SUBJ "Your Mail"
/* timeout for one delivery per sender */
#define REPLY_TIMEOUT 1209600 /* 1 Week */
/* default content type (don't forget the '\n' at the end) */
#define REPLY_CT "text/plain; charset=utf-8\n"
/* default content transfer encoding (don't forget the '\n' at the end) */
#define REPLY_CTE "8bit\n"

/* the maximum and minimum uid allowed */
#define UID_MIN 100
#define UID_MAX 65535

/* the maximum and minimum gid allowed */
#define GID_MIN 100
#define GID_MAX 65535

/* if the sanitycheck function should be less restricted for
 * program pathes, this means especially that most special chars
 * of the shell are allowed (like &, &, ;, and <,|,>)
 * You should know what you are doing when disallowing this  */
/* 1 = restriced sanitycheck; 0 = less restriced sanitycheck */
#define RESTRICT_PROG 1

/* ALIASDEVNULL replacement for the std. aliasempty for user with
 * neither homeDirectory nor mailMessageStore defined */
#define ALIASDEVNULL "|echo \"Unable to deliver mail: account incorrectly configured. (#5.3.5)\"; exit 100"
/* just echo a warning to notify the user and exit 100.
 * It's up to the reader to write a simple script with
 * postmaster notification. */

/* Default ldap search timeout. In seconds */
#define	QLDAP_TIMEOUT		30

/* This needs DASH_EXT option.
 * Limit dash ext to the first DASH_EXT_LEVELS extensions.
 * Search only for (DASH_EXT_LEVELS = 4):
 * a-b-c-d-e-f-g-...@foobar.com
 * a-b-c-d-catchall@foobar.com
 * a-b-c-catchall@foobar.com
 * a-b-catchall@foobar.com
 * a-catchall@foobar.com
 * catchall@foobar.com
 */
#define DASH_EXT_LEVELS 4

/*********************************************************************
        ldap variables used in qmail-lspawn and auth_*
*********************************************************************/
#define LDAP_MAIL		"mail"
#define LDAP_MAILALTERNATE	"mailAlternateAddress"
#define LDAP_QMAILUID		"qmailUID"
#define LDAP_QMAILGID		"qmailGID"
#define LDAP_MAILSTORE		"mailMessageStore"
#define LDAP_HOMEDIR		"homeDirectory"
#define LDAP_QUOTA		"mailQuota"
#define LDAP_QUOTA_SIZE		"mailQuotaSize"
#define LDAP_QUOTA_COUNT	"mailQuotaCount"
#define LDAP_MAXMSIZE		"mailSizeMax"
#define LDAP_FORWARDS		"mailForwardingAddress"
#define LDAP_PROGRAM		"deliveryProgramPath"
#define LDAP_MAILHOST		"mailHost"
#define LDAP_MODE		"deliveryMode"
#define LDAP_REPLYTEXT		"mailReplyText"
#define LDAP_DOTMODE		"qmailDotMode"
#define LDAP_UID		"uid"
#define LDAP_PASSWD		"userPassword"
#define LDAP_OBJECTCLASS	"objectClass"
#define LDAP_ISACTIVE		"accountStatus"
#define LDAP_PURGE		"qmailAccountPurge"

#define DOTMODE_LDAPONLY 	"ldaponly"
#define DOTMODE_LDAPWITHPROG	"ldapwithprog"
#define DOTMODE_DOTONLY		"dotonly"
#define DOTMODE_BOTH		"both"
#define DOTMODE_NONE		"none"

#define MODE_FONLY		"forwardonly"
#define MODE_NOFORWARD		"noforward"
#define MODE_NOMBOX		"nombox"
#define MODE_NOLOCAL		"nolocal"
#define MODE_NOPROG		"noprogram"
#define MODE_REPLY		"reply"
/* these are silently ignored */
#define MODE_LOCAL		"local"
#define MODE_FORWARD		"forward"
#define MODE_PROG		"program"
#define MODE_NOREPLY		"noreply"

#define ISACTIVE_BOUNCE		"disabled"
#define ISACTIVE_DELETE		"deleted"
#define ISACTIVE_NOACCESS	"noaccess"
#define ISACTIVE_ACTIVE		"active"

/*********************************************************************
        ldap variables used in qmail-group
*********************************************************************/
#define LDAP_GROUPMEMONLY	"membersonly"
#define LDAP_GROUPCONFIRM	"senderconfirm"
#define LDAP_GROUPCONFRIMTEXT	"confirmtext"
#define LDAP_GROUPMODERATTEXT	"moderatortext"
#define LDAP_GROUPMODERATDN	"dnmoderator"
#define LDAP_GROUPMODERAT822	"rfc822moderator"
#define LDAP_GROUPMEMBERDN	"dnmember"
#define LDAP_GROUPMEMBER822	"rfc822member"
#define LDAP_GROUPMEMBERFILTER	"filtermember"


/*********************************************************************
                 normaly you can stop editing here
*********************************************************************/
/* the same values as ints */
#define STATUS_DELETE		3
#define STATUS_BOUNCE		2
#define STATUS_NOACCESS		1
#define STATUS_OK 		0
#define STATUS_UNDEF 		-1

/* environment variables used between qmail-lspan and qmail-local
 * and some other tools
 */
#define ENV_HOMEDIRMAKE		"QLDAPAUTOHOMEDIRMAKE"

#define ENV_QUOTA		"MAILDIRQUOTA"
#define ENV_QUOTAWARNING 	"QMAILQUOTAWARNING"

#define ENV_DOTMODE		"QMAILDOTMODE"
#define ENV_MODE 		"QMAILMODE"
#define ENV_REPLYTEXT		"QMAILREPLYTEXT"
#define ENV_FORWARDS		"QMAILFORWARDS"
#define ENV_PROGRAM		"QMAILDELIVERYPROGRAM"

#define ENV_GROUP		"QLDAPGROUP"

/* qmail-local.c only */
#define DO_LDAP 	0x01
#define DO_DOT  	0x02
#define DO_BOTH 	(DO_LDAP | DO_DOT)

#endif
