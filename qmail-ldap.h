#ifndef _QMAIL_LDAP_H_
#define _QMAIL_LDAP_H_

/* this is the "catch all" string									*
 * ATTN: escape the string correctly, remember
 * '(', ')', '\', '*' and '\0' have to be escaped with '\'
 * Escaping is broken in OpenLDAP up to release 1.2.6, 1.2.7 is OK
 */
#define LDAP_CATCH_ALL "catchall"

/* triger level for quotawarning (0-100) */
#define QUOTA_WARNING_LEVEL 70

/* the maximum and minimum uid allowed */
#define UID_MIN 100
#define UID_MAX 65535

/* the maximum and minimum gid allowed */
#define GID_MIN 100
#define GID_MAX 65535

/* ldap variables used in qmail-lspawn and checkpassword */
#define LDAP_MAIL			"mail"
#define LDAP_MAILALTERNATE	"mailAlternateAddress"
#define LDAP_QMAILUID		"qmailUID"
#define LDAP_QMAILGID		"qmailGID"
#define LDAP_MAILSTORE		"mailMessageStore"
#define LDAP_QUOTA			"mailQuota"
#define LDAP_FORWARDS		"mailForwardingAddress"
#define LDAP_PROGRAM		"deliveryProgramPath"
#define LDAP_MAILHOST		"mailHost"
#define LDAP_MODE			"deliveryMode"
#define LDAP_REPLYTEXT		"mailReplyText"
#define LDAP_DOTMODE		"qmailDotMode"
#define LDAP_UID			"uid"
#define LDAP_PASSWD			"userPassword"
#define LDAP_ISACTIVE		"accountStatus"

#define ISACTIVE_BOUNCE	"disabled"
#define ISACTIVE_NOPOP	"nopop"
#define ISACTIVE_ACTIVE	"active"
/* normaly you can stop editing here */
/* the same values as ints */
#define STATUS_BOUNCE	2
#define STATUS_NOPOP	1
#define STATUS_OK 		0
#define STATUS_UNDEF 	-1

/* environment variables used between qmail-lspan and qmail-local
 * and some other tools
 */
#define ENV_HOMEDIRMAKE		"QLDAPAUTOHOMEDIRMAKE"

#define ENV_QUOTA			"QMAILQUOTA"
#define ENV_QUOTAWARNING 	"QMAILQUOTAWARNING"

#define ENV_DOTMODE		"QMAILDOTMODE"
#define ENV_MODE 		"QMAILMODE"
#define ENV_REPLYTEXT	"QMAILREPLYTEXT"
#define ENV_FORWARDS	"QMAILFORWARDS"
#define ENV_PROGRAM		"QMAILDELIVERYPROGRAM"

#define DOTMODE_LDAPONLY "ldaponly"
#define DOTMODE_LDAPWITHPROG "ldapwithprog"
#define DOTMODE_DOTONLY	"dotonly"
#define DOTMODE_BOTH	"both"
#define DOTMODE_NONE	"none"

#define MODE_NORMAL		"normal"
#define MODE_FORWARD	"forwardonly"
#define MODE_NOMBOX		"nombox"
#define MODE_LDELIVERY	"localdelivery"
#define MODE_REPLY		"reply"
#define MODE_ECHO		"echo"


/* qmail-local.c only */
#define DO_LDAP 0x01
#define DO_DOT  0x02
#define DO_BOTH DO_LDAP | DO_DOT

#endif
