#ifndef QLX_H
#define QLX_H

/* 0, 111, 100 are qmail-local success, soft, hard */

#define QLX_USAGE 112
#define QLX_BUG 101
#define QLX_ROOT 113
#define QLX_NFS 115
#define QLX_NOALIAS 116
#define QLX_CDB 117
#define QLX_SYS 118
#define QLX_NOMEM 119
#define QLX_EXECSOFT 120
#define QLX_EXECPW 121
#define QLX_EXECHARD 126

/* qmail-ldap specific exit codes */

/* ldap specific errors */
#define QLX_MAXSIZE 150
#define QLX_DISABLED 151
#define QLX_LDAPFAIL 152	/* generic fail of ldap functions */
#define QLX_LDAPAUTH 153	/* LDAP_BIND_AUTH */
#define QLX_SEARCHTIMEOUT 154	/* TIMEOUT */
#define QLX_BINDTIMEOUT 155	/* LDAP_BIND_UNREACH */
#define QLX_TOOMANY 156
#define QLX_NEEDED 157
#define QLX_ILLVAL 158

/* cluster errors */
#define QLX_CLUSTERSOFT 160
#define QLX_CLUSTERHARD 161
#define QLX_CLUSTERCRASHED 162
#define QLX_CLUSTERLOOP 163
/* dirmaker errors */
#define QLX_DIRMAKESOFT 164
#define QLX_DIRMAKEHARD 165
#define QLX_DIRMAKECRASH 166

#endif
