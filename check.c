#include "check.h"
#include "stralloc.h"
#include "qmail-ldap.h"
#include "str.h"

/* XXX this is not a security checker, it just looks that no special chars are in 
 * XXX the path this is because the ldap server could send some faked datas */
int chck_userb(char *s, register unsigned int len)
{
	register char *t;

	t = s;

	if(!len || len > 32 ) return 0; /* usernames are limited to max 32 characters */
	for (;;) {
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
				( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) {
			++t; --len; 
		} else return 0;
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
				( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) {
			++t; --len; 
		} else return 0;
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
				( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) {
			++t; --len; 
		} else return 0;
	}
}


/* XXX this is not a security checker, it just looks that no special chars are in 
 * XXX the path this is because the ldap server could send some faked datas */
int chck_pathb(register char *s, register unsigned int len)
{

	if(!len) return 0;
	/* ^[A-Za-z0-9/][-A-Za-z0-9._]*$ */
	if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
			( *s >= '0' && *s <= '9' ) || *s == '/' ) {
		++s; --len; 
	} else return 0;
	for (;;) {
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) break;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
				( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || *s == '_'  || *s == '/' ) {
			++s; --len; 
		} else return 0;
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) break;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
				( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || *s == '_'  || *s == '/' ) {
			++s; --len; 
		} else return 0;
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) break;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
				( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || *s == '_'  || *s == '/' ) {
			++s; --len; 
		} else return 0;
	}
}

stralloc escape_tmp = {0};

int escape_forldap(stralloc *toescape)
{
	register int len = toescape->len;
	register char *t;
	register char *s;

	if (!stralloc_ready(&escape_tmp, 2*len)) return 0;

	s = toescape->s;
	t = escape_tmp.s;

	for(;;) {
#ifndef LDAP_ESCAPE_BUG
		if(!len) break; if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '\\' ; *t++ = *s++; len--;
		if(!len) break; if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '\\' ; *t++ = *s++; len--;
		if(!len) break; if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '\\' ; *t++ = *s++; len--;
		if(!len) break; if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '\\' ; *t++ = *s++; len--;
#else
#warning __LDAP_ESCAPE_BUG__IS__ON__
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '_' ; 
		else *t++ = *s++; 
		len--;
		if(!len) break; 
		if (*s == '*' || *s == '(' || *s == ')' || *s == '\\' ) *t++ = '_' ; 
		else *t++ = *s++; 
		len--;
#endif
	}
	*t = '\0';
	if (!stralloc_copys(toescape, escape_tmp.s)) { /* ARRG: almost certainly successful */
		if (!stralloc_copys(&escape_tmp, "")) return 0;
		return 0;
	}
	if (!stralloc_copys(&escape_tmp, "")) return 0; /* free the temporary memory */
	return 1;
}

int chck_users(char *s) { return chck_userb(s, str_len(s) ); }
int chck_paths(char *s) { return chck_pathb(s, str_len(s) ); }
