#include "check.h"
#include "qmail-ldap.h"
#include "str.h"

/* XXX this is not a security checker, it just looks that no special chars 
 * XXX are in the username this is because the ldap server could send some 
 * XXX faked datas */
int chck_userb(char *s, register unsigned int len)
{
	register char *t;

	t = s;

	if(!len || len > 32 ) return 0; 
	/* XXX are usernames limited to max 32 characters ??? */
	for (;;) {
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
			 ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || 
			 *t == '_' ) {
			++t; --len; 
		} else return 0;
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
			 ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || 
			 *t == '_' ) {
			++t; --len; 
		} else return 0;
		/* ^[-a-zA-Z0-9._]*$ */
		if(!len) return 1;
		if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || 
			 ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || 
			 *t == '_' ) {
			++t; --len; 
		} else return 0;
	}
	return 0; /* paranoia ? */
}


/* XXX this is not a security checker, it just looks that no special chars 
 * XXX are in the path this is because the ldap server could send some 
 * XXX faked datas */
int chck_pathb(register char *s, register unsigned int len)
{

	if(!len) return 0;
	/* ^[A-Za-z0-9/][-A-Za-z0-9._]*$ */
	if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
		 ( *s >= '0' && *s <= '9' ) || *s == '/' ) 
	{
		++s; --len; 
	} else return 0;
	for (;;) {
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) return 1;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
			 ( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || 
			 *s == '_'  || *s == '/' ) 
		{
			++s; --len; 
		} else return 0;
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) return 1;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
			 ( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || 
			 *s == '_'  || *s == '/' ) 
		{
			++s; --len; 
		} else return 0;
		/* ^[A-Za-z0-9/][-A-Za-z0-9._/]*$ */
		if(!len) return 1;
		if ( ( *s >= 'a' && *s <= 'z' ) || ( *s >= 'A' && *s <= 'Z' ) || 
			 ( *s >= '0' && *s <= '9' ) || *s == '.' || *s == '-' || 
			 *s == '_'  || *s == '/' ) 
		{
			++s; --len; 
		} else return 0;
	}
	return 0; /* paranoia ? */
}

int chck_users(char *s) { return chck_userb(s, str_len(s) ); }
int chck_paths(char *s) { return chck_pathb(s, str_len(s) ); }
