#include "check.h"
#include "stralloc.h"
#include "qmail-ldap.h"

int chck_userb(char *s, register unsigned int len)
{
   register char *t;
   
   t = s;
   
   if(!len || len > 32 ) return 0; /* usernames are limited to max 32 characters */
   for (;;) {
      /* [a-z]|[A-Z]|[0-9]|[.-_] */
      if(!len) return 1;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_] */
      if(!len) return 1;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_] */
      if(!len) return 1;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_] */
      if(!len) return 1;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' ) { ++t; --len; } else return 0;
   }
   
}


long chck_idb(char *s, register unsigned int len)
{
   unsigned long b=0;
   register char *t;
   
   t = s;
   
   if(!len || len > 6 ) return 0; /* to big id, see 15 lines later */
   for (;;) {
      /* [0-9] */
      if(!len) break;
      if ( *t >= '0' && *t <= '9' ) { b = b*10 + (*t - '0'); ++t; --len; } else return 0;
      /* [0-9] */
      if(!len) break;
      if ( *t >= '0' && *t <= '9' ) { b = b*10 + (*t - '0'); ++t; --len; } else return 0;
      /* [0-9] */
      if(!len) break;
      if ( *t >= '0' && *t <= '9' ) { b = b*10 + (*t - '0'); ++t; --len; } else return 0;
      /* [0-9] */
      if(!len) break;
      if ( *t >= '0' && *t <= '9' ) { b = b*10 + (*t - '0'); ++t; --len; } else return 0;
   }
   
   if ( b <= PW_MAX ) /* see passwd(4) normaly also bigger uids/gids are allowed but ... */
      return b;
   return 0;
   
}

/* XXX: this is not enough secure, will be removed soon */
int chck_pathb(char *s, register unsigned int len)
{
   register char *t;
   int tmp = len;
   t = s;
   
   if(!len) return 0;
   for (;;) {
      /* [a-z]|[A-Z]|[0-9]|[.-_/ ] */
      if(!len) break;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' || *t == '/' || *t == ' ' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_/ ] */
      if(!len) break;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' || *t == '/' || *t == ' ' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_/ ] */
      if(!len) break;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' || *t == '/' || *t == ' ' ) { ++t; --len; } else return 0;
      /* [a-z]|[A-Z]|[0-9]|[.-_/ ] */
      if(!len) break;
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= 'A' && *t <= 'Z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || *t == '_' || *t == '/' || *t == ' ' ) { ++t; --len; } else return 0;
   }
   
   len = tmp;
   t = s;
   for(++t;;) { /*  ./ are not allowed, only 'direct' ones*/
      if(!len) return 1; if ( *(t-1) == '.' && *t == '/' ) return 0; ++t; --len;
      if(!len) return 1; if ( *(t-1) == '.' && *t == '/' ) return 0; ++t; --len;
      if(!len) return 1; if ( *(t-1) == '.' && *t == '/' ) return 0; ++t; --len;
      if(!len) return 1; if ( *(t-1) == '.' && *t == '/' ) return 0; ++t; --len;
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
long chck_ids(char *s) { return chck_idb(s, str_len(s) ); }
int chck_paths(char *s) { return chck_pathb(s, str_len(s) ); }
