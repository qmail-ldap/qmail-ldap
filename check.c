#include "check.h"
#include "stralloc.h"

/* this function will be removed in near future  */
int chck_mailb(char *s, register unsigned int len)
{
   int at=0;
   register char *t;
   
   t = s;
   
   for (;;) {
      /* [a-z]|[0-9]|[.-_]@[a-z]|[0-9]|[.-]  */
      if(!len) { if (at) return 1; else break; }
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || ( !at && *t == '_' ) || ( !at && *t == '@' && (at=1) ) ) { ++t; --len; } else return 0;
      /* [a-z]|[0-9]|[.-_]@[a-z]|[0-9]|[.-]  */
      if(!len) { if (at) return 1; else break; }
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || ( !at && *t == '_' ) || ( !at && *t == '@' && (at=1) ) ) { ++t; --len; } else return 0;
      /* [a-z]|[0-9]|[.-_]@[a-z]|[0-9]|[.-]  */
      if(!len) { if (at) return 1; else break; }
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || ( !at && *t == '_' ) || ( !at && *t == '@' && (at=1) ) ) { ++t; --len; } else return 0;
      /* [a-z]|[0-9]|[.-_]@[a-z]|[0-9]|[.-]  */
      if(!len) { if (at) return 1; else break; }
      if ( ( *t >= 'a' && *t <= 'z' ) || ( *t >= '0' && *t <= '9' ) || *t == '.' || *t == '-' || ( !at && *t == '_' ) || ( !at && *t == '@' && (at=1) ) ) { ++t; --len; } else return 0;
   }
   
}


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
   
   if ( b <= 65535 ) /* see passwd(4) normaly also bigger uids/gids are allowed but ... */
      return b;
   return 0;
   
}

/* XXX: is this enough secure */
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
      if(!len) break; if (*s == '*' || *s == '(' || *s == ')') *t++ = '\\' ; *t++ = *s++; len--;
      if(!len) break; if (*s == '*' || *s == '(' || *s == ')') *t++ = '\\' ; *t++ = *s++; len--;
      if(!len) break; if (*s == '*' || *s == '(' || *s == ')') *t++ = '\\' ; *t++ = *s++; len--;
      if(!len) break; if (*s == '*' || *s == '(' || *s == ')') *t++ = '\\' ; *t++ = *s++; len--;
   }
   *t = '\0';
   if (!stralloc_copys(toescape, escape_tmp.s)) { /* ARRG: almost certainly successful */
      if (!stralloc_copys(&escape_tmp, "")) return 0;
      return 0;
   }
   if (!stralloc_copys(&escape_tmp, "")) return 0; /* free the temporary memory */
   return 1;
}
   
   
/* this function will be removed in near future  */
int chck_mails(char *s) { return chck_mailb(s, str_len(s) ); }

int chck_users(char *s) { return chck_userb(s, str_len(s) ); }
long chck_ids(char *s) { return chck_idb(s, str_len(s) ); }
int chck_paths(char *s) { return chck_pathb(s, str_len(s) ); }
