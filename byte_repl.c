#include "byte.h"

/* char replacement */
unsigned int byte_repl(char *s, unsigned int len, int f, int r)
{
   register char *t;
   int count = 0;
	 char fc;
	 char rc;

   t = s; fc = f; rc = r;
   for(;;) {
      if (!len) return count; if (*t == fc) { *t=rc; count++; } ++t; --len;
      if (!len) return count; if (*t == fc) { *t=rc; count++; } ++t; --len;
      if (!len) return count; if (*t == fc) { *t=rc; count++; } ++t; --len;
      if (!len) return count; if (*t == fc) { *t=rc; count++; } ++t; --len;
   }
}


