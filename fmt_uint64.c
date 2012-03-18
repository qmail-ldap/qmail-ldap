#include "fmt.h"

unsigned int fmt_uint64(char *s, uint64 u)
{
  unsigned int len;
  uint64 q;

  len = 1; q = u;
  while (q > 9) { ++len; q /= 10; }
  if (s) {
    s += len;
    do { *--s = '0' + (u % 10); u /= 10; } while(u); /* handles u == 0 */
  }
  return len;
}
