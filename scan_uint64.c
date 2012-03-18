#include "scan.h"

unsigned int scan_uint64(const char *s, uint64 *u)
{
  unsigned int pos;
  uint64 result;
  uint64 c;

  pos = 0; result = 0;
  while ((c = (uint64) (unsigned char) (s[pos] - '0')) < 10)
    { result = result * 10 + c; ++pos; }
  *u = result; return pos;
}
