#ifndef __HEADERMAGIC_H__
#define __HEADERMAGIC_H__

#include "stralloc.h"

#define DENY 1
#define ALLOW 2
#define FORCE 3
#define SUBJECT 4
#define DEFAULT ""

struct mheader {
	const char	*f; /* field */
	const char	*v; /* default value */
	int		type; /* one of DENY, ALLOW, FORCE, SUBJECT */
	int		seen; /* used internally */
};

int headermagic(stralloc *, stralloc *, stralloc *, struct mheader *);
int mimemagichead(stralloc *, stralloc *);
char *mimemagic(void);

#endif

