#ifndef __DIRMAKER_H__
#define __DIRMAKER_H__

/* init handler */
int dirmaker_init(void);

/* executes the dirmaker returns OK on success */
int dirmaker_make(const char *, const char *);

#endif
