#ifndef CONSTMAP_H
#define CONSTMAP_H

typedef unsigned long constmap_hash;

struct constmap {
  unsigned int num;
  constmap_hash mask;
  constmap_hash *hash;
  unsigned int *first;
  unsigned int *next;
  const char **input;
  unsigned int *inputlen;
} ;

extern int constmap_init(struct constmap *, const char *, unsigned int, int);
extern void constmap_free(struct constmap *);
extern const char *constmap(struct constmap *, const char *, unsigned int);

#endif
