#ifndef SUBSTDIO_H
#define SUBSTDIO_H

typedef struct substdio {
  char *x;
  int p;
  int n;
  int fd;
  int (*op)();
} substdio;

#define SUBSTDIO_FDBUF(op,fd,buf,len) { (buf), 0, (len), (fd), (op) }

extern void substdio_fdbuf(substdio *, int (*)(), int, char *, int);

extern int substdio_flush(substdio *);
extern int substdio_put(substdio *, const char *, int);
extern int substdio_bput(substdio *, const char *, int);
extern int substdio_putflush(substdio *, const char *, int);
extern int substdio_puts(substdio *, const char *);
extern int substdio_bputs(substdio *, const char *);
extern int substdio_putsflush(substdio *, const char *);

extern int substdio_get(substdio *, char *, int);
extern int substdio_bget(substdio *, char *, int);
extern int substdio_feed(substdio *);

extern char *substdio_peek(substdio *);
extern void substdio_seek(substdio *, int);

#define substdio_fileno(s) ((s)->fd)

#define SUBSTDIO_INSIZE 8192
#define SUBSTDIO_OUTSIZE 8192

#define substdio_PEEK(s) ( (s)->x + (s)->n )
#define substdio_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define substdio_BPUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : substdio_bput((s),&(c),1) \
  )

extern int substdio_copy(substdio *, substdio *);

#endif
