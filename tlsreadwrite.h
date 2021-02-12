#ifndef TLSREADWRITE_H
#define TLSREADWRITE_H

int	tlstimeoutread(int, int, struct tls *, void *, int);
int	tlstimeoutwrite(int, int, struct tls *, void *, int);

#endif
