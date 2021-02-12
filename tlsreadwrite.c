/*
 * Copyright (c) 2021 Claudio Jeker,
 *      Internet Business Solutions AG, CH-8005 Zürich, Switzerland
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Internet Business
 *      Solutions AG and its contributors.
 * 4. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#ifdef TLS
#include <tls.h>

#include "select.h"
#include "error.h"
#include "tlsreadwrite.h"

int
tlstimeoutread(int tout, int fd, struct tls *ctx, void *buf, int size)
{
	fd_set rfds;
	struct timeval tv;
	ssize_t ret;

	tv.tv_sec = tout;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(fd,&rfds);

	if (select(fd + 1,&rfds,(fd_set *) 0,(fd_set *) 0,&tv) == -1)
		return -1;
	if (FD_ISSET(fd,&rfds))
		do {
			ret = tls_read(ctx, buf, size);
			if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
				continue;
			return ret;
		} while (1);

	errno = error_timeout;
	return -1;
}

int
tlstimeoutwrite(int tout, int fd, struct tls *ctx, void *buf, int size)
{
	fd_set wfds;
	struct timeval tv;
	ssize_t ret;

	tv.tv_sec = tout;
	tv.tv_usec = 0;

	FD_ZERO(&wfds);
	FD_SET(fd,&wfds);

	if (select(fd + 1,(fd_set *) 0,&wfds,(fd_set *) 0,&tv) == -1)
		return -1;
	if (FD_ISSET(fd,&wfds))
		do {
			ret = tls_write(ctx, buf, size);
			if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT)
				continue;
			return ret;
		} while (1);

	errno = error_timeout;
	return -1;
}

#endif
