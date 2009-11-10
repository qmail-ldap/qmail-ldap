/*
 * Copyright (c) 2003-2004 Claudio Jeker,
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
#include "auto_break.h"
#include "constmap.h"
#include "qldap.h"
#include "qmail-ldap.h"
#include "str.h"
#include "stralloc.h"

extern stralloc	objectclass;
extern struct constmap ad_map;
extern int adok;

int filter_escape(stralloc *, char *, unsigned int);
int filter_start(stralloc *);
int filter_end(stralloc *);

/*
 * For LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\'.
 * We ignore the '\0' case because it is not possible to have a '\0' in s.
 */
int
filter_escape(stralloc *filter, char *s, unsigned int len)
{
	char	x;

	/* pre reserve some space */
	if (!stralloc_readyplus(filter, len))
		return 0;
	for (; len != 0; len--) {
		x = *s++;
		if (x == '*' || x == '(' || x == ')' || x == '\\')
			if (!stralloc_append(filter, "\\"))
				return 0;
		if (!stralloc_append(filter, &x))
			return 0;
	}
	return 1;
}

int
filter_start(stralloc *filter)
{
	if (!stralloc_copys(filter, ""))
		return 0;
	if (objectclass.s != (char *)0 && objectclass.len != 0) {
		/* (&(objectclass=...)%searchfilter%) */
		if (!stralloc_copys(filter, "(&(") ||
		    !stralloc_cats(filter, LDAP_OBJECTCLASS) ||
		    !stralloc_cats(filter, "=") ||
		    !stralloc_cat(filter, &objectclass) ||
		    !stralloc_cats(filter, ")"))
			return 0;
	}
	return 1;
}

int
filter_end(stralloc *filter)
{
	if (objectclass.s != (char *)0 && objectclass.len != 0)
		if (!stralloc_cats(filter, ")"))
			return 0;

	if (!stralloc_0(filter))
		return 0;
	return 1;
}

static stralloc filter = {0};

char *
filter_uid(char *uid)
{
	if (uid == (char *)0)
		return 0;

	if (!filter_start(&filter)  ||
	    !stralloc_copys(&filter,"(") ||
	    !stralloc_cats(&filter, LDAP_UID) ||
	    !stralloc_cats(&filter, "=") ||
	    !filter_escape(&filter, uid, str_len(uid)) ||
	    !stralloc_cats(&filter, ")") ||
	    !filter_end(&filter))
		return (char *)0;

	return filter.s;
}

static int extcnt;
static unsigned int ext = 0;

char *
filter_mail(char *mail, int *done)
{
	char			*domain, *alias;
	unsigned int		at;
	int			round;
#ifdef DASH_EXT
	unsigned int 		i;
#endif

	if (mail == (char *)0) {
		ext = 0;
		return 0;
	}

	at = str_rchr(mail, '@');
	if (at == 0 || mail[at] != '@') {
		ext = 0;
		return 0;
	}
	domain = mail + at + 1;

	if (adok) {
		alias = constmap(&ad_map, domain, str_len(domain));
		if (alias && *alias)
			domain = alias;
	}

	if (ext == 0) {
		ext = at;
		extcnt = -1;
		*done = 0;
	} else {
		if (extcnt == 0) {
			*done = 1;
			ext = 0;
			return 0;
		}
#ifdef DASH_EXT
		/*
		 * limit ext to the first DASH_EXT_LEVELS extensions.
		 * We will only check for (DASH_EXT_LEVELS = 4):
		 * a-b-c-d-e-f-g-...@foobar.com
		 * a-b-c-d-catchall@foobar.com
		 * a-b-c-catchall@foobar.com
		 * a-b-catchall@foobar.com
		 * a-catchall@foobar.com
		 * catchall@foobar.com
		 */
		if (ext == at)
			for (i = 0, ext = 0, extcnt = 1;
			    ext < at && extcnt <= DASH_EXT_LEVELS; ext++)
				if (mail[ext] == *auto_break) extcnt++;
		while (ext != 0 && --ext > 0) {
			if (mail[ext] == *auto_break) break;
		}
		extcnt--;
#else
#error XXX XXX 
		/* basic qmail-ldap behavior test for username@domain.com and
		   catchall@domain.com */
		ext = 0;
		extcnt = 0;
#endif
	}
	
	for (round = 0; round < 2; round++) {
		switch (round) {
		case 0:
			/* build the search string for the email address */
			/* mail address */
			if (!filter_start(&filter) ||
			    !stralloc_copys(&filter, "(|(") ||
			    !stralloc_cats(&filter, LDAP_MAIL) ||
			    !stralloc_cats(&filter, "="))
				return 0;
			break;
		case 1:
			/* mailalternate address */
			if (!stralloc_cats(&filter, ")(") ||
			    !stralloc_cats(&filter, LDAP_MAILALTERNATE) ||
			    !stralloc_cats(&filter, "="))
				return 0;
			break;
		}

		/* username till current '-' or '@' */
		if (!filter_escape(&filter, mail, ext))
			return 0;
		/* do not append catchall in the first round */
		if (ext != at) {
			/* catchall or default */
			if (extcnt > 0) /* add '-' */
				if (!stralloc_cats(&filter, auto_break))
					return 0;
			if (!stralloc_cats(&filter, LDAP_CATCH_ALL))
				return 0;
		}
		/* @domain.com */
		if (!stralloc_append(&filter, "@") ||
		    !filter_escape(&filter, domain, str_len(domain)))
			return 0;
	}

	if (!stralloc_cats(&filter, "))") ||
	    !filter_end(&filter))
		return 0;

	if (extcnt == 0)
		*done = 1;
	return filter.s;
}

int
filter_mail_ext(void)
{
	return extcnt;
}
