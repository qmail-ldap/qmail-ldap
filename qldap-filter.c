#include "auto_break.h"
#include "qldap.h"
#include "qmail-ldap.h"
#include "str.h"
#include "stralloc.h"

static stralloc escapedstr = {0};
/*
 * For LDAP, '(', ')', '\', '*' and '\0' have to be escaped with '\'.
 * We ignore the '\0' case because it is not possible to have a '\0' in s.
 */
char *
filter_escape(char *s)
{
	char	x;

	/* pre reserve some space */
	if (!stralloc_ready(&escapedstr, str_len(s))) return 0;
	if (!stralloc_copys(&escapedstr, "")) return 0;
	do {
		x = *s;
		if (x == '*' || x == '(' || x == ')' || x == '\\')
			if (!stralloc_append(&escapedstr, "\\")) return 0;
		if (!stralloc_append(&escapedstr, s)) return 0;
	} while (*s++);
	return escapedstr.s;
}

static stralloc ocfilter = {0};
extern stralloc	objectclass;

char *
filter_objectclass(char *searchfilter)
{

	if (searchfilter == (char *)0) return 0;
	if (objectclass.s == (char *)0 || objectclass.len == 0)
		return searchfilter;
	/* (&(objectclass=...)%searchfilter%) */
	if (!stralloc_copys(&ocfilter, "(&(") ||
	    !stralloc_cats(&ocfilter, LDAP_OBJECTCLASS) ||
	    !stralloc_cats(&ocfilter, "=") ||
	    !stralloc_cat(&ocfilter, &objectclass) ||
	    !stralloc_cats(&ocfilter, ")") ||
	    !stralloc_cats(&ocfilter, searchfilter) ||
	    !stralloc_cats(&ocfilter, ")") ||
	    !stralloc_0(&ocfilter))
		return 0;
	return ocfilter.s;
}

static stralloc filter = {0};

char *
filter_uid(char *uid)
{
	char	*escaped;
	
	if (uid == (char *)0) return 0;
	
	escaped = filter_escape(uid);
	if (escaped == (char *)0) return 0;
	
	if (!stralloc_copys(&filter,"(") ||
	    !stralloc_cats(&filter, LDAP_UID) ||
	    !stralloc_cats(&filter, "=") ||
	    !stralloc_cats(&filter, escaped) ||
	    !stralloc_cats(&filter, ")") ||
	    !stralloc_0(&filter))
		return (char *)0;
	return filter_objectclass(filter.s);
}

static unsigned int extcnt;


char *
filter_mail(char *mail, int *done)
{
	static char		*escaped;
	static unsigned int	at, ext, len = 0;
#ifdef DASH_EXT
	unsigned int 		i;
#endif

	if (mail == (char *)0) {
		len = 0;
		return 0;
	}

	if (len == 0) {
		escaped = filter_escape(mail);
		if (escaped == (char *)0) return 0;
		len = str_len(escaped);
		at = str_rchr(escaped, '@');
		if (escaped[at] != '@') {
			len = 0;
			return 0;
		}
		ext = at;
		extcnt = -1;
		*done = 0;
	} else {
		if (extcnt == 0) {
			*done = 1;
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
				if (escaped[ext] == *auto_break) extcnt++;
		while (ext != 0 && --ext > 0) {
			if (escaped[ext] == *auto_break) break;
		}
		extcnt--;
#else
		/* basic qmail-ldap behavior test for username@domain.com and
		   catchall@domain.com */
		ext = 0;
		extcnt = 0;
#endif
	}
	
	/* build the search string for the email address */
	if (!stralloc_copys(&filter, "(|(" )) return 0;
	/* mail address */
	if (!stralloc_cats(&filter, LDAP_MAIL)) return 0;
	if (!stralloc_cats(&filter, "=")) return 0;
	/* username till current '-' */
	if (!stralloc_catb(&filter, escaped, ext)) return 0;
	if (ext != at) { /* do not append catchall in the first round */
		/* catchall or default */
		if (extcnt > 0) /* add '-' */
			if (!stralloc_cats(&filter, auto_break))
				return 0;
		if (!stralloc_cats(&filter, LDAP_CATCH_ALL)) return 0;
	}
	/* @damin.com */
	if (!stralloc_catb(&filter, escaped+at, len-at)) return 0;

	/* mailalternate address */
	if (!stralloc_cats(&filter, ")(")) return 0;
	if (!stralloc_cats(&filter, LDAP_MAILALTERNATE)) return 0;
	if (!stralloc_cats(&filter, "=")) return 0;
	/* username till current '-' */
	if (!stralloc_catb(&filter, escaped, ext)) return 0;
	if (ext != at) { /* do not append catchall in the first round */
		/* catchall or default */
		if (extcnt > 0) /* add '-' */
			if (!stralloc_cats(&filter, auto_break)) return 0;
		if (!stralloc_cats(&filter, LDAP_CATCH_ALL)) return 0;
	}
	/* @domain.com */
	if (!stralloc_catb(&filter, escaped+at, len-at)) return 0;
	if (!stralloc_cats(&filter, "))")) return 0;
	if (!stralloc_0(&filter)) return 0;

	if (extcnt == 0) *done = 1;
	return filter_objectclass(filter.s);
}

unsigned int
filter_mail_ext(void)
{
	return extcnt;
}
