#ifdef SMTPEXECCHECK
#include "case.h"
#include "env.h"
#include "qmail.h"
#include "str.h"
#include "stralloc.h"

#include "execcheck.h"

extern void die_nomem(); /* needed error function from qmail-smtpd,c */


static int checkexecutable = 0;
static int flagexecutable;

void
execcheck_setup(void)
{
	if (env_get("REJECTEXEC")) checkexecutable = 1;
}

int
execcheck_on(void)
{
	return checkexecutable;
}

int
execcheck_flag(void)
{
	return flagexecutable;
}

static int putinheader;
static int linespastheader;	/* = 0 after boundary is found in body, until */
				/* blank line then = 1 and 9 lines later = 2 */
static char linetype;

static stralloc line = {0};
static stralloc content = {0};
static stralloc boundary = {0};

void
execcheck_start(void)
{
	boundary.len = 0;
	content.len = 0;
	putinheader = 1;
	linespastheader = -1;
	flagexecutable = 0;
	linetype = ' ';
}

void
execcheck_put(struct qmail *qqt, char *ch)
{
	char *cp, *cpstart, *cpafter;
	unsigned int len;

	if (!checkexecutable)
		return;	
	if (line.len < 1024)
		if (!stralloc_catb(&line,ch,1)) die_nomem();

	if (*ch != '\n')
		/* wait until we have a entire line together */
		return;

	if (putinheader) {
		/*
		 * in mail header, search for content-type
		 * and possible boundary
		 */
		if (line.len == 1) {
			putinheader = 0;
			if (content.len) { /* MIME header */
				cp = content.s;
				len = content.len;
				while (len && (*cp == ' ' || *cp == '\t')) {
					++cp; --len;
				}
				cpstart = cp;
				if (len && *cp == '"') {
					/* might be commented */
					++cp; --len;
					cpstart = cp;
					while (len && *cp != '"') {
						++cp; --len;
					}
				} else {
					while (len && *cp != ' ' &&
					    *cp != '\t' && *cp != ';') {
						++cp; --len;
					}
				}

				cpafter = content.s+content.len;
				while((cp += byte_chr(cp, cpafter-cp, ';')) !=
				    cpafter) {
					++cp;
					while (cp < cpafter &&
					    (*cp == ' ' || *cp == '\t'))
						++cp;
					if (9 > cpafter - cp &&
					    case_diffb(cp, 9, "boundary=")) {
						cp += 9; /* after boundary= */
						if (cp < cpafter &&
						    *cp == '"') {
							++cp;
							cpstart = cp;
							while (cp < cpafter &&
							    *cp != '"')
								++cp;
						} else {
							cpstart = cp;
							while (cp < cpafter &&
							    *cp != ';' &&
							    *cp != ' ' &&
							    *cp != '\t')
								++cp;
						}
						if (!stralloc_copys(
							    &boundary, "--"))
							die_nomem();
						if (!stralloc_catb(&boundary,
							    cpstart,cp-cpstart))
							die_nomem();
						break;
					}
				}
			}
		} else {
			if (*line.s == ' ' || *line.s == '\t') {
				switch(linetype) {
				case 'C':
					if (!stralloc_catb(&content,
						    line.s, line.len-1))
						die_nomem();
					break;
				default:
					break;
				}
			} else {
				if (!case_startb(line.s, line.len,
					    "content-type:")) {
					if (!stralloc_copyb(&content,
						    line.s+13, line.len-14))
						die_nomem();
					linetype = 'C';
				} else {
					linetype = ' ';
				}
			}
		}
	} else {
		if (boundary.len && *line.s == '-' &&
		    line.len > boundary.len &&
		    !str_diffn(line.s,boundary.s,boundary.len)) {
			linespastheader = 0;
		} else if (linespastheader == 0 && line.len == 1) {
			linespastheader = 1;
		} else if (linespastheader == 1) {
			if (line.len >= 9)
				if (!str_diffn(line.s,"TVqQAAMAA",9) ||
				    !str_diffn(line.s,"TVpQAAIAA",9) ||
				    !str_diffn(line.s,"TVpAALQAc",9) ||
				    !str_diffn(line.s,"TVpyAXkAX",9) ||
				    !str_diffn(line.s,"TVrmAU4AA",9) ||
				    !str_diffn(line.s,"TVrhARwAk",9) ||
				    !str_diffn(line.s,"TVoFAQUAA",9) ||
				    !str_diffn(line.s,"TVoAAAQAA",9) ||
				    !str_diffn(line.s,"TVoIARMAA",9) ||
				    !str_diffn(line.s,"TVouARsAA",9) ||
				    !str_diffn(line.s,"TVrQAT8AA",9)) {
					flagexecutable = 1;
					qmail_fail(&qqt);
				}
			linespastheader = 2;
		}
	}
	line.len = 0;
}

#endif

