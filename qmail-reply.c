#include <sys/types.h>
#include <sys/stat.h>
#include "byte.h"
#include "case.h"
#include "control.h"
#include "constmap.h"
#include "env.h"
#include "error.h"
#include "exit.h"
#include "fmt.h"
#include "getln.h"
#include "newfield.h"
#include "now.h"
#include "open.h"
#include "qmail.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "seek.h"
#include "sgetopt.h"
#include "sig.h"
#include "str.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"

#define FATAL "qmail-reply: fatal: "
#define WARN  "qmail-reply: warn: "

void temp_nomem() { strerr_die2x(111, FATAL, "Out of memory."); }
void temp_rewind() { strerr_die2x(111, FATAL, "Unable to rewind message."); }
void temp_fork() { strerr_die2sys(111, FATAL, "Unable to fork: "); }


void usage(void)
{
	strerr_die1x(100,
	    "qmail-reply: usage: qmail-reply [-f mailfile] [-j junkfile]");
}

stralloc replytext = {0};

void envmail(void)
{
	char *s;

	if ((s = env_get(ENV_REPLYTEXT))) {
		if (!stralloc_copys(&replytext, s)) temp_nomem();
	} else {
		strerr_die3x(100, FATAL, ENV_REPLYTEXT,
		    " not present.");
	}
}

char buf[1024];
stralloc line = {0};

void readmail(char *file)
{
	substdio ss;
	int fd;
	int match;

	if (!stralloc_copys(&replytext, "")) temp_nomem();

	fd = open_read(file);
	if (fd == -1)
		strerr_die4sys(100, FATAL, "unable to open '", file, "': ");
 
	substdio_fdbuf(&ss, read, fd, buf, sizeof(buf));
	for (;;) {
		if (getln(&ss, &line, &match, '\n') == -1)
			strerr_die4sys(100, FATAL, "unable to read '", file, "': ");
		if (!match) {
			close(fd);
			return;
		}
		if (!stralloc_cat(&replytext, &line)) temp_nomem();
	}
}

stralloc to={0};
stralloc from={0};
stralloc host={0};
stralloc dtline={0};

void get_env(void)
{
	char *s;
	int i;

	if ((s = env_get("DTLINE")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment DTLINE not present.");
	if (!stralloc_copys(&dtline, s)) temp_nomem();

	if ((s = env_get("SENDER")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment SENDER not present.");
	if (!stralloc_copys(&to, s)) temp_nomem();

	if ((s = env_get("RECIPIENT")) == (char *)0)
		strerr_die2x(100, FATAL, "Environment RECIPIENT not present.");
	if (!stralloc_copys(&from, s)) temp_nomem();

	i = byte_chr(from.s, from.len, '@');
	if ( i == 0 || i >= from.len )
	  strerr_die2x(100, FATAL, "Bad RECIPIENT address.");

	if (!(s = env_get("HOST")))
		strerr_die2x(100, FATAL, "Environment HOST not present.");
	if (!stralloc_copys(&host, s)) temp_nomem();
}

stralloc junkfrom={0};
struct constmap mapjunk;

void junkread(char *path)
{
	if (control_readfile(&junkfrom, path, 0) != 1)
		strerr_die4sys(100, FATAL, "unable to read '", path, "': ");
}


int junksender(char *buf, int len)
{
	int	at, dash, i;
	static char *(junkignore[]) = {
		/* don't reply to bots */
		"-request",
		"daemon",
		"-daemon",
		"uucp",
		"mailer-daemon",
		"mailer",
		/* don't bother admins */
		"postmaster",
		"root",
		/* from vacation(1) */
		"-relay",
		0 } ;
	
	for (i = 0; junkignore[i] != 0; i++) {
		if (!stralloc_cats(&junkfrom, junkignore[i])) temp_nomem();
		if (!stralloc_0(&junkfrom)) temp_nomem();
	}

	if (!constmap_init(&mapjunk, junkfrom.s, junkfrom.len, 0))
		strerr_die2sys(111, FATAL, "constmap_init: ");
	
	at = byte_rchr(buf, len, '@');
	if (at >= len)
		strerr_die2x(111, FATAL, "Bad SENDER address.");

	/*
	   1. user@host
	   2. user
	   3. @host
	   4. -part
	 */
	if (constmap(&mapjunk,buf,len)) return 1;
	if (constmap(&mapjunk,buf,at)) return 1;
	if (constmap(&mapjunk,buf+at,len-at)) return 1;
	
	for (dash = 0; dash < at; dash++) {
		dash += byte_chr(buf+dash,at-dash, '-');
		if (constmap(&mapjunk,buf+dash,at-dash)) return 1;
	}
	return 0;
}	

#ifdef NOTYET

datetime_sec get_stamp(char *hex)
{
	long t;
	char c;

	t = 0;
	while((c = *hex++)) {
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a')
			c -= ('a' - 10);
		else 
			c -= ('A' - 10);
		if (c >= 16)
			break;
		t = (t<<4) + c;
	}
	
	return (datetime_sec) t;	
}

char* stamp(datetime_sec time)
{
	static char stampbuf[9];
	static char* digit = "0123456789abcdef";
	char *s;
	long t;

	t = (long) time;
	s = stampbuf;
	*s++ = digit[(t >> 28) & 0x0f];
	*s++ = digit[(t >> 24) & 0x0f];
	*s++ = digit[(t >> 20) & 0x0f];
	*s++ = digit[(t >> 16) & 0x0f];
	*s++ = digit[(t >> 12) & 0x0f];
	*s++ = digit[(t >>  8) & 0x0f];
	*s++ = digit[(t >>  4) & 0x0f];
	*s++ = digit[ t        & 0x0f];
	*s = '\0';
	return stampbuf;
}

stralloc rs = {0}; /* recent sender */
int rsmatch = 0;
datetime_sec timeout;
#ifndef REPLY_TIMEOUT
#define REPLY_TIMEOUT 1209600 /* 2 weeks */
#endif
#define MAX_SIZE 10240 /* 10kB */

int recent(char *buf, int len)
{
	char *s;
	datetime_sec last;
	int i, slen;
	
	switch (control_readfile(&rs,".qmail-reply.db",1)) {
		case 1:
			break;
		case 0:
			return 0;
		default:
			strerr_die2sys(111, FATAL,
			    "read db file .qmail-reply.db: ");
	}

	slen = rs.len; s = rs.s;
	for (i = 0; i < slen; i += str_len(s+i)) {
		if (case_diffb(buf, len, s+i) == 0) {
			/* match found, look at timeval */
			rsmatch = i; i += len;
			if (s[i++] != ':')
				strerr_die2x(100, FATAL,
				    "db file .qmail-reply.db corrupted");
			last = get_stamp(s+i);
			if (last + timeout > now()) return 1;
			else return 0;
		}
	}

	return 0;
}

char rsoutbuf[SUBSTDIO_OUTSIZE];
char fntmptph[32 + FMT_ULONG * 2];

void tryunlinktmp() { unlink(fntmptph); }
void sigalrm()
{
	tryunlinktmp();
	strerr_die2x(111, FATAL, "timeout while writing db file");
}

void recent_update(char *buf, int len)
{
	char *s, *t;
	struct stat st;
	unsigned long pid, time;
	int fd, loop, size, slen, i;
	substdio ss;

	s = rs.s; slen = rs.len;
	size = slen + len + 10;
	for(; size > MAX_SIZE; ) {
		i = str_len(s) + 1;
		size -= i;
		slen -= i;
		s += i;
	}

	pid = getpid();
	for (loop = 0;;++loop) {
		time = now();
		t = fntmptph;
		t += fmt_str(t, ".qmail-reply.tmp.");
		t += fmt_ulong(t, time); *t++ = '.';
		t += fmt_ulong(t, pid);
		*t++ = 0;
		if (stat(fntmptph, &st) == -1) if (errno == error_noent) break;
		/* really should never get to this point */
		if (loop == 2) _exit(1);
		sleep(2);
	}
	
	sig_alarmcatch(sigalrm);
	alarm(600); /* give up after 10 min */
	fd = open_excl(fntmptph);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "unable to open tmp file: ");

	substdio_fdbuf(&ss, write, fd, rsoutbuf, sizeof(rsoutbuf));

	for (i = 0; i < slen; i += str_len(s+i) + 1) {
		if (rs.s+rsmatch == s+i) continue;
		if (substdio_puts(&ss, s+i) == -1) goto fail;
		if (substdio_put(&ss, "\n", 1) == -1) goto fail;
	}
	if (substdio_put(&ss, buf, len) == -1) goto fail;
	if (substdio_put(&ss, ":", 1) == -1) goto fail;
	if (substdio_puts(&ss, stamp(now())) == -1) goto fail;
	if (substdio_put(&ss, "\n", 1) == -1) goto fail;
	if (substdio_flush(&ss) == -1) goto fail;
	if (fsync(fd) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	if (unlink(".qmail-reply.db") == -1 && errno != error_noent) goto fail;
	
	if (link(fntmptph, ".qmail-reply.db") == -1) goto fail;
	/* if it was error_exist, almost certainly successful; i hate NFS */

	tryunlinktmp();
	return;

fail:
	tryunlinktmp(); /* failed somewhere, giving up */
	return;
}

#endif

int getfield(char *s, int len)
{
	int l;

	l = len;
	for(;;) {
		if (l-- <= 0) break; if (*s++ == ':') break;
		if (l-- <= 0) break; if (*s++ == ':') break;
		if (l-- <= 0) break; if (*s++ == ':') break;
		if (l-- <= 0) break; if (*s++ == ':') break;
	}
	for(;;) {
		if (l <= 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s != ' ' && *s != '\t') break;
		l--; s++;
	}
	return len - l;
}

#ifndef REPLY_SUBJ
#define REPLY_SUBJ "Your Mail"
#endif

stralloc subject = {0};

int parseheader(/* TODO names for to/cc checking */ void)
{
	substdio ss;
	char *s;
	int match, len, subj_set, i;

	subj_set = 0;
	if (seek_begin(0) == -1) temp_rewind();
	substdio_fdbuf(&ss, read, 0, buf, sizeof(buf) );
	do {
		if(getln(&ss, &line, &match, '\n') != 0) {
			strerr_warn3(WARN, "unable to read message: ",
			    error_str(errno), 0);
			break; /* something bad happend, but we ignore it */
		}
		if (line.len == 0) /* something is wrong, bad message */
			break;
		s = line.s; len = line.len;
		switch(*s) {
		case '\n': /* end of header */
			if (subj_set == 0)
				if (!stralloc_copys(&subject, REPLY_SUBJ))
					temp_nomem();
			return 0;
		case 'M':
		case 'm': /* Mailing-List: */
			if (case_diffb("Mailing-List:",
				    sizeof("Mailing-List:") - 1, s) == 0) {
				return 1;
				/* don't reply to mailing-lists */
			}
			break;
		case 'P':
		case 'p': /* Precedence: */
			if (case_diffb("Precedence:",
				    sizeof("Precedence:") - 1, s) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
				if (case_diffb(s, 4, "junk") == 0 ||
				    case_diffb(s, 4, "bulk") == 0 ||
				    case_diffb(s, 4, "list") == 0)
					return 1;
			}
			break;
		case 'S':
		case 's': /* Subject: */
			if (case_diffb("Subject:",
				    sizeof("Subject:") - 1, s) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
				
				if (len > 1) {
					/* subject has to be more than
					   1 char (normaly a \n)
					 */
					if (!stralloc_copyb(&subject, s, len-1))
						temp_nomem();
					subj_set=1;
				}
			}
			break;
		case 'C':
		case 'c': /* Cc: */
		case 'T':
		case 't': /* To: */
			/*  TODO check if address is listed in To ot Cc field */
#if 0
			if (case_diffb("To:"
				    sizeof("To:") - 1, s) == 0 ||
			    case_diffb("Cc:"
				    sizeof("Cc:") - 1, s) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
			}
#endif
			break;
		case ' ':
		case '\t':
			/* TODO multiline header Precedence, Subject, To and Cc */
		default:
			break;
		}
	} while (match);
	strerr_warn2(WARN,
	    "premature end of header. The message has no body.", 0);
	if ( subj_set == 0 )
		if (!stralloc_copys(&subject, REPLY_SUBJ)) temp_nomem();

	return 0;
}

stralloc ct = {0};
stralloc cte = {0};
stralloc resubject = {0};

#ifndef REPLY_CT
#define REPLY_CT "text/plain; charset=\"iso-8859-1\"\n"
#endif
#ifndef REPLY_CTE
#define REPLY_CTE "8bit\n"
#endif

void sendmail(void)
{
	struct qmail qqt;
	char *qqx, *s;
	datetime_sec starttime;
	unsigned long qp;
	int header, len, i, j;
	
	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	
	qmail_put(&qqt,dtline.s,dtline.len);
	qmail_puts(&qqt, "Precedence: junk\n");
	/* XXX Date: qmail uses GMT based dates which is sometimes confusing */
	/* message-id and date line */
	starttime = now();
	if (!newfield_datemake(starttime)) goto fail_nomem;
	if (!newfield_msgidmake(host.s,host.len,starttime)) goto fail_nomem;
	qmail_put(&qqt, newfield_msgid.s, newfield_msgid.len);
	qmail_put(&qqt, newfield_date.s, newfield_date.len);
		
	header = 0;
	s = replytext.s; len = replytext.len;
	do {
		for(i = 0;;) {
			i += byte_chr(s + i, len - i, '\n');
			if (++i >= len)
				strerr_die2x(100, FATAL, "parser error");
			if (s[i] == ' ' || s[i] == '\t')
				continue;
			break;
		}
		if (case_diffb("%HEADER%", sizeof("%HEADER%") - 1, s) == 0) {
			header = 1;
			goto next;
		}
		if (header == 0)
			break;
		
		switch (*s) {
		case '\n': /* end of header */
			header = 0;
			break;
		case 'C':
		case 'c': /* Content-Type: ||
			     Content-Transfer-Encoding: ||
			     Cc: */
			if (case_diffb("Cc:", sizeof("Cc:") - 1, s) == 0)
				break;
			if (case_diffb("Content-Type:",
				    sizeof("Content-Type:") - 1, s) == 0) {
				j = getfield(s, i);
				if (j >= i) break;
				if (!stralloc_copyb(&ct, s+j, i-j))
					goto fail_nomem;
				break;
			}
			if (case_diffb("Content-Transfer-Encoding:",
				    sizeof("Content-Transfer-Encoding:") - 1,
				    s) == 0) {
				j = getfield(s, i);
				if (j >= i) break;
				if (!stralloc_copyb(&cte, s+j, i-j))
					goto fail_nomem;
				break;
			}
			qmail_put(&qqt, s, i);
			break;
		case 'S':
		case 's': /* Subject: */
			if (case_diffb("Subject:",
				    sizeof("Subject:") - 1, s) != 0) {
				qmail_put(&qqt, s, i);
				break;
			}
			j = getfield(s, i);
			if (j >= i) break;
			
			if (!stralloc_ready(&resubject,
				    i + subject.len))
				goto fail_nomem;
			while (j < i) {
				if (s[j] == '%' && 
				    case_diffb("%SUBJECT%", 
					    sizeof("%SUBJECT%") - 1, s + j) == 0) {
					if (!stralloc_cat(&resubject, &subject))
						goto fail_nomem;
					j += sizeof("%SUBJECT%") - 1;
				} else {
					if (!stralloc_append(&resubject, s+j))
						goto fail_nomem;
					++j;
				}
			}
			if (!stralloc_0(&resubject)) goto fail_nomem;
			break;
		case 'F':
		case 'f': /* From: */
		case 'T':
		case 't': /* To: */
		case 'D':
		case 'd': /* Date: */
		case 'P':
		case 'p': /* Precedence: */
			if (case_diffb("From:", sizeof("From:") - 1, s) == 0 ||
			    case_diffb("To:", sizeof("To:") - 1, s) == 0 ||
			    case_diffb("Date:", sizeof("Date:") - 1, s) == 0 ||
			    case_diffb("Precedence:", 
				sizeof("Precedence:") - 1, s) == 0)
				break;
			/* FALLTHROUGH */
		default:			
			qmail_put(&qqt, s, i);
			break;
		}
next:
		s += i;
		len -= i;
	} while (header == 1);

	if (resubject.s == (char *)0) {
		if (!stralloc_copys(&resubject, "[Auto-Reply] "))
			goto fail_nomem;
		if (!stralloc_cat(&resubject, &subject)) goto fail_nomem;
		if (!stralloc_cats(&resubject, "\n")) goto fail_nomem;
		if (!stralloc_0(&resubject)) goto fail_nomem;
	}
	if (!stralloc_0(&from)) goto fail_nomem;
	if (!stralloc_0(&to)) goto fail_nomem;
	
	/* From: */
	qmail_puts(&qqt, "From: ");
	qmail_puts(&qqt, from.s);
	qmail_puts(&qqt, "\n");
	/* To: */
	qmail_puts(&qqt, "To: ");
	qmail_puts(&qqt, to.s);
	qmail_puts(&qqt, "\n");
	/* Subject: */
	qmail_puts(&qqt, "Subject: ");
	qmail_puts(&qqt, resubject.s); /* resubject already ends with a '\n'*/
	/* Content-* */
	qmail_puts(&qqt, "Content-type: ");
	if (ct.s != (char *)0 && ct.len > 0)
		qmail_put(&qqt, ct.s, ct.len);
	else
		qmail_puts(&qqt, REPLY_CT);
	/* '\n' already written */
	qmail_puts(&qqt, "Content-Transfer-Encoding: ");
	if (cte.s != (char *)0 && cte.len > 0)
		qmail_put(&qqt, cte.s, cte.len);
	else
		qmail_puts(&qqt, REPLY_CTE);
	/* '\n' already written */
	/* X-Mailer: qmail-reply */
	qmail_puts(&qqt, "X-Mailer: qmail-reply\n\n");

	/* body */
	qmail_put(&qqt, s, len);
	qmail_from(&qqt, from.s);
	qmail_to(&qqt, to.s);
	qqx = qmail_close(&qqt);
	if (!*qqx) return;
	strerr_die3x(*qqx == 'D' ? 100 : 111,
	    "Unable to send reply message: ", qqx + 1, ".");
	    
fail_nomem:
	qmail_fail(&qqt);
	temp_nomem();
}

int main(int argc, char **argv)
{
	int flagenv;
	int opt;

	if (!env_init()) temp_nomem();
	
	flagenv = 1;
#ifdef NOTYET
	timeout = REPLY_TIMEOUT;
#endif

	while((opt = getopt(argc,argv,"f:j:")) != opteof)
		switch(opt) {
			case 'f':
				readmail(optarg);
				flagenv = 0;
				break;
			case 'j':
				junkread(optarg);
				break;
			default:
				usage();
				/* NOTREACHED */
		}
	
	/* if more arguments are used */
	/* argc -= optind; argv += optind; */
	
	if (flagenv == 1) {
		envmail();
	}

	/* get environment RECIPIENT, SENDER and DTLINE */
	get_env();

	/* check if a reply is needed */
	if (junksender(to.s, to.len)) _exit(0);
#ifdef NOTYET
	if (recent(to.s, to.len)) _exit(0);
#endif
	/* parse header, exit if a precedence or mailinglist field
	   has been found or the mail is not directly sent to us. */
	if (parseheader()) _exit(0);

#ifdef NOTYET
	recent_update(to.s, to.len);
#endif
	sendmail();
	return 0;
}

