#include "byte.h"
#include "case.h"
#include "control.h"
#include "constmap.h"
#include "env.h"
#include "error.h"
#include "getln.h"
#include "now.h"
#include "open.h"
#include "qmail.h"
#include "qmail-ldap.h"
#include "readwrite.h"
#include "seek.h"
#include "sgetopt.h"
#include "strerr.h"
#include "stralloc.h"
#include "substdio.h"

#define FATAL "qmail-reply: fatal: "
#define WARN  "qmail-reply: warn: "

void temp_nomem() { strerr_die2x(111, FATAL, "Out of memory."); }
void temp_rewind() { strerr_die2x(111,FATAL, "Unable to rewind message."); }
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
		if (!stralloc_copys(&replytext,s)) temp_nomem();
	} else {
		strerr_die3x(100, FATAL, ENV_REPLYTEXT,
		    " not present.");
	}
}	

void readmail(char *file)
{
	strerr_die2x(100, FATAL, "option not yet implemented.");
}

stralloc to={0};
stralloc from={0};
stralloc dtline={0};

void get_env(void)
{
	char *s;
	int i;

	if ((s = env_get("DTLINE")) == (char *)0)
		strerr_die2x(100, FATAL, "DTLINE not present.");
	if (!stralloc_copys(&dtline,s)) temp_nomem();

	if ((s = env_get("SENDER")) == (char *)0)
		strerr_die2x(100, FATAL, "SENDER not present.");
	if (!stralloc_copys(&to,s)) temp_nomem();

	if ((s = env_get("RECIPIENT")) == (char *)0)
		strerr_die2x(100, FATAL, "RECIPIENT not present.");
	if (!stralloc_copys(&from,s)) temp_nomem();

	i = byte_chr(from.s, from.len, '@');
	if ( i == 0 || i >= from.len )
	  strerr_die2x(100, FATAL, "Bad RECIPIENT address.");

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
	int	at, dash, i, j;
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
	if (j >= len)
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
		dash = byte_chr(buf+dash,at-dash);
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
	while(c = *hex++) {
		if (c >= '0' && c <= '9')
			c -= '0';
		else if (c >= 'a')
			c -= ('a' + 10);
		else 
			c -= ('A' + 10);
		if (c >= 16)
			break;
		t = t<<4 + c;
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
	*s++ = (t >> 28) & 0x0f;
	*s++ = (t >> 24) & 0x0f;
	*s++ = (t >> 20) & 0x0f;
	*s++ = (t >> 16) & 0x0f;
	*s++ = (t >> 12) & 0x0f;
	*s++ = (t >>  8) & 0x0f;
	*s++ = (t >>  4) & 0x0f;
	*s++ =  t        & 0x0f;
	*s = '\0';
	return stampbuf;
}

stralloc rs = {0}; /* recent sender */
int rsmatch = 0;
datetime_sec timeout;
#define DEF_TIMEOUT 1209600 /* 2 weeks */
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
		if (case_diffb(s+i, buf, len) == 0) {
			/* match found, look at timeval */
			rsmatch = i; i += slen;
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
	strerr_die2x(111. FATAL, "timeout while writing db file");
}

void recent_update(char *buf, int len)
{
	char *s;
	int size, slen, i;
	substdio ss;

	s = rs.s; slen = rs.len;
	size = slen + len + 10;
	for(; size > MAX_SIZE; ) {
		i = str_len(s);
		size -= i;
		slen -= i;
		s += i;
	}

	pid = getpid();
	for (loop = 0;;++loop) {
		time = now();
		s = fntmptph;
		s += fmt_str(s,".qmail-reply.tmp.");
		s += fmt_ulong(s,time); *s++ = '.';
		s += fmt_ulong(s,pid); *s++ = '.';
		*s++ = 0;
		if (stat(fntmptph,&st) == -1) if (errno == error_noent) break;
		/* really should never get to this point */
		if (loop == 2) _exit(1);
		sleep(2);
	}
	
	sig_alarmcatch(sigalrm);
	alarm(600); /* give up after 10 min */
	fd = open_excl(fntmptph);
	if (fd == -1)
		strerr_die2sys(111, FATAL, "unable to open tmp file: ");

	substdio_fdbuf(&ss,write,fd,rsoutbuf,sizeof(rsoutbuf));

	for (i = 0; i < slen; i += str_len(s+i)) {
		if (rs.s+rsmatch == s+i) continue;
		if (substdio_puts(&ss, s+i) == -1) goto fail;
		if (substdio_put(&ss, "\n", 1) == -1) goto fail;
	}
	if (substdio_put(&ss, buf, len) == -1) goto fail;
	if (substdio_put(&ss, ":", len) == -1) goto fail;
	if (substdio_puts(&ss, stamp(now())) == -1) goto fail;
	if (substdio_put(&ss, "\n", 1) == -1) goto fail;
	if (substdio_flush(&ss) == -1) goto fail;
	if (fsync(fd) == -1) goto fail;
	if (close(fd) == -1) goto fail; /* NFS dorks */

	if (unlink(".qmail-reply.db") == -1 && errno != error_noent) goto fail;
	
	if (link(fntmptph,".qmail-reply.db") == -1) goto fail;
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
		if (l <= 0) break; if (*s == ':') break; l--; s++;
		if (l <= 0) break; if (*s == ':') break; l--; s++;
		if (l <= 0) break; if (*s == ':') break; l--; s++;
		if (l <= 0) break; if (*s == ':') break; l--; s++;
	}
	for(;;) {
		if (l <= 0) break; if (*s == ' ' || *s == '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s == ' ' || *s == '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s == ' ' || *s == '\t') break;
		l--; s++;
		if (l <= 0) break; if (*s == ' ' || *s == '\t') break;
		l--; s++;
	}
	return len - l;
}

#ifndef REPLY_SUBJ
#define REPLY_SUBJ "Your Mail"
#endif

stralloc subject = {0};
stralloc line = {0};
char buf[1024];

int parseheader(/* XXX names for to/cc checking */ void)
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
			    error_str(errno),0);
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
			if (case_diffb(s, "Mailing-List:",
				    sizeof("Mailing-List:") - 1) == 0) {
				return 1;
				/* don't reply to mailing-lists */
			}
			break;
		case 'P':
		case 'p': /* Precedence: */
			if (case_diffb(s, "Precedence:",
				    sizeof("Precedence:") - 1) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;

				if (case_diffb(s, "junk", 4) == 0 ||
				    case_diffb(s, "bulk", 4) == 0 ||
				    case_diffb(s, "list", 4) == 0)
					return 1;
			}
			break;
		case 'S':
		case 's': /* Subject: */
			if (case_diffb(s, "Subject:",
				    sizeof("Subject:") - 1) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
				
				if (len > 1) {
					/* subject has to be more than
					   1 char (normaly a \n)
					 */
					if (!stralloc_copyb(&subject, s, len))
						temp_nomem();
					subj_set=1;
				}
			}
			break;
		case 'C':
		case 'c': /* Cc: */
		case 'T':
		case 't': /* To: */
			/* to be implemented */
#if 0
			if (case_diffb(s, "To:"
				    sizeof("To:") - 1) == 0 ||
			    case_diffb(s, "Cc:"
				    sizeof("Cc:") - 1) == 0) {
				i = getfield(s, len);
				if (i >= len) break;
				s += i; len -= i;
			}
#endif
			break;
		default:
			/* XXX multiline header for to and cc */
			break;
		}
	} while (match);
	strerr_warn2(WARN,
	    "premature end of header. This message has no body.", 0);
	if ( subj_set == 0 )
		if (!stralloc_copys(&subject, REPLY_SUBJ)) temp_nomem();

	return 0;
}

stralloc ct = {0};
stralloc cte = {0};
stralloc resubject = {0};

void sendmail(void)
{
	struct qmail qqt;
	char *qqx, *s;
	unsigned long qp;
	int header, len, i, j;
	
	if (qmail_open(&qqt) == -1) temp_fork();
	qp = qmail_qp(&qqt);
	
	qmail_put(&qqt,dtline.s,dtline.len);
	qmail_puts(&qqt, "Precedence: junk\n");
	
	header = 0;
	s = replytext.s; len = replytext.len;
	do {
		i = byte_chr(s, len, '\n');
		if (i >= len)
			strerr_die2x(100, FATAL, "parser error");
		
		if (case_diffb(s, "%HEADER%", sizeof("%HEADER%") - 1) == 0) {
			header = 1;
			goto next;
		}
		if (*s == '\n' || header == 0) {
			header = 0;
			goto next;
		}
		
		switch (*s) {
		case 'C':
		case 'c': /* Content-Type: ||
			     Content-Transfer-Encoding: ||
			     Cc: */
			if (case_diffb(s, "Cc:", sizeof("Cc:") - 1) == 0)
				break;
			if (case_diffb(s, "Content-Type:",
				    sizeof("Content-Type:") - 1) == 0) {
				j = getfield(s, i);
				if (j >= i) break;
				if (!stralloc_copyb(&ct, s+j, i-j))
					temp_nomem();
				break;
			}
			if (case_diffb(s, "Content-Transfer-Encoding:",
				    sizeof("Content-Transfer-Encoding:") - 1
				    ) == 0) {
				j = getfield(s, i);
				if (j >= i) break;
				if (!stralloc_copyb(&cte, s+j, i-j))
					temp_nomem();
				break;
			}
			qmail_put(&qqt, s, i);
			break;
		case 'S':
		case 's': /* Subject: */
			if (case_diffb(s, "Subject:",
				    sizeof("Subject:") - 1) != 0) {
				qmail_put(&qqt, s, i);
				break;
			}
			j = getfield(s, i);
			if (j >= i) break;
			
			if (!stralloc_ready(&resubject,
				    i + subject.len))
				temp_nomem();
			while (j < i) {
				if (s[j] == '%' && 
				    case_diffb(s + j,
					    "%SUBJECT%", 
					    sizeof("%SUBJECT%") - 1) == 0) {
					if (!stralloc_cat(&resubject, &subject))
						temp_nomem();
					while (s[++j] != '%') ;
				} else {
					if (!stralloc_append(&resubject, s+j))
						temp_nomem();
				}
				++j;
			}
			if (stralloc_0(&resubject)) temp_nomem();
			break;
		case 'F':
		case 'f': /* From: */
		case 'T':
		case 't': /* To: */
			if (case_diffb(s, "From:", sizeof("From:") - 1) == 0 ||
			    case_diffb(s, "To:", sizeof("From:") - 1) == 0)
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
		if (!stralloc_copys(&resubject, "[Auto-Reply] ")) temp_nomem();
		if (!stralloc_cat(&resubject, &subject)) temp_nomem();
		if (stralloc_0(&resubject)) temp_nomem();
	}
	if (!stralloc_0(&from)) temp_nomem();
	if (!stralloc_0(&to)) temp_nomem();
	
	/* From: */
	qmail_puts(&qqt, "From: ");
	qmail_put(&qqt, from.s);
	qmail_puts(&qqt, "\n");
	/* To: */
	qmail_puts(&qqt, "To: ");
	qmail_put(&qqt, to.s);
	qmail_puts(&qqt, "\n");
	/* Subject: */
	qmail_puts(&qqt, "Subject: ");
	qmail_put(&qqt, resubject.s);
	qmail_puts(&qqt, "\n");
	/* XXX Date: qmail uses GMT based dates which is sometimes confusing */
	/* Content-* */
	qmail_puts(&qqt, "Content-type: ");
	if (ct.s != (char *)0 && ct.len > 0)
		qmail_put(&qqt, ct.s, ct.len);
	else
		qmail_puts(&qqt, "text/plain; charset=\"iso-8859-1\"");
	qmail_puts(&qqt, "\n");
	qmail_puts(&qqt, "Content-Transfer-Encoding: ");
	if (cte.s != (char *)0 && cte.len > 0)
		qmail_put(&qqt, cte.s, cte.len);
	else
		qmail_puts(&qqt, "8bit");
	qmail_puts(&qqt, "\n");
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
}

int main(int argc, char **argv)
{
	int flagenv;
	int opt;

	if (!env_init()) temp_nomem();
	
	flagenv = 1;
#ifdef NOTYET
	timeout = DEF_TIMEOUT;
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
	sendmail(); /* actually qmail :) */
	return 0;
}

