#include "byte.h"
#include "localdelivery.h"
#include "output.h"
#include "qldap.h"
#include "qldap-debug.h"
#include "qldap-errno.h"
#include "stralloc.h"
#include "read-ctrl.h"
#ifdef AUTOHOMEDIRMAKE
#include "dirmaker.h"
#endif
#ifdef QLDAP_CLUSTER
#include "qldap-cluster.h"
#endif

#include "checkpassword.h"
#include "auth_mod.h"

stralloc	loginstr = {0};
stralloc	authdatastr = {0};

ctrlfunc	ctrls[] = {
		qldap_controls,
		localdelivery_init,
#ifdef QLDAP_CLUSTER
		cluster_init,
#endif
#ifdef AUTOHOMEDIRMAKE
		dirmaker_init,
#endif		
		0 };

int
main(int argc, char **argv)
{
	struct	credentials c;
	int r;

	log_init(STDERR, ~256, 0);	/* XXX limited so that it is not
					   possible to get passwords via 
					   debug on production systems.
					 */
	if (read_controls(ctrls) == -1)
		auth_error(AUTH_CONF);

	auth_init(argc, argv, &loginstr, &authdatastr);
	log(256, "auth_init: login=%s, authdata=%s\n",
	    loginstr.s, authdatastr.s);

	if (authdatastr.len <= 1) {
		log(1, "alert: null password.\n");
		auth_fail(loginstr.s, BADPASS);
	}
	
	byte_zero(&c, sizeof(c));
	r = check(&loginstr, &authdatastr, &c, 0);
	switch (r) {
	case OK:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		change_uid(c.uid, c.gid);
		setup_env(loginstr.s, &c);
		if (c.maildir.s && *c.maildir.s) {
			/* use default maildir aka aliasempty or
			   in other words the last argv */
			if (!stralloc_copys(&c.maildir, argv[argc-1]))
				auth_error(ERRNO);
			if (!stralloc_0(&c.maildir))
				auth_error(ERRNO);
		}
		chdir_or_make(c.home.s, c.maildir.s);
		auth_success();
	case FORWARD:
#ifdef QLDAP_CLUSTER
		change_uid(-1, -1);
		setup_env(loginstr.s, &c);
		forward(loginstr.s, authdatastr.s, &c);
		/* does not return */
#else
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		/* system error, now way out ... module likes to forward
		   but we don't have support for it. */
		auth_error(r);
#endif
	case NOSUCH: /* FALLTHROUGH */
	case BADPASS:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		auth_fail(loginstr.s, r);
	default:
		/* authdata no longer needed */
		byte_zero(authdatastr.s, authdatastr.len);
		/* system error, now way out ... */
		auth_error(r);
	}
		
	auth_error(PANIC);
	return 1; /* should never get here */
}


