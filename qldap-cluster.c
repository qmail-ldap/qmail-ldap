#ifdef QLDAP_CLUSTER
#include "constmap.h"
#include "control.h"
#include "qldap-debug.h"
#include "str.h"
#include "stralloc.h"

#include "qldap-cluster.h"

static int		clusteron;
static stralloc		me = {0};
static stralloc		mh = {0};	/* buffer for constmap */
static struct constmap	mailhosts_map;


int
cluster_init(void)
{
	clusteron = 0;	/* default is off */
	
	if (control_readline(&me, "control/me") != 1)
		return -1;
	if (control_readint(&clusteron, "control/ldapcluster") == -1)
		return -1;
	logit(64, "init: control/ldapcluster: %i\n", clusteron);

	if (clusteron == 0)
		return 0;
	
	if (control_readfile(&mh,"control/ldapclusterhosts",0) == -1)
		return -1;
	logit(64, "init_ldap: control/ldapclusterhosts: read\n");
	if (!stralloc_cat(&mh, &me) || !stralloc_0(&mh))
		return -1;
	if (mailhosts_map.num != 0) constmap_free(&mailhosts_map);
	if (!constmap_init(&mailhosts_map, mh.s, mh.len,0))
		return -1;
	return 0;
}

int
cluster(char *mailhost)
/* returns 1 if mail/connection needs to be forwarded else 0 */
{
	if (clusteron == 0 || mailhost == (char *)0)
		return 0;
	if (constmap(&mailhosts_map, mailhost, str_len(mailhost)) == 0)
		return 1;
	else
		return 0;
}

stralloc *
cluster_me(void)
{
	return &me;
}

#endif
