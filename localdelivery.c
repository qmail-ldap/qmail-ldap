#include "control.h"
#include "qldap-debug.h"

#include "localdelivery.h"

static int	flaglocaldelivery;

int
localdelivery_init(void)
{
	flaglocaldelivery = 1;	/* localdelivery is on (DEFAULT) */

	if (control_readint(&flaglocaldelivery,
		    "control/ldaplocaldelivery") == -1)
		return -1;
	log(64, "init: control/ldaplocaldelivery: %i\n", flaglocaldelivery);
	return 0;
}

int
localdelivery(void)
{
	return flaglocaldelivery;
}

