#ifdef PROFILE
#include "taia.h"
#include "qldap-profile.h"
#include "qldap-debug.h"

struct profile_t {
	struct taia start;
	char *function;
};
	
static struct profile_t profile_list[PROFILES_MAX];

void start_timing(int profile, char *function)
{
	if ( profile >= PROFILES_MAX ) {
		debug(0x400, "Max Number of profiles exceded\n");
		return;
	}
	
	taia_now(&(profile_list[profile].start));

}

void stop_timing(int profile) 
{
	struct taia stop;
	struct taia diff;
	char nano[TAIA_FMTFRAC];
	unsigned long sec;
	
	if ( profile >= PROFILES_MAX ) {
		debug(0x400, "Max Number of profiles exceded\n");
		return;
	}

	taia_now(&stop);

	taia_sub(&diff, &stop, &profile_list[profile].start);
	nano[taia_fmtfrac(nano, &diff)] = 0; /* terminate to be sure */
	nano[7] = 0; /* only the first 6-7 figures are != 0, (nano seconds) */
	sec=(unsigned long) ((unsigned long long) diff.sec.x);
	debug(0x400, "%s took %u.%s Sec\n", profile_list[profile].function, sec, nano);

}

#endif
