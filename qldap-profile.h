#ifndef __QLDAP_PROFILE_H__
#define __QLDAP_PROFILE_H__

#define PROFILES_MAX 4 /* 4 concurrent profiles */

void start_timing(int profile, char *function);
/* start the timing of a function */

void stop_timing(int profile);
/* stop the timing of a function and print the difference */

#endif
