#ifndef __QLDAP_DEBUG_H__
#define __QLDAP_DEBUG_H__

#ifdef DEBUG
void log_init(int fd, unsigned long mask, int via_spawn);
void log(unsigned long level, char *fmt, ...);
void logstart(unsigned long level, char *fmt, ...);
void logadd(unsigned long level, char *fmt, ...);
void logend(unsigned long level, char *fmt, ...);
void profile(char *s);

#define PROFILE(s) profile(s)
#else
static void log_init() {};
static void log() {};
static void logstart() {};
static void logadd() {};
static void logend() {};

#define PROFILE(s)
#endif

#endif
