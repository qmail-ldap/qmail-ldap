#ifndef __QLDAP_DEBUG_H__
#define __QLDAP_DEBUG_H__

extern void log_init(int fd, unsigned long mask, int via_spawn);
extern void logit(unsigned long level, const char *fmt, ...);
extern void logstart(unsigned long level, const char *fmt, ...);
extern void logadd(unsigned long level, const char *fmt, ...);
extern void logend(unsigned long level, const char *fmt, ...);
extern void profile(const char *s);

#define PROFILE(s) profile(s)

#endif
