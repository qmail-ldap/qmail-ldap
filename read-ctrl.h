#ifndef __READ_CTRL_H__
#define __READ_CTRL_H__

typedef int (*ctrlfunc)(void);

int read_controls(ctrlfunc *);

#endif
