#ifndef COMMANDS_H
#define COMMANDS_H

struct commands {
  const char *text;
  void (*fun)();
  void (*flush)();
} ;

extern int commands();

#endif
