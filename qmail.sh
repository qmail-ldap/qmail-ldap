#!/bin/sh
exec 2>&1
#
# qmail-send and friends
#
QMAIL="%QMAIL%"
ALIASEMPTY="`head -1 $QMAIL/control/aliasempty 2> /dev/null`"
ALIASEMPTY=${ALIASEMPTY:="./Maildir/"}

PATH="$QMAIL/bin:$PATH"

# limit to prevent memory hogs
ulimit -c 204800 

exec envdir ./env qmail-start "$ALIASEMPTY"

