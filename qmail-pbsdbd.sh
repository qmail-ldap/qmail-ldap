#!/bin/sh
exec 2>&1
#
# pop before smtp database daemon
#
USER=qmaild
QMAIL="%QMAIL%"

PATH="$QMAIL/bin:$PATH"

exec envdir ./env setuidgid $USER \
	$QMAIL/bin/pbsdbd

