#!/bin/sh
exec 2>&1
#
# pop before smtp database daemon
#
QMAIL="%QMAIL%"

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - PATH=$PATH envdir ./env awk '\
	BEGIN { for (i in ENVIRON) \
		printf "export %s=\"%s\"\n", i, ENVIRON[i] }'`

# enforce some sane defaults
USER=${USER:="qmaild"}

exec \
	setuidgid $USER \
	$QMAIL/bin/pbsdbd

