#!/bin/sh
exec 2>&1
#
# SMTP service 
#
QMAIL="%QMAIL%"
ME="`head -1 $QMAIL/control/me`"
CONCURRENCY=${CONCURRENCY:=50}

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - PATH=$PATH envdir ./env awk '\
	BEGIN { for (i in ENVIRON) \
		printf "export %s=\"%s\"\n", i, ENVIRON[i] }'`

# enforce some sane defaults
USER=${USER:="qmaild"}

exec \
	envuidgid $USER \
	tcpserver -v -URl $ME -x$QMAIL/control/qmail-smtpd.cdb \
	    ${CONCURRENCY+"-c$CONCURRENCY"} ${BACKLOG+"-b$BACKLOG"} 0 smtp \
	$QMAIL/bin/pbscheck \
	$QMAIL/bin/qmail-smtpd

