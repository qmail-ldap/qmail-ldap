#!/bin/sh
exec 2>&1
#
# QMQP service 
#
QMAIL="%QMAIL%"
ME=$(head -1 $QMAIL/control/me)

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - envdir ./env awk '\
        BEGIN { for (i in ENVIRON) printf "%s=\"%s\"\n", i, ENVIRON[i] }'`

# enforce some sane defaults
USER=${USER:="qmaild"}

exec envdir ./env \
	envuidgid $USER \
	tcpserver -v -URl $ME -x$QMAIL/control/qmail-qmqpd.cdb \
	    ${CONCURRENCY+"-c$CONCURRENCY"} ${BACKLOG+"-b$BACKLOG"} 0 628 \
	$QMAIL/bin/qmail-qmqpd

