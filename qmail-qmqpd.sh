#!/bin/sh
exec 2>&1
#
# QMQP service 
#
USER=qmaild
QMAIL="%QMAIL%"
ME=$(head -1 $QMAIL/control/me)

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - envdir ./env awk '\
        BEGIN { for (i in ENVIRON) printf "%s=\"%s\"\n", i, ENVIRON[i] }'`

exec envdir ./env \
	envuidgid $USER \
	tcpserver -v -URl $ME -x$QMAIL/control/qmail-qmqpd.cdb \
	    ${CONCURRENCY+"-c$CONCURRENCY"} ${BACKLOG+"-b$BACKLOG"} 0 628 \
	$QMAIL/bin/qmail-qmqpd

