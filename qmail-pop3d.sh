#!/bin/sh
exec 2>&1
#
# POP3 service 
#
QMAIL="%QMAIL%"
ME="`head -1 $QMAIL/control/me`"
if [ -e $QMAIL/control/defaultdelivery ]; then
        ALIASEMPTY=`head -1 $QMAIL/control/defaultdelivery 2> /dev/null`
else
        ALIASEMPTY=`head -1 $QMAIL/control/aliasempty 2> /dev/null`
fi
ALIASEMPTY=${ALIASEMPTY:="./Maildir/"}

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - PATH=$PATH envdir ./env awk '\
	BEGIN { for (i in ENVIRON) \
		printf "export %s=\"%s\"\n", i, ENVIRON[i] }'`

# enforce some sane defaults
# Nothing so far

exec \
	tcpserver -v -HRl $ME -x$QMAIL/control/qmail-pop3d.cdb \
	    ${CONCURRENCY+"-c$CONCURRENCY"} ${BACKLOG+"-b$BACKLOG"} 0 pop3 \
	$QMAIL/bin/qmail-popup $ME \
	$QMAIL/bin/auth_pop \
	$QMAIL/bin/pbsadd \
	$QMAIL/bin/qmail-pop3d "$ALIASEMPTY"

