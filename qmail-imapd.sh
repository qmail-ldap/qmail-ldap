#!/bin/sh
exec 2>&1
#
# IMAP service: this script is for courier-imap
#
QMAIL="%QMAIL%"
ME=$(head -1 $QMAIL/control/me)
ALIASEMPTY=$(head -1 $QMAIL/control/aliasempty 2> /dev/null)
ALIASEMPTY=${ALIASEMPTY:="./Maildir/"}

PATH="$QMAIL/bin:$PATH"

# source the environemt in ./env
eval `env - envdir ./env awk '\
        BEGIN { for (i in ENVIRON) printf "%s=\"%s\"\n", i, ENVIRON[i] }'`

# enforce some sane defaults
COURIER=${COURIER:="/usr/local"}

exec envdir ./env \
	tcpserver -v -HRl $ME -x$QMAIL/control/qmail-imapd.cdb \
	    ${CONCURRENCY+"-c$CONCURRENCY"} ${BACKLOG+"-b$BACKLOG"} 0 imap \
	$COURIER/sbin/imaplogin \
	$QMAIL/bin/auth_imap \
	$QMAIL/bin/pbsadd \
	$COURIER/bin/imapd "$ALIASEMPTY"
