#!/bin/sh
NAME=frox
DAEMON=/usr/sbin/$NAME

/usr/sbin/frox_configure.pl

if grep -vE '^#' /etc/frox.conf| grep -q LogFile;then
        log=$(grep -vE '^#' /etc/frox.conf | grep LogFile | awk '{print $2}')
fi 

exec &>>$log
exec $DAEMON
