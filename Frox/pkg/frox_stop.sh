#!/bin/sh

NAME=frox
DAEMON=/usr/sbin/$NAME

start-stop-daemon --stop --quiet --exec $DAEMON
